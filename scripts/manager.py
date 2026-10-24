#!/usr/bin/env python3
"""Privileged local VPN exit manager. Never expose this script to a public port."""
from __future__ import annotations
import fcntl
import ipaddress
import json
import os
import secrets
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from contextlib import contextmanager
from pathlib import Path
from core import (STATE, CONFIG, EXITS, RULES, CLASH, build_singbox,
                  parse_peer, clean_name, ConfigError, default_state)

CLASH_SECRET = Path('/etc/vpn-proxy/clash-secret')
LOCK = Path('/run/vpn-proxy-manager.lock')


def run(args, *, check=True, timeout=60, **kw):
    return subprocess.run(args, text=True, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, check=check, timeout=timeout, **kw)


def atomic(path:Path, data:str, mode=0o600):
    path.parent.mkdir(parents=True,exist_ok=True)
    fd,name=tempfile.mkstemp(prefix='.next-',dir=str(path.parent))
    try:
        with os.fdopen(fd,'w',encoding='utf-8') as f:
            f.write(data);f.flush();os.fsync(f.fileno())
        os.chmod(name, mode)
        os.replace(name,str(path))
    finally:
        if os.path.exists(name): os.unlink(name)


def get_state():
    return json.loads(STATE.read_text())


def put_state(state):
    atomic(STATE,json.dumps(state,ensure_ascii=False,indent=2)+'\n')


@contextmanager
def locked():
    LOCK.parent.mkdir(parents=True,exist_ok=True)
    with open(LOCK,'w') as f:
        fcntl.flock(f,fcntl.LOCK_EX)
        yield


def secret():
    return CLASH_SECRET.read_text().strip()


def shell_service_action(verb):
    run(['systemctl',verb,'vpn-proxy-singbox.service'])


def check_config(state):
    c=build_singbox(state,secret())
    txt=json.dumps(c,ensure_ascii=False,indent=2)+'\n'
    fd,path=tempfile.mkstemp(prefix='.check-',suffix='.json',dir=str(CONFIG.parent))
    try:
        with os.fdopen(fd,'w') as f:f.write(txt)
        run(['sing-box','check','-c',path],timeout=30)
    finally:
        Path(path).unlink(missing_ok=True)
    return txt


def apply_state(state):
    """Validate before touching service, restore previous config if service fails."""
    txt=check_config(state)
    old=CONFIG.read_text() if CONFIG.exists() else None
    atomic(CONFIG,txt,0o640)
    try:
        shell_service_action('restart')
        run(['systemctl','is-active','--quiet','vpn-proxy-singbox.service'])
    except Exception:
        if old is not None: atomic(CONFIG,old,0o640)
        else: CONFIG.unlink(missing_ok=True)
        try:shell_service_action('restart')
        except Exception:pass
        raise


def _entry(state, uid):
    for e in state['exits']:
        if e['id'] == uid: return e
    raise ConfigError('VPN-источник не найден')


def _ipcmd(*args, check=True):
    return run(['ip',*map(str,args)],check=check)


def tunnel_up(e):
    dev,mark=e['interface'],int(e['mark'])
    if not Path('/sys/class/net/'+dev).exists():
        run(['amneziawg-go',dev],timeout=15)
        for _ in range(30):
            if Path('/sys/class/net/'+dev).exists(): break
            time.sleep(.1)
        else: raise ConfigError('amneziawg-go не создал интерфейс')
    cfg=EXITS/(e['id']+'.conf')
    # awg-quick strip discards Address, Table and other Quick-only settings.
    stripped=run(['awg-quick','strip',str(cfg)]).stdout
    fd,path=tempfile.mkstemp(prefix='awg-strip-',dir='/run')
    try:
        with os.fdopen(fd,'w') as f:f.write(stripped)
        os.chmod(path,0o600)
        run(['awg','setconf',dev,path])
    finally:Path(path).unlink(missing_ok=True)
    _ipcmd('address','replace',e['address'],'dev',dev)
    _ipcmd('link','set',dev,'mtu',e.get('mtu',1420),'up')
    # Distinct policy routing table, with explicit unreachable fallback for kill-switch.
    _ipcmd('-4','route','replace','unreachable','default','table',mark,'metric','427')
    _ipcmd('-4','route','replace','default','dev',dev,'table',mark,'metric','10')
    rules=_ipcmd('-4','rule','show').stdout
    if f'fwmark 0x{mark:x} lookup {mark}' not in rules and f'fwmark {mark} lookup {mark}' not in rules:
        _ipcmd('-4','rule','add','pref',11000+mark,'fwmark',mark,'lookup',mark)
    rules=_ipcmd('-4','rule','show').stdout
    if f'{12000+mark}:' not in rules:
        _ipcmd('-4','rule','add','pref',12000+mark,'fwmark',mark,'prohibit')


def tunnel_down(e):
    dev,mark=e['interface'],int(e['mark'])
    _ipcmd('link','del',dev,check=False)
    _ipcmd('-4','rule','del','pref',11000+mark,check=False)
    _ipcmd('-4','rule','del','pref',12000+mark,check=False)
    _ipcmd('-4','route','flush','table',mark,check=False)


def probe(e):
    """Independent SOCKS probe: destination traffic is bound and fwmarked to just this tunnel."""
    cfg={'log':{'level':'warn'},'inbounds':[{'type':'socks','listen':'127.0.0.1',
          'listen_port':30000+int(e['mark'])}],
          'outbounds':[{'type':'direct','tag':'probe','bind_interface':e['interface'],
                        'routing_mark':e['mark']}], 'route':{'final':'probe'}}
    fd,path=tempfile.mkstemp(prefix='vpn-probe-',suffix='.json',dir='/run')
    with os.fdopen(fd,'w') as f:json.dump(cfg,f)
    proc=None
    try:
        run(['sing-box','check','-c',path],timeout=20)
        proc=subprocess.Popen(['sing-box','run','-c',path],stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL)
        ip=None
        for _ in range(4):
            time.sleep(.5)
            if proc.poll() is not None:
                raise ConfigError('Проверочный sing-box не запустился')
            try:
                resp=run(['curl','-4','-fsS','--max-time','7','--socks5-hostname',
                          f'127.0.0.1:{30000+int(e["mark"])}','https://api.ipify.org'],
                         timeout=10)
                ip=resp.stdout.strip()
                break
            except subprocess.CalledProcessError:
                pass
        if not ip:
            raise ConfigError('Выход через туннель недоступен (SOCKS-проба не прошла)')
        try:
            addr=ipaddress.ip_address(ip)
            if addr.version != 4 or not addr.is_global:raise ValueError()
        except ValueError as exc:
            raise ConfigError('Проба вернула не публичный IPv4') from exc
        hs=run(['awg','show',e['interface'],'latest-handshakes']).stdout.strip()
        if not hs or not any(int(row.split()[-1]) > time.time()-120 for row in hs.splitlines()):
            raise ConfigError('Нет свежего AmneziaWG handshake')
        # Confirm exit IP differs from RU WAN external address when possible.
        return {'ip':ip, 'handshake':True}
    finally:
        if proc:
            proc.terminate()
            try:proc.wait(timeout=4)
            except subprocess.TimeoutExpired:proc.kill();proc.wait()
        Path(path).unlink(missing_ok=True)


def clash_select(tag):
    payload=json.dumps({'name':tag}).encode('utf-8')
    req=urllib.request.Request(CLASH+'/proxies/exit-default',data=payload,method='PUT',
            headers={'Authorization':'Bearer '+secret(),'Content-Type':'application/json'})
    with urllib.request.urlopen(req,timeout=4) as res:
        if res.status not in (200,204):raise ConfigError('Clash API не подтвердил переключение')


def bootstrap(wan,bridge,container_ip,port):
    with locked():
        if STATE.exists():raise ConfigError('Система уже развёрнута, bootstrap запрещён')
        RULES.mkdir(parents=True,exist_ok=True)
        EXITS.mkdir(parents=True,exist_ok=True)
        state=default_state(wan,bridge,container_ip,port)
        put_state(state)
        # Configuration is generated during deploy once GeoIP and secret exist.
        return {'created':True,'state':state}


def add(name,raw):
    with locked():
        state=get_state()
        if len(state['exits']) >= 70: raise ConfigError('Достигнут лимит: 70 серверов')
        parsed=parse_peer(raw);name=clean_name(name)
        for existing in state['exits']:
            if existing['name'].casefold()==name.casefold():
                raise ConfigError('Такое название уже существует')
        uid=secrets.token_hex(5)
        mark=next((i for i in range(220,300) if all(x['mark']!=i for x in state['exits'])),None)
        if mark is None:raise ConfigError('Нет свободных таблиц маршрутизации')
        e={'id':uid,'name':name,'interface':'ax'+uid[:10], 'mark':mark,
           'address':parsed['address'],'endpoint':parsed['endpoint'], 'mtu':parsed['mtu']}
        cfg=EXITS/(uid+'.conf')
        atomic(cfg,parsed['config'])
        try:
            tunnel_up(e)
            result=probe(e)
            e['last_ip']=result['ip']
            new=dict(state,exits=state['exits']+[e])
            apply_state(new)
            put_state(new)
            return {'added':e}
        except Exception:
            tunnel_down(e)
            cfg.unlink(missing_ok=True)
            raise


def validate(uid):
    with locked():
        e=_entry(get_state(),uid)
        tunnel_up(e)
        return probe(e)


def activate(uid):
    with locked():
        state=get_state();e=_entry(state,uid)
        tunnel_up(e)
        result=probe(e)  # do not switch blindly
        old=state.get('active')
        if old == uid:return {'active':uid,'ip':result['ip']}
        new=dict(state,active=uid)
        if old is None:
            # First selection enables the foreign route; requires reload once.
            apply_state(new)
        else:
            clash_select('exit-'+uid)  # no restart for a normal change
        try:
            put_state(new)
        except Exception:
            if old is not None:clash_select('exit-'+old)
            else:apply_state(state)
            raise
        return {'active':uid,'ip':result['ip']}


def delete(uid, force=False):
    with locked():
        state=get_state();e=_entry(state,uid)
        if state.get('active')==uid and not force:
            raise ConfigError('Активный сервер: сначала активируйте другой либо подтвердите отключение')
        new=dict(state,exits=[x for x in state['exits'] if x['id']!=uid],
                 active=None if state.get('active')==uid else state.get('active'))
        # In particular, removing last active exit forces reject for foreign traffic.
        apply_state(new)
        put_state(new)
        tunnel_down(e)
        (EXITS/(uid+'.conf')).unlink(missing_ok=True)
        return {'deleted':uid,'active':new['active']}


def restore():
    with locked():
        state=get_state()
        failures=[]
        for e in state['exits']:
            try:tunnel_up(e)
            except Exception as ex:failures.append(e['name']+': '+str(ex))
        txt=check_config(state)
        atomic(CONFIG,txt,0o640)
        # Do not start sing-box here; systemd orders it after restore.
        return {'restored':len(state['exits'])-len(failures),'failures':failures}


def read_status():
    state=get_state()
    safe=[]
    for e in state['exits']:
        item={k:v for k,v in e.items() if k in {'id','name','interface','last_ip','endpoint'}}
        item['active']=e['id']==state['active']
        item['tunnel_up']=Path('/sys/class/net/'+e['interface']).exists()
        safe.append(item)
    return {'active':state['active'], 'exits':safe}


def main():
    if os.geteuid()!=0:raise ConfigError('Нужны права root')
    cmd=sys.argv[1] if len(sys.argv)>1 else 'status'
    if cmd=='bootstrap':
        result=bootstrap(sys.argv[2],sys.argv[3],sys.argv[4],int(sys.argv[5]))
    elif cmd=='add':
        data=json.load(sys.stdin)
        result=add(data['name'],data['conf'])
    elif cmd=='validate':result=validate(sys.argv[2])
    elif cmd=='activate':result=activate(sys.argv[2])
    elif cmd=='delete':result=delete(sys.argv[2],'--force' in sys.argv)
    elif cmd=='restore':result=restore()
    elif cmd=='status':result=read_status()
    else:raise ConfigError('Неизвестная команда')
    print(json.dumps(result,ensure_ascii=False))


if __name__=='__main__':
    try:main()
    except (ConfigError,subprocess.CalledProcessError,subprocess.TimeoutExpired,
            OSError,urllib.error.URLError,ValueError,KeyError) as ex:
        # Never log config secrets or subprocess arguments (can contain .conf paths).
        if isinstance(ex,subprocess.CalledProcessError):
            msg='Ошибка команды внешнего компонента (код '+str(ex.returncode)+')'
        else:msg=str(ex)
        print(json.dumps({'error':msg},ensure_ascii=False))
        sys.exit(1)
