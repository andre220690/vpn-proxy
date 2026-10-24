#!/usr/bin/env python3
"""Pure, testable configuration helpers for VPN Proxy (IPv4 only)."""
from __future__ import annotations
import configparser
import ipaddress
import json
import re
from pathlib import Path

STATE = Path('/var/lib/vpn-proxy/state.json')
CONFIG = Path('/etc/sing-box/config.json')
EXITS = Path('/etc/vpn-proxy/exits')
RULES = Path('/etc/sing-box/rules')
PORT = 2083
CLASH = 'http://127.0.0.1:9090'
GEOIP_FILE = str(RULES / 'ru.srs')

class ConfigError(ValueError):
    pass


def parse_peer(raw: str) -> dict:
    if not isinstance(raw, str) or len(raw.encode('utf-8')) > 32768:
        raise ConfigError('Файл .conf пустой или слишком большой (максимум 32 КБ)')
    p = configparser.ConfigParser(interpolation=None, strict=True, inline_comment_prefixes=('#',';'))
    p.optionxform = str
    try:
        p.read_string(raw)
    except configparser.Error as ex:
        raise ConfigError('Неверный формат INI/AmneziaWG') from ex
    if set(p.sections()) != {'Interface', 'Peer'}:
        raise ConfigError('Нужны ровно две секции: [Interface] и [Peer]')
    it, peer = ({k.lower():v for k,v in p['Interface'].items()},
                {k.lower():v for k,v in p['Peer'].items()})
    mandatory = [(it, 'privatekey'), (it, 'address'), (peer, 'publickey'), (peer, 'endpoint')]
    if any(not section.get(key, '').strip() for section, key in mandatory):
        raise ConfigError('Отсутствуют PrivateKey, Address, PublicKey или Endpoint')
    dangerous = {'preup','postup','predown','postdown','saveconfig','table','dns'}
    # Reject shell commands rather than silently executing/retaining them.
    if dangerous.intersection(set(it)) - {'table','dns'}:
        raise ConfigError('Скрипты PreUp/PostUp/PreDown/PostDown/SaveConfig запрещены')
    addr = it['address'].strip().split(',')
    if len(addr) != 1:
        raise ConfigError('В этой версии поддерживается один IPv4-адрес интерфейса')
    try:
        interface = ipaddress.ip_interface(addr[0].strip())
        if interface.version != 4:
            raise ValueError()
    except ValueError as ex:
        raise ConfigError('Address должен быть IPv4/CIDR') from ex
    endpoint = peer.get('endpoint','').strip()
    ep = re.fullmatch(r'([A-Za-z0-9.-]+):(\d{1,5})', endpoint)
    if not ep or not 1 <= int(ep.group(2)) <= 65535:
        raise ConfigError('Endpoint: требуется hostname/IP:port (IPv4)')
    hostname = ep.group(1)
    if not (1 <= len(hostname) <= 253 and all(0 < len(label) <= 63 for label in hostname.split('.'))):
        raise ConfigError('Некорректное имя Endpoint')
    # Prevent a tunnel from being silently limited to particular destinations.
    allowed = {p.strip() for p in peer.get('allowedips','').split(',') if p.strip()}
    if '0.0.0.0/0' not in allowed:
        raise ConfigError('Peer должен содержать AllowedIPs = 0.0.0.0/0')
    # Do not allow multiple peers or unsafe command sections; awg validates AWG2 keys itself.
    # Rebuild config line-by-line, with only expected quick fields removed.
    lines = []
    for section_name in ('Interface','Peer'):
        lines.append('['+section_name+']')
        for original_key,v in p[section_name].items():
            k=original_key.lower()
            if '\n' in v or '\r' in v:
                raise ConfigError('Многострочные значения запрещены')
            if section_name == 'Interface' and k in {'table','dns','mtu'}:
                continue
            if section_name == 'Peer' and k == 'allowedips':
                # IPv4-only: IPv6 is not claimed supported.
                v = '0.0.0.0/0'
            lines.append(original_key+' = '+v.strip())
        if section_name == 'Interface':
            lines.append('Table = off')
        lines.append('')
    return {'address': str(interface), 'endpoint': endpoint,
            'config': '\n'.join(lines), 'mtu': int(it.get('mtu','1420')) if it.get('mtu','1420').isdigit() and 576 <= int(it.get('mtu','1420')) <= 9000 else 1420}


def clean_name(name: str) -> str:
    if not isinstance(name,str) or not 1 <= len(name.strip()) <= 64 or any(ord(c) < 32 for c in name):
        raise ConfigError('Название должно содержать 1–64 символа')
    return name.strip()


def default_state(wan: str, bridge: str, container_ip: str, vpn_port: int = 1234) -> dict:
    if not re.fullmatch(r'[a-zA-Z0-9_.-]{1,15}', wan) or not re.fullmatch(r'[a-zA-Z0-9_.-]{1,15}', bridge):
        raise ConfigError('Некорректное имя сетевого интерфейса')
    if ipaddress.ip_address(container_ip).version != 4:
        raise ConfigError('Нужен IPv4 контейнера')
    if not 1 <= vpn_port <= 65535:
        raise ConfigError('Некорректный VPN UDP port')
    return {'wan':wan,'bridge':bridge,'container_ip':container_ip,'vpn_port':vpn_port,
            'active':None, 'exits':[]}


def _set(tag: str, path: str, fmt: str='source') -> dict:
    return {'type':'local','tag':tag,'format':fmt,'path':path}


def build_singbox(state: dict, clash_secret: str='') -> dict:
    wan = state['wan']
    exits = sorted(state['exits'],key=lambda x:x['id'])
    out = [{'type':'direct','tag':'ru','bind_interface':wan}]
    for e in exits:
        out.append({'type':'direct','tag':'exit-'+e['id'], 'bind_interface':e['interface'], 'routing_mark':e['mark']})
    if exits:
        active = state['active']
        options = ['exit-'+e['id'] for e in exits]
        if active is not None and 'exit-'+active not in options:
            raise ConfigError('Активный сервер отсутствует в списке')
        out.append({'type':'selector','tag':'exit-default','outbounds':options,
                    'default':'exit-'+(active or exits[0]['id']),
                    'interrupt_exist_connections':True})
    rules = [ {'action':'sniff'},
        {'inbound':'diagnostic-ru','outbound':'ru'},
        {'rule_set':'manual-ru','outbound':'ru'},
        {'rule_set':'manual-exit', 'outbound':'exit-default'} if state['active'] else {'rule_set':'manual-exit','action':'reject'},
        {'rule_set':'domain-ru','outbound':'ru'},
        {'rule_set':'domain-exit','outbound':'exit-default'} if state['active'] else {'rule_set':'domain-exit','action':'reject'},
        {'rule_set':'geoip-ru','outbound':'ru'} ]
    if not state['active']:
        rules.append({'action':'reject'})
    return {'log':{'level':'info','timestamp':True},
            'inbounds':[{'type':'tproxy','tag':'tproxy-in','listen':'0.0.0.0','listen_port':PORT},
                        {'type':'socks','tag':'diagnostic-ru','listen':'127.0.0.1','listen_port':2080}],
            'outbounds':out,
            'route':{'rules':rules, 'rule_set':[
                _set('manual-ru', str(RULES/'manual-ru.json')),
                _set('manual-exit', str(RULES/'manual-exit.json')),
                _set('domain-ru', str(RULES/'domain-ru.json')),
                _set('domain-exit', str(RULES/'domain-exit.json')),
                _set('geoip-ru', GEOIP_FILE, 'binary')
            ],'final':'exit-default' if state['active'] else 'ru'},
            'experimental':{'clash_api':{'external_controller':'127.0.0.1:9090','secret':clash_secret}}}


def rules_text(items: list[str], domain: bool) -> str:
    if domain:
        exact, suffix = [], []
        for value in items:
            value = value.strip().lower()
            if value.startswith('*.'):
                value = value[2:]
                if not re.fullmatch(r'[a-z0-9-]+(?:\.[a-z0-9-]+)+',value):
                    raise ConfigError('Неверное доменное правило')
                suffix.append('.'+value)
            else:
                if not re.fullmatch(r'[a-z0-9-]+(?:\.[a-z0-9-]+)+',value):
                    raise ConfigError('Неверное доменное правило')
                exact.append(value)
        rule = {**({'domain':exact} if exact else {}),**({'domain_suffix':suffix} if suffix else {})}
    else:
        normalized = []
        for value in items:
            net = ipaddress.ip_network(value, strict=False)
            if net.version != 4 or not net.is_global:
                raise ConfigError('Допустимы только публичные IPv4/CIDR')
            normalized.append(str(net))
        rule = {'ip_cidr':normalized} if normalized else {}
    return json.dumps({'version':3,'rules':[rule] if rule else []},ensure_ascii=False,indent=2)+'\n'


def nft_text(state:dict, ru_public_ipv4:str) -> str:
    # The exclusion of ingress UDP sport is essential for the existing AWG2 Docker setup.
    b,ip,port = state['bridge'],state['container_ip'],state['vpn_port']
    return f'''table ip vpn_proxy {{
 chain prerouting {{
  type filter hook prerouting priority mangle; policy accept;
  iifname "{b}" ip saddr {ip} udp sport {port} return
  iifname "{b}" ip saddr {ip} ip daddr {{ 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 198.18.0.0/15, 224.0.0.0/4, 240.0.0.0/4 }} return
  iifname "{b}" ip saddr {ip} ip daddr {ru_public_ipv4} return
  iifname "{b}" ip saddr {ip} meta l4proto {{ tcp, udp }} meta mark set 100 tproxy to :{PORT} accept
 }}
}}
table inet vpn_proxy_input {{
 chain input {{
  type filter hook input priority filter; policy accept;
  iifname \"{state['wan']}\" meta l4proto {{ tcp, udp }} th dport {PORT} drop
 }}
}}
table ip6 vpn_proxy6 {{
 chain forward {{
  type filter hook forward priority filter; policy accept;
  iifname "{b}" drop
 }}
}}
'''
