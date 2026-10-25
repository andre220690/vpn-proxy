#!/usr/bin/env python3
"""Loopback-only admin UI. Authentication required even behind SSH forwarding."""
import base64
import hmac
import html
import json
import os
import secrets
import subprocess
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT=Path('/opt/vpn-proxy')
PASSFILE=Path('/etc/vpn-proxy/panel-password')
CSRF=secrets.token_urlsafe(32)
MAX_BODY=45_000

PAGE=r'''<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>VPN Proxy — Источники и маршруты</title><style>
:root{color-scheme:dark}body{font:16px system-ui;background:#111827;color:#e5e7eb;max-width:850px;margin:35px auto;padding:0 16px}header{display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap}h1{font-size:25px}h2{font-size:19px}section{background:#1f2937;padding:20px;border-radius:14px;margin:18px 0}button{border:0;border-radius:9px;padding:10px 15px;background:#2563eb;color:white;cursor:pointer;font-size:14px;margin:5px 5px 5px 0}button:disabled{opacity:.5;cursor:wait}.muted{color:#a1a1aa}.danger{background:#9f1239}.good{color:#86efac}.bad{color:#fca5a5}input{padding:10px;border-radius:8px;background:#111827;border:1px solid #475569;color:#fff;max-width:98%}li{padding:12px 0;border-bottom:1px solid #374151}#message{white-space:pre-wrap}small{font-size:13px}
textarea{box-sizing:border-box;width:100%;min-height:140px;padding:10px;border-radius:8px;background:#111827;border:1px solid #475569;color:#fff;font:14px monospace;resize:vertical}.routes-grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}.routes-grid label{display:block}.routes-grid textarea{margin-top:8px}#route-message{white-space:pre-wrap}a{color:#93c5fd}@media(max-width:600px){.routes-grid{grid-template-columns:1fr}}</style></head>
<body><header><h1>VPN Proxy</h1><span class="muted">Источники и маршрутизация</span></header>
<nav><a href="#vpn-sources">VPN-серверы</a> · <a href="#routing">Маршрутизация</a></nav>
<section><h2>Выход по умолчанию</h2><p id="current" class="muted">Загрузка…</p><p class="muted">Весь зарубежный трафик направляется через один выбранный источник. Российский — через RU VPS.</p></section>
<section id="vpn-sources"><h2>VPN-серверы</h2><ul id="servers"></ul></section>
<section><h2>Добавить VPN-сервер</h2><label>Название<br><input id="name" type="text" maxlength="64" placeholder="Например, Германия" autocomplete="off"></label><p><label>AmneziaWG .conf (содержит секреты)<br><input id="file" type="file" accept=".conf,text/plain"></label></p><button id="add" onclick="addServer()">Загрузить и проверить</button><p class="muted"><small>Конфигурация передаётся только через локальный SSH-туннель. Добавленный сервер не становится активным автоматически.</small></p></section>
<p id="message" aria-live="polite"></p>
<section id="routing"><h2>Маршрутизация</h2>
<p>Ручные правила имеют приоритет перед GeoIP. Домены проверяются раньше IP-подсетей. Остальные российские IP идут через RU, остальные зарубежные — через выбранный VPN.</p>
<p class="muted">По одному правилу на строку, максимум 500 суммарно. Домены — без https://, порта и пути. Для поддоменов: *.example.com. Для основного домена добавьте также example.com. Международные домены преобразуются в punycode. IPv4: 8.8.8.8 или 8.8.8.0/24. Приватные и служебные сети не принимаются.</p>
<div class="routes-grid">
<label for="domain-ru">Домены → RU<textarea id="domain-ru" spellcheck="false" placeholder="example.ru&#10;*.example.ru" disabled></textarea></label>
<label for="domain-exit">Домены → выбранный VPN<textarea id="domain-exit" spellcheck="false" placeholder="example.com&#10;*.example.com" disabled></textarea></label>
<label for="manual-ru">IPv4 / подсети → RU<textarea id="manual-ru" spellcheck="false" placeholder="Публичный IPv4 или CIDR" disabled></textarea></label>
<label for="manual-exit">IPv4 / подсети → выбранный VPN<textarea id="manual-exit" spellcheck="false" placeholder="8.8.8.8&#10;8.8.4.0/24" disabled></textarea></label>
</div>
<p class="muted">Без активного VPN направления EXIT блокируются. Доменное правило действует, когда sing-box распознаёт имя в трафике; ECH может этому помешать. Если нужен надёжный выбор по адресу, добавьте IPv4/CIDR.</p>
<p>Применение перезапустит sing-box и кратковременно прервёт соединения. При ошибке применения прежние настройки восстанавливаются.</p>
<button id="routes-save" onclick="saveRoutes()" disabled>Сохранить и применить</button>
<button id="routes-reload" onclick="reloadRoutes()">Загрузить актуальные списки</button>
<p id="route-message" aria-live="polite">Загрузка правил…</p></section>
<script>
const csrf=__CSRF__;
const info=document.getElementById('message');
function message(s,bad=false){info.textContent=s;info.className=bad?'bad':'good'}
async function api(action,payload={}){const r=await fetch('/api/'+action,{method:'POST',headers:{'Content-Type':'application/json','X-Panel-Token':csrf},body:JSON.stringify(payload)});const j=await r.json();if(!r.ok)throw Error(j.error||'Ошибка '+r.status);return j}
async function refresh(){try{const r=await fetch('/api/status');if(!r.ok)throw Error('Не удалось получить состояние');const s=await r.json();document.getElementById('current').textContent=s.active?(s.exits.find(x=>x.id===s.active)?.name||'Неизвестно'):'Нет активного выхода: зарубежный трафик заблокирован';const ul=document.getElementById('servers');ul.replaceChildren();if(!s.exits.length){const p=document.createElement('p');p.className='muted';p.textContent='Список пуст. Добавьте первый .conf ниже.';ul.append(p)}for(const e of s.exits){const li=document.createElement('li');const h=document.createElement('div');h.textContent=e.name+(e.active?' ● Активен':'');li.append(h);const x=document.createElement('small');x.className='muted';x.textContent=e.interface+' · '+(e.last_ip||'IP не определён')+' · '+(e.tunnel_up?'интерфейс поднят':'нет интерфейса');li.append(x,document.createElement('br'));for(const [caption,action,klass] of [['Проверить','validate',''],['Активировать','activate',''],['Удалить','delete','danger']]){if(action==='activate'&&e.active)continue;const btn=document.createElement('button');btn.textContent=caption;btn.className=klass;btn.onclick=async()=>{if(action==='delete'&&!confirm(e.active?'Отключить активный VPN и заблокировать зарубежный трафик?':'Удалить VPN-сервер '+e.name+'?'))return;btn.disabled=true;message('Выполняется '+caption.toLowerCase()+'…');try{const j=await api(action,{id:e.id,force:action==='delete'&&e.active});message('Готово. '+(j.ip?'Внешний IP: '+j.ip:''));await refresh()}catch(err){message(err.message,true)}finally{btn.disabled=false}};li.append(btn)}ul.append(li)}}catch(e){message(e.message,true)}}
async function addServer(){const b=document.getElementById('add'),f=document.getElementById('file').files[0],n=document.getElementById('name').value.trim();if(!f||!n){message('Введите имя и выберите .conf',true);return}if(f.size>32768){message('Максимальный размер .conf — 32 КБ',true);return}b.disabled=true;message('Создание туннеля и независимая проверка выхода…');try{const conf=await f.text();const j=await api('add',{name:n,conf});message('Добавлен '+j.added.name+'. Для использования нажмите «Активировать».');document.getElementById('file').value='';await refresh()}catch(e){message(e.message,true)}finally{b.disabled=false}}
refresh();
const routeKeys=['domain-ru','domain-exit','manual-ru','manual-exit'];
let routeRevision=null,routeDirty=false,routeBusy=false;
const routeMessage=document.getElementById('route-message');
function routeStatus(text,bad=false){routeMessage.textContent=text;routeMessage.className=bad?'bad':'good'}
function setRouteBusy(busy){routeBusy=busy;for(const key of routeKeys)document.getElementById(key).disabled=busy||routeRevision===null;document.getElementById('routes-save').disabled=busy||routeRevision===null;document.getElementById('routes-reload').disabled=busy}
function showRoutes(data){for(const key of routeKeys)document.getElementById(key).value=data.rules[key].join('\n');routeRevision=data.revision;routeDirty=false}
async function loadRoutes(){setRouteBusy(true);try{const r=await fetch('/api/routes');const j=await r.json();if(!r.ok)throw Error(j.error||'Не удалось загрузить правила');showRoutes(j);routeStatus('Загружены текущие правила')}catch(e){routeStatus(e.message,true)}finally{setRouteBusy(false)}}
async function reloadRoutes(){if(routeDirty&&!confirm('Заменить несохранённые изменения актуальными правилами с сервера?'))return;await loadRoutes()}
async function saveRoutes(){if(routeBusy||routeRevision===null)return;const rules={};for(const key of routeKeys)rules[key]=document.getElementById(key).value.split(/\r?\n/).map(x=>x.trim()).filter(Boolean);setRouteBusy(true);routeStatus('Проверка и применение правил…');try{const j=await api('routes-save',{rules,revision:routeRevision});showRoutes(j);routeStatus('Правила сохранены и применены')}catch(e){routeStatus(e.message+' Ваши изменения оставлены в полях.',true)}finally{setRouteBusy(false)}}
for(const key of routeKeys)document.getElementById(key).addEventListener('input',()=>{routeDirty=true;routeStatus('Есть несохранённые изменения')});
window.addEventListener('beforeunload',e=>{if(routeDirty){e.preventDefault();e.returnValue=''}});
loadRoutes();
</script></body></html>'''


def manager(*args, body=None):
    p=subprocess.run([sys.executable,str(ROOT/'scripts/manager.py'),*args],
       input=json.dumps(body,ensure_ascii=False) if body is not None else None,
       encoding='utf-8',stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
       timeout=120 if args and args[0]=='routes-save' else 65)
    try:data=json.loads(p.stdout)
    except json.JSONDecodeError:raise RuntimeError('Менеджер завершился без корректного ответа')
    if p.returncode:raise RuntimeError(data.get('error','Неизвестная ошибка'))
    return data


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        # Do not log uploaded config, secrets, or credentials.
        return

    def authenticated(self):
        header=self.headers.get('Authorization','')
        if not header.startswith('Basic '):return False
        try:
            userpass=base64.b64decode(header[6:],validate=True).decode('utf-8')
        except (ValueError,UnicodeError):return False
        pwd=PASSFILE.read_text().strip()
        return hmac.compare_digest(userpass,'admin:'+pwd)

    def respond(self,status,obj):
        raw=json.dumps(obj,ensure_ascii=False).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type','application/json; charset=utf-8')
        self.send_header('Cache-Control','no-store')
        self.send_header('X-Content-Type-Options','nosniff')
        self.send_header('Content-Length',str(len(raw)))
        self.end_headers();self.wfile.write(raw)

    def authorize(self):
        if not self.authenticated():
            self.send_response(401)
            self.send_header('WWW-Authenticate','Basic realm="VPN Proxy"')
            self.send_header('Content-Length','0');self.end_headers()
            return False
        return True

    def do_GET(self):
        if not self.authorize():return
        if self.path=='/':
            body=PAGE.replace('__CSRF__',json.dumps(CSRF)).encode('utf-8')
            self.send_response(200)
            self.send_header('Content-Type','text/html; charset=utf-8')
            self.send_header('Cache-Control','no-store')
            self.send_header('Content-Security-Policy',"default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'")
            self.send_header('X-Frame-Options','DENY')
            self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
        elif self.path=='/api/status':
            try:self.respond(200,manager('status'))
            except Exception:self.respond(503,{'error':'Не удалось прочитать состояние'})
        elif self.path=='/api/routes':
            try:self.respond(200,manager('routes'))
            except (RuntimeError,subprocess.TimeoutExpired) as exc:self.respond(503,{'error':str(exc)[:300]})
        else:self.respond(404,{'error':'Не найдено'})

    def do_POST(self):
        if not self.authorize():return
        # Only same-origin script may use a non-simple CSRF header.
        if not hmac.compare_digest(self.headers.get('X-Panel-Token',''),CSRF):
            return self.respond(403,{'error':'Неверный CSRF token'})
        origin=self.headers.get('Origin')
        if origin and origin not in {'http://127.0.0.1:8765','http://localhost:8765'}:
            return self.respond(403,{'error':'Недопустимый Origin'})
        try:
            n=int(self.headers.get('Content-Length','-1'))
            if n<0 or n>MAX_BODY:raise ValueError('Некорректный размер данных')
            data=json.loads(self.rfile.read(n))
            if not isinstance(data,dict):raise ValueError('Нужен JSON-объект')
            action=self.path.removeprefix('/api/')
            if action=='add':result=manager('add',body={'name':data['name'],'conf':data['conf']})
            elif action=='validate':result=manager('validate',data['id'])
            elif action=='activate':result=manager('activate',data['id'])
            elif action=='delete':result=manager('delete',data['id'],*(['--force'] if data.get('force') is True else []))
            elif action=='routes-save':result=manager('routes-save',body=data)
            else:return self.respond(404,{'error':'Неизвестная операция'})
            return self.respond(200,result)
        except (KeyError,ValueError,TypeError,RuntimeError,subprocess.TimeoutExpired) as exc:
            self.respond(400,{'error':str(exc)[:300]})

if __name__=='__main__':
    if os.geteuid()!=0:
        sys.exit('Для управления интерфейсами нужны права root. Слушаем только loopback.')
    ThreadingHTTPServer(('127.0.0.1',8765),Handler).serve_forever()
