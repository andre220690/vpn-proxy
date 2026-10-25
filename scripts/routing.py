"""Validated manual routing lists and recoverable filesystem updates.

Callers must hold the manager lock across read/save and provide service callbacks.
"""
import hashlib
import ipaddress
import json
import os
import re
import stat
import tempfile
from pathlib import Path

from core import ConfigError, rules_text

KEYS = ('manual-ru', 'manual-exit', 'domain-ru', 'domain-exit')
MAX_ENTRIES = 500
NON_PUBLIC = tuple(ipaddress.ip_network(n) for n in (
    '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8',
    '169.254.0.0/16', '172.16.0.0/12', '192.0.0.0/24', '192.0.2.0/24',
    '192.168.0.0/16', '198.18.0.0/15', '198.51.100.0/24', '203.0.113.0/24',
    '224.0.0.0/4', '240.0.0.0/4'))


def _domain(value):
    wildcard = value.startswith('*.')
    name = value[2:] if wildcard else value
    try:
        name = name.encode('idna').decode('ascii').lower()
    except UnicodeError as exc:
        raise ConfigError('Некорректный домен') from exc
    labels = name.split('.')
    if (len(name) > 253 or len(labels) < 2 or
            any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label)
                for label in labels) or labels[-1].isdigit()):
        raise ConfigError('Нужен домен без URL, порта и пути: example.com или *.example.com')
    return ('*.' if wildcard else '') + name


def _domain_overlap(left, right):
    if left == right:
        return True
    for pattern, value in ((left, right), (right, left)):
        if pattern.startswith('*.'):
            base = pattern[2:]
            other = value.removeprefix('*.')
            # Conservative at the apex: suffix implementations can match it too.
            if other == base or other.endswith('.' + base):
                return True
    return False


def normalize_routes(payload):
    if not isinstance(payload, dict) or set(payload) != set(KEYS):
        raise ConfigError('Нужны все четыре списка маршрутизации')
    if any(not isinstance(payload[k], list) for k in KEYS):
        raise ConfigError('Правила должны быть списками строк')
    if sum(len(payload[k]) for k in KEYS) > MAX_ENTRIES:
        raise ConfigError('Максимум 500 правил суммарно')
    result = {}
    for key in KEYS:
        values = []
        for line, raw in enumerate(payload[key], 1):
            try:
                if not isinstance(raw, str) or len(raw) > 1024 or any(ord(c) < 32 for c in raw):
                    raise ConfigError('Нужна одна строка без управляющих символов')
                value = raw.strip()
                if not value:
                    continue
                if key.startswith('domain-'):
                    value = _domain(value)
                else:
                    net = ipaddress.ip_network(value, strict=False)
                    if net.version != 4 or not net.is_global or any(net.overlaps(n) for n in NON_PUBLIC):
                        raise ConfigError('Допустимы только публичные IPv4/CIDR')
                    value = str(net)
                if value not in values:
                    values.append(value)
            except (ValueError, UnicodeError) as exc:
                raise ConfigError(f'{key}, строка {line}: {exc}') from exc
        result[key] = values
    for left in result['manual-ru']:
        for right in result['manual-exit']:
            if ipaddress.ip_network(left).overlaps(ipaddress.ip_network(right)):
                raise ConfigError(f'Конфликт RU/EXIT: {left} и {right}')
    for left in result['domain-ru']:
        for right in result['domain-exit']:
            if _domain_overlap(left, right):
                raise ConfigError(f'Конфликт RU/EXIT: {left} и {right}')
    return result


def _snapshot(directory):
    snapshot = {}
    for key in KEYS:
        path = directory / (key + '.json')
        snapshot[key] = (path.read_bytes(), stat.S_IMODE(path.stat().st_mode)) if path.exists() else None
    return snapshot


def _revision(snapshot):
    h = hashlib.sha256()
    for key, item in snapshot.items():
        h.update(key.encode() + b'\0')
        h.update(b'missing' if item is None else b'present\0' + item[0])
        h.update(b'\0')
    return h.hexdigest()


def read_routes(directory):
    directory = Path(directory)
    snapshot = _snapshot(directory)
    result = {key: [] for key in KEYS}
    for key, item in snapshot.items():
        if item is None:
            continue
        try:
            if len(item[0]) > 100_000:
                raise ValueError('file too large')
            doc = json.loads(item[0])
            if set(doc) != {'version', 'rules'} or doc['version'] != 3 or not isinstance(doc['rules'], list):
                raise ValueError('unsupported format')
            for rule in doc['rules']:
                allowed = {'domain', 'domain_suffix'} if key.startswith('domain-') else {'ip_cidr'}
                if not isinstance(rule, dict) or not rule or not set(rule) <= allowed:
                    raise ValueError('unsupported fields')
                for field, values in rule.items():
                    if not isinstance(values, list) or any(not isinstance(v, str) for v in values):
                        raise ValueError('unsupported values')
                    for value in values:
                        if field == 'domain_suffix':
                            if not value.startswith('.'):
                                result[key].append(value)
                            result[key].append('*.' + value.lstrip('.'))
                        else:
                            result[key].append(value)
        except (ValueError, TypeError, KeyError) as exc:
            raise ConfigError(f'{key}.json: формат не поддерживается редактором; файл не изменён') from exc
    return {'rules': normalize_routes(result), 'revision': _revision(snapshot)}


def _write(path, data, mode=0o600):
    fd, name = tempfile.mkstemp(prefix='.route-', dir=str(path.parent))
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(data); f.flush(); os.fsync(f.fileno())
        os.chmod(name, mode)
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def save_routes(directory, payload, revision, validate, apply, rollback):
    directory = Path(directory)
    normalized = normalize_routes(payload)
    current = read_routes(directory)  # Refuse to overwrite unsupported hand-edited files.
    if not isinstance(revision, str) or revision != current['revision']:
        raise ConfigError('Правила изменились. Загрузите актуальные списки и повторите изменения')
    previous = _snapshot(directory)
    directory.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.routes-', dir=str(directory)) as tmp:
        stage = Path(tmp)
        for key in KEYS:
            _write(stage / (key + '.json'),
                   rules_text(normalized[key], key.startswith('domain-')).encode('utf-8'))
        candidate = validate(stage)  # No live mutation before sing-box accepts the candidate.
        try:
            for key in KEYS:
                _write(directory / (key + '.json'), (stage / (key + '.json')).read_bytes())
            apply(candidate)
        except Exception as exc:
            try:
                for key, item in previous.items():
                    path = directory / (key + '.json')
                    if item is None:
                        path.unlink(missing_ok=True)
                    else:
                        _write(path, item[0], item[1])
                rollback()
            except Exception as recovery:
                raise ConfigError('Ошибка применения и восстановления; проверьте службу sing-box по SSH') from recovery
            raise ConfigError('Не удалось применить правила; прежние настройки восстановлены') from exc
    return read_routes(directory)
