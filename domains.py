"""Read-only REG.RU inventory and public DNS monitoring (standard library only)."""
import argparse
import copy
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import ipaddress
import json
import logging
from pathlib import Path
import re
import time
from urllib.parse import urlencode
from urllib.request import Request, build_opener, ProxyHandler, HTTPRedirectHandler

LOG = logging.getLogger('ilo-bot.domains')
TYPES = {'A': 1, 'AAAA': 28, 'CNAME': 5, 'MX': 15, 'SRV': 33, 'NS': 2}
TYPE_NAMES = {v: k for k, v in TYPES.items()}
REG_URL = 'https://api.reg.ru/api/regru2/zone/get_resource_records'
DNS_URL = 'https://dns.google/resolve'


class DomainError(Exception):
    """A deliberately sanitized error safe to show in Telegram/logs."""


def domain_name(value):
    if not isinstance(value, str):
        raise ValueError('Invalid domain name')
    name = value.rstrip('.').lower().encode('idna').decode('ascii')
    labels = name.split('.')
    if (len(name) > 253 or len(labels) < 2
            or any(not re.fullmatch(r'[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?|\*', p) for p in labels)
            or '*' in labels[1:]):
        raise ValueError('Invalid domain name')
    return name


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def request_json(url, payload=None, proxy=None):
    # Fixed HTTPS destinations; credentials never enter a URL or follow a redirect.
    data = urlencode({'input_format': 'json', 'input_data': json.dumps(payload)}).encode() if payload else None
    headers = {'Accept': 'application/json', 'User-Agent': 'ilo-telegram-bot/domains'}
    if data:
        headers['Content-Type'] = 'application/x-www-form-urlencoded'
    request = Request(url, data=data, headers=headers)
    opener = build_opener(ProxyHandler({'https': proxy} if proxy else {}), NoRedirect())
    try:
        with opener.open(request, timeout=8) as response:
            raw = response.read(2_000_001)
        if len(raw) > 2_000_000:
            raise ValueError('Response too large')
        result = json.loads(raw)
        if not isinstance(result, dict):
            raise ValueError('Unexpected response')
        return result
    except (OSError, ValueError) as exc:
        raise DomainError('Не удалось получить ответ DNS/REG.RU') from None


class DomainClient:
    def __init__(self, config):
        self.config = config
        self.zones = sorted({domain_name(n) for n in config.get('zones', [])})
        self.names = {domain_name(n) for n in config.get('names', [])} | set(self.zones)
        self.routes = {domain_name(n): v for n, v in config.get('routes', {}).items()}
        for route in self.routes.values():
            if (not isinstance(route, dict) or not isinstance(route.get('target'), str)
                    or not 1 <= len(route['target']) <= 512
                    or any(ord(c) < 32 for c in route['target'])
                    or type(route.get('confirmed', False)) is not bool):
                raise ValueError('Invalid domain route')
        self.names.update(self.routes)
        self.expected = {str(ipaddress.ip_address(v)) for v in config.get('server_ips', [])}
        self.reg_enabled = bool(config.get('regru_username') and config.get('regru_password'))
        if bool(config.get('regru_username')) != bool(config.get('regru_password')):
            raise ValueError('Both REG.RU credentials are required')
        if self.reg_enabled and not self.zones:
            raise ValueError('REG.RU zones are required')
        if not self.names:
            raise ValueError('At least one domain is required')
        self.interval = max(60, int(config.get('poll_seconds', 300)))

    def inventory(self):
        names = set(self.names)
        if self.reg_enabled:
            payload = {'username': self.config['regru_username'], 'password': self.config['regru_password'],
                       'domains': [{'dname': n} for n in self.zones], 'output_content_type': 'plain'}
            result = request_json(REG_URL, payload, self.config.get('regru_proxy'))
            if result.get('result') != 'success':
                raise DomainError('REG.RU: не удалось прочитать зону; проверьте доступ к API')
            try:
                zones = result['answer']['domains']
                for name in self.zones:
                    zone = next(z for z in zones if domain_name(z['dname']) == name)
                    if zone.get('result') != 'success' or not isinstance(zone['rrs'], list):
                        raise ValueError()
                    for record in zone['rrs']:
                        subname = record['subname']
                        # REG.RU supplies relative owner names, including @ and wildcards.
                        names.add(domain_name(name if subname in ('', '@') else subname + '.' + name))
            except (KeyError, TypeError, ValueError, StopIteration):
                raise DomainError('REG.RU: неполный или неизвестный формат DNS-зоны') from None
        if len(names) > 200:
            raise DomainError('В списке больше 200 имён; разделите зоны между конфигурациями')
        return sorted(names)

    def query(self, task):
        name, kind = task
        url = DNS_URL + '?' + urlencode({'name': name, 'type': kind, 'edns_client_subnet': '0.0.0.0/0'})
        result = request_json(url, proxy=self.config.get('dns_proxy'))
        if type(result.get('Status')) is not int or result['Status'] not in (0, 3) or result.get('TC'):
            raise DomainError('DNS: ошибка разрешения имени ' + name)
        records = set()
        try:
            for answer in result.get('Answer', []):
                record_type = TYPE_NAMES.get(answer['type'])
                if record_type is None:
                    continue
                owner = domain_name(answer['name'])
                value = answer['data'].strip()
                if record_type in ('A', 'AAAA'):
                    ip = ipaddress.ip_address(value)
                    if ip.version != (4 if record_type == 'A' else 6):
                        raise ValueError()
                    value = str(ip)
                elif record_type in ('CNAME', 'NS'):
                    value = domain_name(value)
                else:
                    parts = value.split()
                    count = 2 if record_type == 'MX' else 4
                    if len(parts) != count or any(not p.isdigit() or int(p) > 65535 for p in parts[:-1]):
                        raise ValueError()
                    # RFC 7505 null MX and SRV target '.' mean no service.
                    value = ' '.join([*(str(int(p)) for p in parts[:-1]),
                                      '.' if parts[-1] == '.' else domain_name(parts[-1])])
                records.add((record_type, owner, value))
        except (KeyError, TypeError, AttributeError, ValueError):
            raise DomainError('DNS: неизвестный формат ответа для ' + name) from None
        return name, result['Status'], sorted(records)

    def snapshot(self, stop=None):
        names = self.inventory()
        tasks = [(n, kind) for n in names for kind in TYPES]
        rows = {n: {'name': n, 'records': [], 'route': self.routes.get(n)} for n in names}
        statuses = {n: {} for n in names}
        # Batches bound shutdown time and pending work; commands never wait for DNS.
        with ThreadPoolExecutor(max_workers=6) as pool:
            for start in range(0, len(tasks), 6):
                if stop and stop.is_set():
                    raise DomainError('Опрос остановлен')
                batch = tasks[start:start+6]
                for (_, kind), (name, status, records) in zip(batch, pool.map(self.query, batch)):
                    statuses[name][kind] = status
                    rows[name]['records'].extend(records)
        for name, row in rows.items():
            values = set(statuses[name].values())
            broken_alias = (statuses[name]['A'] == statuses[name]['AAAA'] == 3
                            and any(r[0] == 'CNAME' for r in row['records']))
            if len(values) != 1 and not broken_alias:
                raise DomainError('DNS: ответы ещё не согласованы для ' + name)
            row['status'] = 'TARGET_NXDOMAIN' if broken_alias else ('NXDOMAIN' if values == {3} else 'OK')
            row['records'] = sorted(set(tuple(r) for r in row['records']))
        return {'collected_at': time.time(), 'rows': list(rows.values()), 'zones': self.zones,
                'complete_inventory': self.reg_enabled, 'server_ips': sorted(self.expected),
                'poll_seconds': self.interval}


def domain_fingerprint(snapshot):
    """TTL, order and collection time do not represent a routing change."""
    return {row['name']: json.dumps({'status': row['status'], 'records': sorted(row['records'])},
                                   sort_keys=True, ensure_ascii=False)
            for row in snapshot['rows']}


def domain_changes(previous, current):
    lines = []
    for name in sorted(previous.keys() | current.keys()):
        if name not in previous:
            lines.append('Добавлено: ' + name)
        elif name not in current:
            lines.append('Удалено из зоны: ' + name)
        elif previous[name] != current[name]:
            lines.append('Изменилось: ' + name)
    return ('🌐 Изменения DNS\n' + '\n'.join(lines) + '\n\nАдреса и службы: /domains') if lines else ''


def format_domains(snapshot, error=None):
    lines = ['🌐 Домены и назначения']
    if error:
        lines += ['⚠️ Последний опрос не удался: ' + error]
    if not snapshot:
        return '\n'.join(lines + ['Данные ещё не получены. Повторите запрос через минуту.'])
    when = datetime.fromtimestamp(snapshot['collected_at'], timezone(timedelta(hours=3)))
    lines += ['Проверено: ' + when.strftime('%d.%m.%Y %H:%M:%S МСК')]
    if error or time.time() - snapshot['collected_at'] > snapshot['poll_seconds'] * 2:
        lines += ['⚠️ Ниже — сохранённые данные, они могут быть устаревшими.']
    lines += [('Список имён: зоны REG.RU (' + ', '.join(snapshot['zones']) + ').')
              if snapshot['complete_inventory'] else
              'Список имён: из настроек. Полнота зоны REG.RU не проверена.']
    expected = set(snapshot.get('server_ips', []))
    for row in snapshot['rows']:
        lines += ['', row['name']]
        if row['status'] in ('NXDOMAIN', 'TARGET_NXDOMAIN'):
            lines += ['❌ Имя не существует в DNS.' if row['status'] == 'NXDOMAIN'
                      else '❌ Назначение CNAME не существует в DNS.']
        elif not row['records']:
            lines += ['Нет записей A/AAAA/CNAME/MX/SRV/NS.']
        for kind, owner, value in row['records']:
            prefix = kind if owner == row['name'] else owner + ' · ' + kind
            suffix = ''
            if kind in ('A', 'AAAA') and expected:
                suffix = ' (IP сервера из настроек)' if value in expected else ' (другой IP)'
            lines.append(prefix + ' → ' + value + suffix)
        route = row.get('route')
        if route:
            lines += [('Служба по конфигурации: ' if route.get('confirmed') else 'План, подключение не проверено: ')
                      + route['target']]
        else:
            lines += ['Служба внутри сети: не указана.']
    lines += ['', 'DNS не подтверждает доступность сайта или проброс портов.',
              'Обновление каждые ' + str(snapshot['poll_seconds']) + ' с; /alerts_on — изменения DNS.']
    return '\n'.join(lines)


class DomainMonitor:
    def __init__(self, config, state, stop):
        self.client = DomainClient(config) if config else None
        self.state, self.stop = state, stop
        self.enabled = self.client is not None
        self.ready = False

    def collect(self):
        try:
            snapshot = self.client.snapshot(self.stop)
            with self.state.lock:
                self.state.data['domains_snapshot'] = snapshot
                self.state.data['domains_error'] = None
                self.state.save()
                self.ready = True
            LOG.info('DNS collection successful; names=%d', len(snapshot['rows']))
        except DomainError as exc:
            with self.state.lock:
                self.state.data['domains_error'] = str(exc)
                self.state.save()
                self.ready = False
            LOG.warning('DNS collection failed: %s', exc)

    def report(self):
        if not self.enabled:
            return '🌐 Мониторинг доменов не настроен. Добавьте раздел domains в конфигурацию бота.'
        with self.state.lock:
            return format_domains(copy.deepcopy(self.state.data.get('domains_snapshot')),
                                  self.state.data.get('domains_error'))

    def run(self):
        while not self.stop.is_set():
            started = time.monotonic()
            self.collect()
            self.stop.wait(max(1, self.client.interval - (time.monotonic() - started)))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Read DNS/REG.RU without Telegram or iLO')
    parser.add_argument('--config', required=True)
    args = parser.parse_args()
    try:
        settings = json.loads(Path(args.config).read_text(encoding='utf-8'))
        print(format_domains(DomainClient(settings['domains']).snapshot()))
    except (DomainError, ValueError, KeyError, OSError) as error:
        print('Проверка доменов не удалась: ' + (str(error) if isinstance(error, DomainError) else type(error).__name__))
        raise SystemExit(1)
