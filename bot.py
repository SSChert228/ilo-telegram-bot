"""Private Russian Telegram monitor for HPE iLO 4. No third-party dependencies."""
import argparse
import copy
from datetime import datetime, timedelta, timezone
import json
import logging
import os
from pathlib import Path
import signal
import threading
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, build_opener, ProxyHandler, HTTPRedirectHandler

from ilo import IloClient, IloError, first, health, issues, present, log_time

LOG = logging.getLogger('ilo-bot')
LABELS = {'OK': '✅ исправно', 'Warning': '⚠️ предупреждение', 'Critical': '🔴 неисправность',
          'Unknown': 'нет данных', 'On': 'включён', 'Off': 'выключен', 'Enabled': 'активен',
          'Absent': 'не установлен', 'Disabled': 'отключён', 'StandbyOffline': 'резерв'}
BUTTONS = {'📊 Состояние': 'status', '🌡 Температуры': 'temps', '🌀 Вентиляторы': 'fans',
           '⚡ Питание': 'power', '💾 Диски и RAID': 'storage', '📋 Журнал': 'logs',
           '🖥 О сервере': 'info', '🔔 Уведомления': 'alerts', '❓ Помощь': 'help'}
KEYBOARD = {'keyboard': [[{'text': label} for label in list(BUTTONS)[i:i+3]]
                         for i in range(0, len(BUTTONS), 3)], 'resize_keyboard': True}
COMMANDS = [('status', 'Общее состояние'), ('temps', 'Температуры'), ('fans', 'Вентиляторы'),
            ('power', 'Питание и блоки питания'), ('storage', 'Диски и RAID'),
            ('logs', 'Последние записи IML'), ('info', 'О сервере'),
            ('alerts', 'Состояние уведомлений'), ('alerts_on', 'Включить уведомления'),
            ('alerts_off', 'Выключить уведомления'), ('help', 'Помощь')]
HELP = ('Мониторинг сервера через iLO 4\n\n' + '\n'.join('/' + c + ' — ' + d for c, d in COMMANDS)
        + '\n\nОпрос раз в минуту. /start включает уведомления в этом чате. '
        'Сообщаю об изменениях неисправностей и восстановлении; одинаковые предупреждения не повторяю. '
        'При недоступности iLO жду 3 неудачных опроса.\n\n'
        'Бот работает в ВМ apps: при остановке всего физического сервера он тоже остановится. '
        'Данные iLO описывают оборудование, а не загрузку CPU/RAM операционной системы.')


def text_value(value):
    if value is None or value == '':
        return 'нет данных'
    return LABELS.get(str(value), str(value))


def unit(value, suffix):
    return 'нет данных' if value is None else str(value) + ' ' + suffix


def object_name(obj):
    return str(first(obj, 'Name', 'FanName', 'Location', 'Id', 'MemberId', default='Датчик'))


def timestamp(value):
    return datetime.fromtimestamp(value, timezone(timedelta(hours=3))).strftime('%d.%m.%Y %H:%M:%S МСК')


def format_snapshot(snapshot, command, name):
    if not snapshot:
        return name + '\nДанные iLO ещё не получены. Повторите запрос через минуту.'
    system = snapshot['system']
    age = max(0, int(time.time() - snapshot['collected_at']))
    lines = [name, 'Опрос: ' + timestamp(snapshot['collected_at']) + f' ({age} с назад)']
    if age > 150:
        lines.append('⚠️ Данные устарели: это последний успешный опрос.')
    if snapshot.get('errors'):
        lines.append('⚠️ Недоступны разделы: ' + ', '.join(snapshot['errors']))
    lines.append('')
    if command == 'status':
        lines += ['Сервер: ' + text_value(system.get('PowerState')),
                  'Общее состояние: ' + text_value(health(system))]
        power = snapshot.get('power', {})
        watts = power.get('PowerConsumedWatts')
        if watts is None:
            values = [v['PowerConsumedWatts'] for v in power.get('PowerControl', []) if v.get('PowerConsumedWatts') is not None]
            watts = sum(values) if values else None
        lines.append('Потребление: ' + unit(watts, 'Вт'))
        active = issues(snapshot)
        lines += [''] + (['⚠️ Требует внимания:'] + [k + ': ' + text_value(v) for k, v in active.items()]
                        if active else ['Активных предупреждений в доступных данных iLO нет.'])
    elif command == 'info':
        memory = system.get('MemorySummary') or system.get('Memory') or {}
        cpu = system.get('ProcessorSummary') or system.get('Processors') or {}
        lines += ['Модель: ' + text_value(system.get('Model')), 'Серийный номер: ' + text_value(system.get('SerialNumber')),
                  'BIOS: ' + text_value(system.get('BiosVersion')), 'CPU: ' + text_value(cpu.get('Model')),
                  'Процессоров: ' + text_value(cpu.get('Count')),
                  'Память: ' + unit(first(memory, 'TotalSystemMemoryGiB', 'TotalSystemMemoryGB'), 'ГиБ')]
    elif command in ('temps', 'fans'):
        key = 'Temperatures' if command == 'temps' else 'Fans'
        for obj in snapshot.get('thermal', {}).get(key, []):
            if not present(obj):
                continue
            if command == 'temps':
                reading = unit(first(obj, 'ReadingCelsius', 'CurrentReading'), '°C')
                threshold = obj.get('UpperThresholdCritical')
                if isinstance(threshold, (int, float)) and threshold > 0:
                    reading += f' / крит. {threshold} °C'
            else:
                suffix = {'Percent': '%', 'RPM': 'об/мин'}.get(obj.get('Units'), obj.get('ReadingUnits') or '')
                if obj.get('ReadingRPM') is not None:
                    reading = unit(obj['ReadingRPM'], 'об/мин')
                else:
                    reading = unit(first(obj, 'Reading', 'CurrentReading'), suffix)
            lines.append(object_name(obj) + ': ' + reading + ' · ' + text_value(health(obj)))
    elif command == 'power':
        power = snapshot.get('power', {})
        if power.get('PowerConsumedWatts') is not None:
            lines.append('Потребление сервера: ' + unit(power['PowerConsumedWatts'], 'Вт'))
        else:
            for obj in power.get('PowerControl', []):
                lines.append('Потребление сервера: ' + unit(obj.get('PowerConsumedWatts'), 'Вт'))
        for index, obj in enumerate(power.get('PowerSupplies', []), 1):
            bay = obj.get('Oem', {}).get('Hp', {}).get('BayNumber', index)
            lines.append('БП ' + str(bay) + ': ' + text_value(health(obj)) + ' · '
                         + text_value((obj.get('Status') or {}).get('State'))
                         + '\n  Номинал: ' + unit(obj.get('PowerCapacityWatts'), 'Вт')
                         + '; отдаёт: ' + unit(first(obj, 'PowerOutputWatts', 'LastPowerOutputWatts'), 'Вт')
                         + '; вход: ' + unit(obj.get('LineInputVoltage'), 'В'))
        for obj in power.get('Redundancy', []):
            lines.append('Режим резервирования: ' + text_value(obj.get('Mode')))
    elif command == 'storage':
        for controller in snapshot.get('storage', []):
            lines.append(text_value(controller.get('Model') or object_name(controller)) + ': ' + text_value(health(controller)))
            lines.append('Кэш: ' + unit(controller.get('CacheMemorySizeMiB'), 'МиБ')
                         + '; резервное питание: ' + text_value(controller.get('BackupPowerSourceStatus')))
            for obj in controller.get('LogicalDrives', []):
                capacity = round(obj['CapacityMiB'] / (1024 ** 2), 2) if obj.get('CapacityMiB') is not None else None
                lines.append('RAID (по iLO): ' + text_value(obj.get('Raid')) + ' · ' + unit(capacity, 'ТиБ')
                             + ' · ' + text_value(health(obj)))
            for obj in controller.get('DiskDrives', []):
                lines.append('Диск ' + text_value(obj.get('Location')) + ': ' + text_value(health(obj))
                             + '\n  ' + text_value(obj.get('Model')) + ' · ' + unit(obj.get('CapacityGB'), 'ГБ')
                             + ' · ' + unit(obj.get('CurrentTemperatureCelsius'), '°C'))
        for vendor in system.get('Oem', {}).values():
            if isinstance(vendor, dict):
                for obj in vendor.get('Battery', []):
                    condition = obj.get('Condition')
                    lines.append(str(obj.get('ProductName') or 'Батарея кэша').strip() + ': '
                                 + text_value('OK' if str(condition).lower() == 'ok' else condition))
    if len(lines) <= 4:
        lines.append('В этом разделе iLO не вернул показаний.')
    return '\n'.join(lines)


def format_logs(entries):
    lines = ['Последние записи IML (история, не список активных неисправностей)', '']
    for obj in entries:
        repaired = (obj.get('Oem', {}).get('Hp', {}).get('Repaired'))
        lines.append(str(log_time(obj) or 'Время неизвестно') + ' · '
                     + text_value(obj.get('Severity')) + (' · устранено' if repaired else '')
                     + '\n' + str(obj.get('Message') or 'Без описания'))
    return '\n'.join(lines) if entries else 'Журнал IML пуст.'


def allowed_message(update, allowed_users):
    message = update.get('message') or {}
    sender = message.get('from') or {}
    chat = message.get('chat') or {}
    return (isinstance(sender.get('id'), int) and sender['id'] in allowed_users
            and not sender.get('is_bot', False) and chat.get('type') == 'private'
            and chat.get('id') == sender['id'] and not message.get('via_bot')
            and not message.get('sender_chat') and not message.get('business_connection_id'))


class TelegramError(Exception):
    def __init__(self, code=0, retry_after=0):
        super().__init__('Telegram error ' + str(code))
        self.code = code
        self.retry_after = retry_after


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class Telegram:
    def __init__(self, config):
        self.base = 'https://api.telegram.org/bot' + config['telegram_token'] + '/'
        proxy = config.get('telegram_proxy')
        self.opener = build_opener(ProxyHandler({'https': proxy} if proxy else {}), NoRedirect())

    def call(self, method, **payload):
        request = Request(self.base + method, data=json.dumps(payload).encode(),
                          headers={'Content-Type': 'application/json'}, method='POST')
        try:
            with self.opener.open(request, timeout=35) as response:
                data = json.load(response)
        except HTTPError as exc:
            try:
                data = json.loads(exc.read())
            except (ValueError, OSError):
                data = {}
            raise TelegramError(exc.code, data.get('parameters', {}).get('retry_after', 0)) from None
        except (OSError, URLError, ValueError) as exc:
            raise TelegramError() from None
        if not data.get('ok'):
            raise TelegramError(data.get('error_code', 0), data.get('parameters', {}).get('retry_after', 0))
        return data['result']

    def send(self, chat_id, text, keyboard=False):
        # 1800 Unicode characters are <= 3600 UTF-16 code units, even with emoji.
        for start in range(0, len(text), 1800):
            payload = {'chat_id': chat_id, 'text': text[start:start+1800]}
            if keyboard and start == 0:
                payload['reply_markup'] = KEYBOARD
            self.call('sendMessage', **payload)


class State:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.file = self.directory / 'state.json'
        self.lock = threading.RLock()
        self.data = json.loads(self.file.read_text(encoding='utf-8')) if self.file.exists() else {}
        self.data.setdefault('subscribers', [])
        self.data.setdefault('notified', {})
        self.data.setdefault('offset', 0)

    def save(self):
        with self.lock:
            temp = self.file.with_suffix('.tmp')
            with temp.open('w', encoding='utf-8') as handle:
                json.dump(self.data, handle, ensure_ascii=False)
                handle.flush()
                os.fsync(handle.fileno())
            temp.replace(self.file)


def alert_changes(previous, current):
    new = [key + ': ' + text_value(value) for key, value in current.items() if previous.get(key) != value]
    recovered = [key for key in previous if key not in current]
    lines = (['⚠️ Изменения состояния:', *new] if new else [])
    if recovered:
        lines += ['✅ Восстановлено:', *recovered]
    return '\n'.join(lines)


class Monitor:
    def __init__(self, config, state, stop):
        self.config, self.state, self.stop = config, state, stop
        self.ilo = IloClient(config)
        self.failures = 0
        self.ready = False
        self.current = copy.deepcopy(state.data.get('current_issues', {}))
        self.last_error = None

    def collect(self):
        try:
            snapshot = self.ilo.snapshot()
            current = issues(snapshot)
            if snapshot.get('errors'):
                # Missing telemetry cannot prove a previously broken component recovered.
                current = {**{k: v for k, v in self.current.items() if k != 'iLO'}, **current}
            with self.state.lock:
                self.state.data['snapshot'] = snapshot
                self.current = current
                self.state.data['current_issues'] = current
                self.state.save()
                self.failures = 0
                self.last_error = None
                self.ready = True
            LOG.info('iLO collection successful; unavailable sections=%s', ','.join(snapshot.get('errors', {})) or 'none')
        except IloError as exc:
            with self.state.lock:
                self.failures += 1
                self.last_error = str(exc)
                if self.failures >= self.config.get('failure_threshold', 3):
                    self.current = {**self.current, 'iLO': 'Недоступен'}
                    self.state.data['current_issues'] = self.current
                    self.state.save()
                    self.ready = True
            LOG.warning('iLO collection failed (%d): %s', self.failures, exc)

    def run(self):
        while not self.stop.is_set():
            started = time.monotonic()
            self.collect()
            self.stop.wait(max(1, self.config.get('poll_seconds', 60) - (time.monotonic() - started)))


class Bot:
    def __init__(self, config, telegram=None):
        self.config = config
        self.allowed = set(config['allowed_users'])
        if not self.allowed or any(type(i) is not int or i <= 0 for i in self.allowed):
            raise ValueError('allowed_users must be a nonempty list of positive integers')
        self.state = State(config['state_dir'])
        self.stop = threading.Event()
        self.telegram = telegram or Telegram(config)
        self.monitor = Monitor(config, self.state, self.stop)
        self.last_request = {}
        self.username = ''

    def handle(self, update):
        if not allowed_message(update, self.allowed):
            return
        message = update['message']
        uid = message['from']['id']
        if not isinstance(message.get('text'), str):
            return
        # Avoid responding to old queued commands after a prolonged outage.
        if message.get('date', time.time()) < time.time() - 300:
            return
        raw = message['text'].strip()
        if not raw:
            return
        command = BUTTONS.get(raw, raw.split()[0].lstrip('/').split('@')[0].lower())
        if '@' in raw.split()[0] and self.username and raw.split()[0].split('@', 1)[1].lower() != self.username.lower():
            return
        if time.monotonic() - self.last_request.get(uid, -100) < 1:
            return
        self.last_request[uid] = time.monotonic()
        with self.state.lock:
            snapshot = copy.deepcopy(self.state.data.get('snapshot'))
        if command in ('start', 'alerts_on', 'alerts_off', 'stop'):
            enabled = command in ('start', 'alerts_on')
            with self.state.lock:
                subscribers = set(self.state.data['subscribers']) & self.allowed
                subscribers.add(uid) if enabled else subscribers.discard(uid)
                self.state.data['subscribers'] = sorted(subscribers)
                self.state.data['notified'][str(uid)] = copy.deepcopy(self.monitor.current)
                self.state.save()
            response = 'Уведомления включены.' if enabled else 'Уведомления выключены. Команды продолжают работать.'
            if command == 'start':
                response += '\n\n' + format_snapshot(snapshot, 'status', self.config['server_name']) + '\n\nКоманды: /help'
        elif command in ('help', 'setting', 'settings'):
            response = HELP
        elif command == 'alerts':
            response = ('Уведомления: ' + ('включены' if uid in self.state.data['subscribers'] else 'выключены')
                        + '\n/alerts_on — включить\n/alerts_off — выключить')
        elif command == 'logs':
            try:
                response = format_logs(self.monitor.ilo.logs())
            except IloError:
                response = 'Не удалось прочитать журнал iLO. Повторите запрос позже.'
        elif command in ('status', 'temps', 'fans', 'power', 'storage', 'info'):
            response = format_snapshot(snapshot, command, self.config['server_name'])
            if self.monitor.last_error:
                response = '⚠️ Последний опрос iLO не удался. Ниже — сохранённые данные.\n\n' + response
        else:
            response = 'Неизвестная команда. Выберите кнопку меню или /help.'
        self.telegram.send(uid, response, keyboard=True)
        LOG.info('Command handled: user=%d command=%s', uid, command if command in {c for c, _ in COMMANDS} | {'start', 'stop'} else 'other')

    def notify(self):
        with self.state.lock:
            if not self.monitor.ready:
                return
            current = copy.deepcopy(self.monitor.current)
            subscribers = sorted(set(self.state.data['subscribers']) & self.allowed)
        for uid in subscribers:
            previous = self.state.data['notified'].get(str(uid), {})
            text = alert_changes(previous, current)
            if not text:
                continue
            try:
                self.telegram.send(uid, self.config['server_name'] + '\n' + text)
            except TelegramError as exc:
                LOG.warning('Alert delivery failed: user=%d code=%d', uid, exc.code)
                if exc.code == 403:
                    with self.state.lock:
                        self.state.data['subscribers'].remove(uid)
                        self.state.save()
                if exc.code == 429:
                    self.stop.wait(min(max(exc.retry_after, 1), 300))
                continue
            with self.state.lock:
                self.state.data['notified'][str(uid)] = current
                self.state.save()

    def run(self):
        thread = threading.Thread(target=self.monitor.run, daemon=True, name='ilo-monitor')
        thread.start()
        configured = False
        while not self.stop.is_set():
            try:
                if not thread.is_alive():
                    raise RuntimeError('iLO monitor worker stopped')
                if not configured:
                    self.username = self.telegram.call('getMe')['username']
                    if self.telegram.call('getWebhookInfo').get('url'):
                        raise RuntimeError('Existing Telegram webhook must be reviewed before polling')
                    self.telegram.call('setMyCommands', commands=[{'command': c, 'description': d} for c, d in COMMANDS])
                    configured = True
                    LOG.info('Telegram polling ready: @%s', self.username)
                self.notify()
                updates = self.telegram.call('getUpdates', offset=self.state.data['offset'], timeout=20,
                                             allowed_updates=['message'], limit=50)
                for update in updates:
                    try:
                        self.handle(update)
                    except TelegramError as exc:
                        if exc.code not in (400, 403):
                            raise
                        LOG.warning('Command reply rejected: code=%d', exc.code)
                    with self.state.lock:
                        self.state.data['offset'] = update['update_id'] + 1
                        self.state.save()
            except TelegramError as exc:
                if exc.code in (401, 409):
                    raise RuntimeError('Telegram authorization/polling conflict: ' + str(exc.code)) from None
                LOG.warning('Telegram temporarily unavailable: code=%d', exc.code)
                self.stop.wait(min(max(exc.retry_after, 5), 300))
        thread.join(timeout=15)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', default='/etc/ilo-telegram-bot/config.json')
    parser.add_argument('--check', action='store_true', help='Read iLO and check Telegram without polling or sending messages')
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
    config = json.loads(Path(args.config).read_text(encoding='utf-8'))
    if args.check:
        snapshot = IloClient(config).snapshot()
        tg = Telegram(config)
        me = tg.call('getMe')
        webhook = tg.call('getWebhookInfo')
        print(json.dumps({'telegram_username': me['username'], 'webhook_present': bool(webhook.get('url')),
                          'model': snapshot['system'].get('Model'), 'power': snapshot['system'].get('PowerState'),
                          'sections_unavailable': snapshot['errors'], 'issues': issues(snapshot)}, ensure_ascii=False))
        return
    bot = Bot(config)
    # Guard against a second process using this state directory on Linux.
    instance_lock = None
    if os.name == 'posix':
        import fcntl
        instance_lock = (bot.state.directory / 'instance.lock').open('w')
        fcntl.flock(instance_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: bot.stop.set())
    bot.run()


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        # A traceback from a network library can include the token URL.
        LOG.error('Bot stopped: %s', type(error).__name__)
        raise SystemExit(1)
