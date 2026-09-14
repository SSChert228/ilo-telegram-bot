"""Send two explicitly labeled simulated alerts to one authorized test chat."""
import argparse
import json
import tempfile
import time
from unittest.mock import MagicMock
from pathlib import Path

from bot import Bot, Telegram
from ilo import IloError


class CountTelegram(Telegram):
    sent = 0

    def send(self, *args, **kwargs):
        super().send(*args, **kwargs)
        self.sent += 1


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', required=True)
    parser.add_argument('--chat-id', type=int, required=True)
    parser.add_argument('--domains', action='store_true', help='Test two DNS change alerts instead of hardware alerts')
    args = parser.parse_args()
    config = json.loads(Path(args.config).read_text())
    production = json.loads((Path(config['state_dir']) / 'state.json').read_text())
    if args.chat_id not in config['allowed_users'] or args.chat_id not in production['subscribers']:
        raise SystemExit('Test recipient must be an allowed subscriber')
    snapshot = production['snapshot']
    config['server_name'] = '🧪 ТЕСТ уведомлений (симуляция, сервер работает штатно)'
    with tempfile.TemporaryDirectory(prefix='ilo-bot-alert-test-') as directory:
        config['state_dir'] = directory
        telegram = CountTelegram(config)
        bot = Bot(config, telegram)
        bot.state.data['subscribers'] = [args.chat_id]
        if args.domains:
            if not bot.domains.enabled:
                raise SystemExit('Domain monitoring is not configured')
            bot.state.data['domains_snapshot'] = {'collected_at': time.time(), 'rows': [
                {'name': 'test.example.invalid', 'status': 'OK',
                 'records': [('A', 'test.example.invalid', '192.0.2.1')]}]}
            bot.domains.ready = True
            bot.notify()
            assert telegram.sent == 0
            row = bot.state.data['domains_snapshot']['rows'][0]
            for expected, address in enumerate(['192.0.2.2', '192.0.2.1'], 1):
                row['records'] = [('A', 'test.example.invalid', address)]
                bot.notify()
                bot.notify()
                assert telegram.sent == expected
            print(json.dumps({'dns_alert_integration': 'passed', 'messages_sent': telegram.sent,
                              'deduplication': 'passed', 'dns_modified': False,
                              'production_state_modified': False}))
            return
        bot.monitor.ilo.snapshot = MagicMock(side_effect=IloError('simulated outage'))
        for _ in range(2):
            bot.monitor.collect()
            bot.notify()
        assert telegram.sent == 0
        bot.monitor.collect()
        bot.notify()
        bot.notify()
        assert telegram.sent == 1
        bot.monitor.ilo.snapshot.side_effect = None
        bot.monitor.ilo.snapshot.return_value = snapshot
        bot.monitor.collect()
        bot.notify()
        bot.notify()
        assert telegram.sent == 2
        print(json.dumps({'alert_integration': 'passed', 'messages_sent': telegram.sent,
                          'failure_threshold': 3, 'deduplication': 'passed',
                          'recovery': 'passed', 'hardware_modified': False}))


if __name__ == '__main__':
    main()
