"""Send two explicitly labeled simulated alerts to one authorized test chat."""
import argparse
import json
import tempfile
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
    args = parser.parse_args()
    config = json.loads(Path(args.config).read_text())
    production = json.loads((Path(config['state_dir']) / 'state.json').read_text())
    assert args.chat_id in config['allowed_users'] and args.chat_id in production['subscribers']
    snapshot = production['snapshot']
    config['server_name'] = '🧪 ТЕСТ уведомлений (симуляция, сервер работает штатно)'
    with tempfile.TemporaryDirectory(prefix='ilo-bot-alert-test-') as directory:
        config['state_dir'] = directory
        telegram = CountTelegram(config)
        bot = Bot(config, telegram)
        bot.state.data['subscribers'] = [args.chat_id]
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
