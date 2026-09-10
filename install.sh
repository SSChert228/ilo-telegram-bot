#!/bin/sh
set -eu
test "$(id -u)" = 0 || { echo 'Run with sudo'; exit 1; }
cd "$(dirname "$0")"
python3 -m unittest -v test_bot.py
python3 bot.py --config config.json --check
if ! id ilo-bot >/dev/null 2>&1; then
    useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin ilo-bot
fi
install -d -m 0755 /opt/homelab/bots/ilo-telegram-bot
install -d -o root -g ilo-bot -m 0750 /etc/ilo-telegram-bot
if test -f /etc/ilo-telegram-bot/config.json; then
    install -m 0600 /etc/ilo-telegram-bot/config.json /etc/ilo-telegram-bot/config.json.previous
fi
for file in bot.py ilo.py test_bot.py integration_alert_test.py README.md README.ru.md; do
    install -o root -g root -m 0644 "$file" /opt/homelab/bots/ilo-telegram-bot/
done
install -o root -g ilo-bot -m 0640 config.json /etc/ilo-telegram-bot/config.json
install -m 0644 ilo-telegram-bot.service /etc/systemd/system/ilo-telegram-bot.service
systemd-analyze verify /etc/systemd/system/ilo-telegram-bot.service
systemctl daemon-reload
systemctl enable ilo-telegram-bot.service
systemctl restart ilo-telegram-bot.service
systemctl is-active ilo-telegram-bot.service
rm -- config.json
