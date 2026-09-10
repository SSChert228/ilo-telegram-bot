"""Offline regression suite: no real Telegram messages or hardware changes."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import MagicMock, patch

from bot import (Bot, Telegram, TelegramError, State, allowed_message, alert_changes,
                 format_snapshot, format_logs)
from ilo import IloClient, IloError, health, issues

USERS = [6000000001, 6000000002, 6000000003]


def fixture():
    return {'collected_at': time.time(), 'errors': {},
            'system': {'Model': 'ProLiant ML350 Gen9', 'PowerState': 'On',
                       'Status': {'HealthRollUp': 'OK'}, 'SerialNumber': 'TEST123',
                       'ProcessorSummary': {'Count': 2, 'Model': 'Xeon'},
                       'MemorySummary': {'TotalSystemMemoryGiB': 64}},
            'thermal': {'Temperatures': [
                {'Name': 'CPU 1', 'CurrentReading': 45, 'UpperThresholdCritical': 85, 'Status': {'Health': 'OK'}},
                {'Name': 'Empty DIMM', 'CurrentReading': 0, 'Status': {'State': 'Absent'}}],
                'Fans': [{'FanName': 'Fan 1', 'CurrentReading': 18, 'Units': 'Percent', 'Status': {'Health': 'OK'}}]},
            'power': {'PowerConsumedWatts': 0, 'PowerSupplies': [
                {'Name': 'PSU 1', 'PowerCapacityWatts': 1400, 'Status': {'Health': 'OK', 'State': 'Enabled'}}]},
            'storage': [{'Name': 'P440ar', 'Status': {'Health': 'OK'},
                         'DiskDrives': [{'Location': '1I:1:1', 'CapacityGB': 1200, 'Status': {'Health': 'OK'}}],
                         'LogicalDrives': [{'Raid': '1+0', 'CapacityMiB': 2000000, 'Status': {'Health': 'OK'}}]}]}


def config(directory):
    return {'telegram_token': 'test:never-real', 'allowed_users': USERS,
            'ilo_url': 'https://192.0.2.10', 'ilo_username': 'test', 'ilo_password': 'secret',
            'server_name': 'Test server', 'state_dir': directory, 'failure_threshold': 3, 'poll_seconds': 60}


def message(uid=USERS[0], text='/status', chat_type='private', chat_id=None):
    return {'update_id': 1, 'message': {'from': {'id': uid, 'is_bot': False},
            'chat': {'type': chat_type, 'id': uid if chat_id is None else chat_id},
            'text': text, 'date': int(time.time())}}


class AccessTests(unittest.TestCase):
    def test_all_three_users_allowed(self):
        for uid in USERS:
            self.assertTrue(allowed_message(message(uid), set(USERS)))

    def test_other_users_and_missing_sender_denied(self):
        for uid in [1, 0, -1, 6000000000, '6000000001', None]:
            self.assertFalse(allowed_message(message(uid), set(USERS)))
        self.assertFalse(allowed_message({}, set(USERS)))

    def test_groups_channels_and_chat_id_spoof_denied(self):
        for typ in ['group', 'supergroup', 'channel', None]:
            self.assertFalse(allowed_message(message(chat_type=typ), set(USERS)))
        self.assertFalse(allowed_message(message(chat_id=USERS[1]), set(USERS)))

    def test_bot_inline_business_and_anonymous_denied(self):
        for key in ['via_bot', 'sender_chat', 'business_connection_id']:
            update = message()
            update['message'][key] = {'id': 1}
            self.assertFalse(allowed_message(update, set(USERS)))
        update = message()
        update['message']['from']['is_bot'] = True
        self.assertFalse(allowed_message(update, set(USERS)))


class FormatTests(unittest.TestCase):
    def test_zero_watts_is_not_missing(self):
        self.assertIn('0 Вт', format_snapshot(fixture(), 'status', 'Server'))

    def test_legacy_temperatures_and_absent_sensor(self):
        value = format_snapshot(fixture(), 'temps', 'Server')
        self.assertIn('45 °C', value)
        self.assertNotIn('Empty DIMM', value)

    def test_fan_percent_is_not_rpm(self):
        value = format_snapshot(fixture(), 'fans', 'Server')
        self.assertIn('18 %', value)
        self.assertNotIn('об/мин', value)

    def test_unknown_and_stale_data_explicit(self):
        value = fixture()
        value['collected_at'] -= 1000
        value['system']['Status'] = {}
        result = format_snapshot(value, 'status', 'Server')
        self.assertIn('устарели', result)
        self.assertIn('Общее состояние: нет данных', result)

    def test_missing_section_not_reported_healthy(self):
        value = fixture()
        value['errors']['storage'] = 'iLO HTTP 404'
        result = format_snapshot(value, 'status', 'Server')
        self.assertIn('Нет данных: storage', result)
        self.assertNotIn('Активных предупреждений', result)

    def test_raid_fault_and_temperature_threshold(self):
        value = fixture()
        value['storage'][0]['DiskDrives'][0]['Status']['Health'] = 'Critical'
        value['thermal']['Temperatures'][0]['CurrentReading'] = 86
        active = issues(value)
        self.assertEqual(sum(v == 'Critical' for v in active.values()), 2)

    def test_empty_and_historical_logs(self):
        self.assertIn('пуст', format_logs([]))
        self.assertIn('история', format_logs([{'Message': 'Old power loss', 'Severity': 'Critical'}]))

    def test_health_rollup_case(self):
        self.assertEqual(health({'Status': {'HealthRollUp': 'Warning', 'Health': 'OK'}}), 'Warning')
        self.assertEqual(health({'Status': {'HealthRollup': 'Critical'}}), 'Critical')

    def test_ilo_zero_thresholds_do_not_create_false_alarms(self):
        value = fixture()
        value['thermal']['Temperatures'][0]['UpperThresholdFatal'] = 0
        self.assertEqual(issues(value), {})
        value['thermal']['Temperatures'][0]['UpperThresholdCritical'] = 0
        self.assertNotIn('крит. 0', format_snapshot(value, 'temps', 'Server'))
        self.assertEqual(issues(value), {})

    def test_identical_psu_names_keep_both_faults(self):
        value = fixture()
        value['power']['PowerSupplies'] = [
            {'Name': 'HpServerPowerSupply', 'Status': {'Health': 'Warning'}},
            {'Name': 'HpServerPowerSupply', 'Status': {'Health': 'Critical'}}]
        self.assertEqual(len(issues(value)), 2)

    def test_legacy_and_redfish_power_not_duplicated(self):
        value = fixture()
        value['power']['PowerControl'] = [{'PowerConsumedWatts': 0}]
        self.assertEqual(format_snapshot(value, 'power', 'Server').count('Потребление сервера:'), 1)

    def test_cache_battery_failure(self):
        value = fixture()
        value['system']['Oem'] = {'Hp': {'Battery': [{'Index': 1, 'Condition': 'Failed'}]}}
        self.assertEqual(issues(value)['Батарея кэша 1'], 'Failed')


class BotTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.telegram = MagicMock()
        self.bot = Bot(config(self.directory.name), self.telegram)
        self.bot.state.data['snapshot'] = fixture()
        self.bot.monitor.ready = True

    def send(self, text, uid=USERS[0]):
        self.bot.last_request.clear()
        self.bot.handle(message(uid, text))

    def test_unauthorized_no_reply_no_subscription_no_ilo(self):
        self.bot.monitor.ilo = MagicMock()
        for command in ['/start', '/logs', '/status', '/alerts_on']:
            self.send(command, 42)
        self.telegram.send.assert_not_called()
        self.bot.monitor.ilo.logs.assert_not_called()
        self.assertEqual(self.bot.state.data['subscribers'], [])

    def test_start_and_stop_persist(self):
        self.send('/start')
        self.assertIn(USERS[0], State(self.directory.name).data['subscribers'])
        self.send('/alerts_off')
        self.assertNotIn(USERS[0], State(self.directory.name).data['subscribers'])
        self.send('/status')
        self.assertEqual(self.telegram.send.call_count, 3)

    def test_command_menu_and_buttons(self):
        self.bot.monitor.ilo.logs = MagicMock(return_value=[])
        for cmd in ['/status', '/temps', '/fans', '/power', '/storage', '/info', '/help',
                    '/logs', '/alerts', '/unknown', '📊 Состояние', '🌡 Температуры']:
            self.send(cmd)
            self.assertEqual(self.telegram.send.call_args.args[0], USERS[0])
            self.assertTrue(self.telegram.send.call_args.args[1])

    def test_rate_limit_and_stale_messages(self):
        self.send('/status')
        self.bot.handle(message())
        self.assertEqual(self.telegram.send.call_count, 1)
        old = message()
        old['message']['date'] -= 600
        self.bot.last_request.clear()
        self.bot.handle(old)
        self.assertEqual(self.telegram.send.call_count, 1)

    def test_non_text_and_wrong_bot_command(self):
        update = message()
        del update['message']['text']
        self.bot.handle(update)
        self.bot.username = 'actual_bot'
        self.send('/status@different_bot')
        self.telegram.send.assert_not_called()

    def test_alert_once_and_recovery(self):
        self.send('/start')
        self.telegram.send.reset_mock()
        self.bot.monitor.current = {'Fan 1': 'Critical'}
        self.bot.notify()
        self.bot.notify()
        self.assertEqual(self.telegram.send.call_count, 1)
        self.bot.monitor.current = {}
        self.bot.notify()
        self.assertIn('Восстановлено', self.telegram.send.call_args.args[1])

    def test_notification_retry_and_revoked_allowlist(self):
        self.send('/start')
        self.telegram.send.reset_mock()
        self.bot.monitor.current = {'Fan 1': 'Critical'}
        self.telegram.send.side_effect = TelegramError(502)
        self.bot.notify()
        self.assertEqual(self.bot.state.data['notified'][str(USERS[0])], {})
        self.telegram.send.side_effect = None
        self.bot.notify()
        self.assertEqual(self.telegram.send.call_count, 2)
        self.bot.allowed.clear()
        self.bot.monitor.current = {}
        self.bot.notify()
        self.assertEqual(self.telegram.send.call_count, 2)

    def test_blocked_user_subscription_removed(self):
        self.send('/start')
        self.telegram.send.side_effect = TelegramError(403)
        self.bot.monitor.current = {'Fan 1': 'Critical'}
        self.bot.notify()
        self.assertEqual(self.bot.state.data['subscribers'], [])

    def test_three_failures_then_recovery(self):
        self.bot.monitor.ilo.snapshot = MagicMock(side_effect=IloError('offline'))
        self.bot.monitor.collect()
        self.bot.monitor.collect()
        self.assertNotIn('iLO', self.bot.monitor.current)
        self.bot.monitor.collect()
        self.assertIn('iLO', self.bot.monitor.current)
        self.bot.monitor.ilo.snapshot.side_effect = None
        self.bot.monitor.ilo.snapshot.return_value = fixture()
        self.bot.monitor.collect()
        self.assertNotIn('iLO', self.bot.monitor.current)

    def test_partial_data_does_not_clear_hardware_fault(self):
        self.bot.monitor.current = {'RAID': 'Critical'}
        value = fixture()
        value['errors']['storage'] = 'offline'
        self.bot.monitor.ilo.snapshot = MagicMock(return_value=value)
        self.bot.monitor.collect()
        self.assertEqual(self.bot.monitor.current['RAID'], 'Critical')

    def test_alert_baseline_survives_restart(self):
        self.send('/start')
        self.bot.monitor.current = {'Fan': 'Warning'}
        self.bot.notify()
        restarted = Bot(config(self.directory.name), self.telegram)
        restarted.monitor.current = {'Fan': 'Warning'}
        restarted.monitor.ready = True
        self.telegram.send.reset_mock()
        restarted.notify()
        self.telegram.send.assert_not_called()

    def test_log_failure_is_user_friendly(self):
        self.bot.monitor.ilo.logs = MagicMock(side_effect=IloError('offline'))
        self.send('/logs')
        self.assertIn('Не удалось', self.telegram.send.call_args.args[1])

    def test_restart_preserves_faults_during_outage(self):
        self.bot.state.data['current_issues'] = {'RAID': 'Critical'}
        self.bot.state.save()
        restarted = Bot(config(self.directory.name), self.telegram)
        restarted.monitor.ilo.snapshot = MagicMock(side_effect=IloError('offline'))
        for _ in range(3):
            restarted.monitor.collect()
        self.assertEqual(restarted.monitor.current['RAID'], 'Critical')
        self.assertIn('iLO', restarted.monitor.current)

    def test_partial_failure_is_not_marked_recovered_while_another_section_missing(self):
        self.bot.monitor.current = {'Нет данных: storage': 'Unknown'}
        value = fixture()
        value['errors']['power'] = 'offline'
        self.bot.monitor.ilo.snapshot = MagicMock(return_value=value)
        self.bot.monitor.collect()
        self.assertIn('Нет данных: storage', self.bot.monitor.current)


class TransportTests(unittest.TestCase):
    def setUp(self):
        self.config = config('unused')

    def test_credentials_cannot_leave_ilo_origin(self):
        client = IloClient(self.config)
        for url in ['https://evil.example/redfish/v1/Systems/', 'http://192.0.2.10/rest/v1/',
                    '//evil.example/rest/v1/', '/login', 'https://user@192.0.2.10/rest/v1/']:
            with self.assertRaises(IloError):
                client.path(url)

    def test_tls_pin_checked_before_authorization_sent(self):
        self.config['ilo_cert_sha256'] = '0' * 64
        client = IloClient(self.config)
        with patch('ilo.http.client.HTTPSConnection') as cls:
            conn = cls.return_value
            conn.sock.getpeercert.return_value = b'wrong certificate'
            with self.assertRaises(IloError):
                client.get('/redfish/v1/Systems/1/')
            conn.request.assert_not_called()

    def test_read_only_and_redirect_rejected(self):
        client = IloClient(self.config)
        with patch('ilo.http.client.HTTPSConnection') as cls:
            conn = cls.return_value
            conn.getresponse.return_value.status = 302
            with self.assertRaises(IloError):
                client.get('/redfish/v1/Systems/1/')
            self.assertEqual(conn.request.call_args.args[0], 'GET')
            self.assertEqual(conn.request.call_count, 1)

    def test_legacy_expanded_items_and_pagination(self):
        client = IloClient(self.config)
        client.get = MagicMock(side_effect=[{'Items': [{'Name': 'first'}],
                   'links': {'NextPage': {'href': '/rest/v1/Systems/?page=2'}}}, {'Items': [{'Name': 'second'}]}])
        self.assertEqual([o['Name'] for o in client.collection('/rest/v1/Systems/')], ['first', 'second'])

    def test_redfish_members_dereferenced(self):
        client = IloClient(self.config)
        client.get = MagicMock(side_effect=[{'Members': [{'@odata.id': '/redfish/v1/Systems/1/'}]}, {'Name': 'server'}])
        self.assertEqual(client.collection('/redfish/v1/Systems/')[0]['Name'], 'server')

    def test_ilo_mixed_collection_reuses_expanded_items(self):
        client = IloClient(self.config)
        client.get = MagicMock(return_value={'Members': [{'@odata.id': '/redfish/v1/Systems/1/'}],
                                            'Items': [{'Name': 'server'}]})
        self.assertEqual(client.collection('/redfish/v1/Systems/')[0]['Name'], 'server')
        self.assertEqual(client.get.call_count, 1)

    def test_logs_include_newest_events_without_created_timestamp(self):
        client = IloClient(self.config)
        client.root = '/redfish/v1/'
        client.paths['logs'] = '/redfish/v1/Systems/1/LogServices/IML/Entries/'
        client.collection = MagicMock(return_value=[
            {'Id': '1', 'Created': '2020-01-01T00:00:00Z', 'Message': 'old'},
            {'Id': '2', 'Oem': {'Hp': {'Updated': '2026-09-10T15:55:00Z'}}, 'Message': 'new'}])
        self.assertEqual(client.logs()[0]['Message'], 'new')
        self.assertIn('2026-09-10', format_logs(client.logs()))

    def test_pagination_loop_detected(self):
        client = IloClient(self.config)
        client.get = MagicMock(return_value={'Members': [], 'Members@odata.nextLink': '/redfish/v1/Systems/'})
        with self.assertRaises(IloError):
            client.collection('/redfish/v1/Systems/')

    def test_large_telegram_message_chunking(self):
        telegram = Telegram(self.config)
        telegram.call = MagicMock()
        text = '🌡' * 6000
        telegram.send(USERS[0], text)
        sent = [call.kwargs['text'] for call in telegram.call.call_args_list]
        self.assertEqual(''.join(sent), text)
        self.assertTrue(all(len(s.encode('utf-16-le')) // 2 <= 4096 for s in sent))

    def test_corrupted_state_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / 'state.json').write_text('invalid json')
            with self.assertRaises(ValueError):
                State(directory)


if __name__ == '__main__':
    unittest.main()
