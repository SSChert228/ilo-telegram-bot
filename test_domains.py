import copy
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlparse

from bot import Bot, COMMANDS, KEYBOARD, State, TelegramError
from domains import (DomainClient, DomainError, DomainMonitor, REG_URL, TYPES,
                     domain_name, domain_fingerprint, domain_changes, format_domains, request_json)
from test_bot import config, message, USERS


def settings(**extra):
    return {'zones': ['example.com'], 'names': ['www.example.com'], **extra}


def dns_answer(url, payload=None, proxy=None):
    args = parse_qs(urlparse(url).query)
    name, kind = args['name'][0], args['type'][0]
    values = {'A': '192.0.2.1', 'AAAA': '2001:db8::1', 'NS': 'ns1.example.net.'}
    answers = [{'name': name + '.', 'type': TYPES[kind], 'TTL': 60, 'data': values[kind]}] if kind in values else []
    return {'Status': 0, 'Answer': answers}


def snapshot():
    return {'collected_at': time.time(), 'rows': [{'name': 'example.com', 'status': 'OK',
            'records': [('A', 'example.com', '192.0.2.1')], 'route': None}],
            'zones': ['example.com'], 'complete_inventory': False, 'server_ips': ['192.0.2.1'],
            'poll_seconds': 300}


class DnsTests(unittest.TestCase):
    def test_names_idna_wildcard_and_invalid_input(self):
        self.assertEqual(domain_name('EXAMPLE.com.'), 'example.com')
        self.assertEqual(domain_name('пример.рф'), 'xn--e1afmkfd.xn--p1ai')
        self.assertEqual(domain_name('_minecraft._tcp.example.com'), '_minecraft._tcp.example.com')
        self.assertEqual(domain_name('*.example.com'), '*.example.com')
        for value in ['https://example.com', 'a..com', 'a.*.com', 'example.com\nsecret', '-a.com', 'x' * 64 + '.com']:
            with self.assertRaises(ValueError):
                domain_name(value)

    @patch('domains.request_json', side_effect=dns_answer)
    def test_live_shape_ipv4_ipv6_and_dedup(self, request):
        value = DomainClient(settings()).snapshot()
        self.assertEqual(len(value['rows']), 2)
        self.assertEqual(len(value['rows'][0]['records']), 3)
        self.assertFalse(value['complete_inventory'])
        self.assertEqual(request.call_count, 12)

    @patch('domains.request_json')
    def test_cname_chain_mail_and_srv(self, request):
        request.return_value = {'Status': 0, 'Answer': [
            {'type': 5, 'name': 'www.example.com.', 'data': 'edge.example.net.'},
            {'type': 1, 'name': 'edge.example.net.', 'data': '192.0.2.44'},
            {'type': 15, 'name': 'www.example.com.', 'data': '10 mail.example.net.'},
            {'type': 33, 'name': 'www.example.com.', 'data': '0 5 25565 game.example.net.'}]}
        _, _, records = DomainClient(settings()).query(('www.example.com', 'A'))
        self.assertIn(('A', 'edge.example.net', '192.0.2.44'), records)
        self.assertIn(('MX', 'www.example.com', '10 mail.example.net'), records)
        self.assertIn(('SRV', 'www.example.com', '0 5 25565 game.example.net'), records)

    @patch('domains.request_json')
    def test_null_mx(self, request):
        request.return_value = {'Status': 0, 'Answer': [{'type': 15, 'name': 'example.com.', 'data': '0 .'}]}
        self.assertEqual(DomainClient(settings()).query(('example.com', 'MX'))[2][0][2], '0 .')

    @patch('domains.request_json')
    def test_nxdomain_is_different_from_nodata_and_failure(self, request):
        client = DomainClient(settings())
        request.return_value = {'Status': 3}
        self.assertEqual(client.snapshot()['rows'][0]['status'], 'NXDOMAIN')
        request.return_value = {'Status': 0}
        self.assertEqual(client.snapshot()['rows'][0]['status'], 'OK')
        for result in [{'Status': 2}, {'Status': 5}, {'Status': 0, 'TC': True}, {'Status': 0, 'Answer': [{}]}]:
            request.return_value = result
            with self.assertRaises(DomainError):
                client.query(('example.com', 'A'))

    @patch('domains.request_json')
    def test_reg_zone_discovers_all_names_without_exposing_txt(self, request):
        def response(url, payload=None, proxy=None):
            if url == REG_URL:
                return {'result': 'success', 'answer': {'domains': [{'dname': 'example.com', 'result': 'success',
                    'rrs': [{'subname': '@', 'rectype': 'A', 'content': '192.0.2.1'},
                            {'subname': 'new', 'rectype': 'A', 'content': '192.0.2.2'},
                            {'subname': '_verify', 'rectype': 'TXT', 'content': 'private-verification-value'},
                            {'subname': '*', 'rectype': 'CNAME', 'content': 'example.com.'}]}]}}
            return dns_answer(url)
        request.side_effect = response
        client = DomainClient(settings(regru_username='user', regru_password='secret'))
        value = client.snapshot()
        self.assertTrue(value['complete_inventory'])
        self.assertEqual(len(value['rows']), 5)
        self.assertIn('new.example.com', [row['name'] for row in value['rows']])
        self.assertNotIn('private-verification-value', json.dumps(value))
        self.assertNotIn('secret', json.dumps(value))

    @patch('domains.request_json')
    def test_reg_failed_missing_or_malformed_zone_is_not_empty_inventory(self, request):
        client = DomainClient(settings(regru_username='user', regru_password='secret'))
        for response in [{'result': 'error', 'error_text': 'secret'},
                         {'result': 'success', 'answer': {'domains': []}},
                         {'result': 'success', 'answer': {'domains': [{'dname': 'example.com', 'result': 'error'}]}}]:
            request.return_value = response
            with self.assertRaises(DomainError) as ctx:
                client.inventory()
            self.assertNotIn('secret', str(ctx.exception))

    def test_bounds_credentials_and_graceful_stop(self):
        with self.assertRaises(ValueError):
            DomainClient(settings(regru_username='user'))
        with self.assertRaises(ValueError):
            DomainClient(settings(routes={'example.com': {'target': 'site', 'confirmed': 'false'}}))
        with self.assertRaises(DomainError):
            DomainClient(settings(names=[f'n{i}.example.com' for i in range(201)])).inventory()
        stop = threading.Event()
        stop.set()
        with patch('domains.request_json') as request, self.assertRaises(DomainError):
            DomainClient(settings()).snapshot(stop)
        request.assert_not_called()

    @patch('domains.request_json')
    def test_broken_alias_is_not_a_deleted_name(self, request):
        def answer(url, payload=None, proxy=None):
            kind = parse_qs(urlparse(url).query)['type'][0]
            return {'Status': 0 if kind == 'CNAME' else 3, 'Answer': [
                {'name': 'example.com.', 'type': 5, 'data': 'missing.example.net.'}]}
        request.side_effect = answer
        value = DomainClient(settings(names=[])).snapshot()
        self.assertEqual(value['rows'][0]['status'], 'TARGET_NXDOMAIN')
        self.assertIn('Назначение CNAME не существует', format_domains(value))

    @patch('domains.request_json')
    def test_inconsistent_negative_answers_do_not_report_deletion(self, request):
        def answer(url, payload=None, proxy=None):
            kind = parse_qs(urlparse(url).query)['type'][0]
            return {'Status': 0 if kind == 'A' else 3}
        request.side_effect = answer
        with self.assertRaises(DomainError):
            DomainClient(settings()).snapshot()

    @patch('domains.build_opener')
    def test_transport_fixed_post_body_and_sanitized_error(self, opener):
        opener.return_value.open.side_effect = HTTPError(REG_URL, 403, 'private secret', {}, None)
        with self.assertRaises(DomainError) as ctx:
            request_json(REG_URL, {'password': 'private secret'})
        self.assertNotIn('private secret', str(ctx.exception))
        request = opener.return_value.open.call_args.args[0]
        self.assertEqual(request.get_method(), 'POST')
        self.assertEqual(request.full_url, REG_URL)
        self.assertIn('private secret', parse_qs(request.data.decode())['input_data'][0])
        redirect_handler = opener.call_args.args[1]
        self.assertIsNone(redirect_handler.redirect_request(None, None, None, None, None, None))

    def test_view_coverage_plans_external_addresses_and_staleness(self):
        value = snapshot()
        value['rows'][0]['route'] = {'target': 'Сайт → 192.0.2.10:8080', 'confirmed': False}
        value['rows'][0]['records'].append(('A', 'example.com', '192.0.2.2'))
        text = format_domains(value, 'Нет связи')
        for expected in ['Полнота зоны REG.RU не проверена', 'План, подключение не проверено',
                         'другой IP', 'сохранённые данные', 'не подтверждает доступность']:
            self.assertIn(expected, text)

    def test_fingerprint_ignores_order_and_time_but_detects_destination(self):
        value = snapshot()
        before = domain_fingerprint(value)
        value['collected_at'] += 300
        value['rows'][0]['records'].reverse()
        self.assertEqual(before, domain_fingerprint(value))
        value['rows'][0]['records'] = [('A', 'example.com', '192.0.2.2')]
        self.assertIn('Изменилось: example.com', domain_changes(before, domain_fingerprint(value)))
        self.assertIn('Удалено из зоны', domain_changes(before, {}))
        self.assertIn('Добавлено', domain_changes({}, before))


class DomainBotTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.config = config(self.directory.name)
        self.config['domains'] = settings()
        self.telegram = MagicMock()
        self.bot = Bot(self.config, self.telegram)
        self.bot.domains.client.snapshot = MagicMock(return_value=snapshot())
        self.bot.domains.collect()

    def subscribe(self):
        self.bot.handle(message(text='/start'))
        self.telegram.send.reset_mock()

    def change(self):
        self.bot.state.data['domains_snapshot']['rows'][0]['records'] = [('A', 'example.com', '192.0.2.2')]

    def test_button_and_command_cached_and_independent_of_ilo(self):
        self.assertIn('domains', dict(COMMANDS))
        self.assertIn({'text': '🌐 Домены'}, sum(KEYBOARD['keyboard'], []))
        self.bot.domains.client.snapshot.reset_mock()
        self.bot.monitor.ilo = MagicMock()
        for command in ['/domains', '🌐 Домены']:
            self.bot.last_request.clear()
            self.bot.handle(message(text=command))
            self.assertIn('example.com', self.telegram.send.call_args.args[1])
        self.bot.domains.client.snapshot.assert_not_called()
        self.bot.monitor.ilo.snapshot.assert_not_called()

    def test_unauthorized_and_group_do_not_read_or_reply(self):
        self.bot.domains.report = MagicMock()
        for update in [message(uid=42, text='/domains'), message(text='/domains', chat_type='group')]:
            self.bot.handle(update)
        self.bot.domains.report.assert_not_called()
        self.telegram.send.assert_not_called()

    def test_failure_keeps_cache_and_does_not_report_deletion(self):
        self.subscribe()
        old = copy.deepcopy(self.bot.state.data['domains_snapshot'])
        self.bot.domains.client.snapshot.side_effect = DomainError('DNS недоступен')
        self.bot.domains.collect()
        self.bot.notify()
        self.assertEqual(self.bot.state.data['domains_snapshot'], old)
        self.assertIn('сохранённые данные', self.bot.domains.report())
        self.telegram.send.assert_not_called()

    def test_changes_notify_once_without_ilo_ready_and_survive_restart(self):
        self.subscribe()
        self.change()
        self.bot.notify()
        self.bot.notify()
        self.assertEqual(self.telegram.send.call_count, 1)
        restarted = Bot(self.config, self.telegram)
        restarted.domains.ready = True
        restarted.notify()
        self.assertEqual(self.telegram.send.call_count, 1)

    def test_first_poll_for_existing_subscriber_silent(self):
        self.bot.state.data['subscribers'] = [USERS[0]]
        self.bot.notify()
        self.telegram.send.assert_not_called()
        self.change()
        self.bot.notify()
        self.assertEqual(self.telegram.send.call_count, 1)

    def test_retry_after_delivery_failure(self):
        self.subscribe()
        baseline = copy.deepcopy(self.bot.state.data['domains_notified'])
        self.change()
        self.telegram.send.side_effect = TelegramError(502)
        self.bot.notify()
        self.assertEqual(self.bot.state.data['domains_notified'], baseline)
        self.telegram.send.side_effect = None
        self.bot.notify()
        self.assertEqual(self.telegram.send.call_count, 2)

    def test_blocked_unsubscribed_or_revoked_user_does_not_receive_changes(self):
        self.subscribe()
        self.change()
        self.telegram.send.side_effect = TelegramError(403)
        self.bot.notify()
        self.assertEqual(self.bot.state.data['subscribers'], [])
        self.bot.state.data['subscribers'] = [42]
        self.bot.notify()
        self.assertEqual(self.telegram.send.call_count, 1)

    def test_alerts_off_disables_dns_messages(self):
        self.subscribe()
        self.bot.last_request.clear()
        self.bot.handle(message(text='/alerts_off'))
        self.telegram.send.reset_mock()
        self.change()
        self.bot.notify()
        self.telegram.send.assert_not_called()

    def test_existing_config_without_domains_is_compatible(self):
        bot = Bot(config(self.directory.name), self.telegram)
        bot.handle(message(text='/domains'))
        self.assertIn('не настроен', self.telegram.send.call_args.args[1])


if __name__ == '__main__':
    unittest.main()
