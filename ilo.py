"""Read-only iLO 4 client: Redfish and legacy /rest/v1, Python 3.10+."""
import base64
import hashlib
import hmac
import http.client
import json
import ssl
import time
from urllib.parse import urlsplit


class IloError(Exception):
    def __init__(self, message, status=0):
        super().__init__(message)
        self.status = status


def link(value):
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return value.get('@odata.id') or value.get('href')
    return None


def related(obj, key):
    for container in (obj, obj.get('Links', {}), obj.get('links', {})):
        if isinstance(container, dict) and link(container.get(key)):
            return link(container[key])
    for vendor in obj.get('Oem', {}).values():
        if isinstance(vendor, dict):
            result = related(vendor, key)
            if result:
                return result
    return None


def first(obj, *keys, default=None):
    return next((obj[k] for k in keys if obj.get(k) is not None), default)


def health(obj):
    status = obj.get('Status') or {}
    return first(status, 'HealthRollup', 'HealthRollUp', 'Health', default='Unknown')


def present(obj):
    return (obj.get('Status') or {}).get('State') != 'Absent'


def log_time(entry):
    updated = [v.get('Updated') for v in entry.get('Oem', {}).values() if isinstance(v, dict) and v.get('Updated')]
    return max(updated + [str(entry.get('Created') or entry.get('EventTimestamp') or '')])


class IloClient:
    def __init__(self, config):
        self.origin = urlsplit(config['ilo_url'].rstrip('/'))
        if (self.origin.scheme != 'https' or not self.origin.hostname
                or self.origin.username or self.origin.password
                or self.origin.path not in ('', '/') or self.origin.query or self.origin.fragment):
            raise ValueError('ilo_url must be https://host[:port]')
        self.pin = config.get('ilo_cert_sha256', '').lower().replace(':', '')
        if self.pin and (len(self.pin) != 64 or any(c not in '0123456789abcdef' for c in self.pin)):
            raise ValueError('ilo_cert_sha256 must contain 64 hexadecimal characters')
        self.context = ssl.create_default_context()
        if self.pin:
            self.context.check_hostname = False
            self.context.verify_mode = ssl.CERT_NONE
            if config.get('ilo_legacy_tls', False):
                self.context.set_ciphers('DEFAULT:@SECLEVEL=1')
        credentials = (config['ilo_username'] + ':' + config['ilo_password']).encode()
        self.authorization = 'Basic ' + base64.b64encode(credentials).decode('ascii')
        self.root = None
        self.paths = {}

    def path(self, uri):
        parsed = urlsplit(uri)
        if parsed.scheme or parsed.netloc:
            if (parsed.scheme, parsed.hostname, parsed.port or 443) != (
                    'https', self.origin.hostname, self.origin.port or 443):
                raise IloError('iLO returned a link to a different origin')
        if not parsed.path.startswith(('/rest/v1/', '/redfish/v1/')):
            raise IloError('iLO returned a path outside its API')
        if parsed.username or parsed.fragment or '\\' in uri:
            raise IloError('Invalid iLO API link')
        return parsed.path + ('?' + parsed.query if parsed.query else '')

    def get(self, uri):
        path = self.path(uri)
        conn = http.client.HTTPSConnection(self.origin.hostname, self.origin.port or 443,
                                           timeout=12, context=self.context)
        try:
            conn.connect()
            if self.pin:
                actual = hashlib.sha256(conn.sock.getpeercert(binary_form=True)).hexdigest()
                if not hmac.compare_digest(actual, self.pin):
                    raise IloError('iLO TLS certificate fingerprint changed')
            # Verify the peer before transmitting any credentials; never follow redirects.
            conn.request('GET', path, headers={'Authorization': self.authorization,
                                             'Accept': 'application/json'})
            response = conn.getresponse()
            if response.status != 200:
                raise IloError('iLO HTTP ' + str(response.status), response.status)
            data = response.read(4 * 1024 * 1024 + 1)
            if len(data) > 4 * 1024 * 1024:
                raise IloError('iLO response too large')
            result = json.loads(data)
            if not isinstance(result, dict):
                raise IloError('iLO response is not an object')
            return result
        except (OSError, http.client.HTTPException, ValueError) as exc:
            # Do not expose URLs, passwords, headers or response bodies in errors.
            raise IloError('iLO transport error: ' + type(exc).__name__) from None
        finally:
            conn.close()

    def collection(self, uri, limit=256):
        result, visited = [], set()
        base_uri = uri.split('?')[0]
        while uri:
            if uri in visited or len(visited) >= 32:
                raise IloError('iLO collection pagination loop or limit exceeded')
            visited.add(uri)
            page = self.get(uri)
            # iLO 4 often returns both: Items already contains the full resources.
            # Reusing them avoids dozens of slow per-sensor or per-log-entry requests.
            members = first(page, 'Items', 'Members')
            if members is None:
                members = (page.get('links') or {}).get('Member', [])
            for member in members:
                if len(result) >= limit:
                    raise IloError('iLO collection size limit exceeded')
                # Legacy Items are expanded objects; Members are normally links.
                if isinstance(member, dict) and any(k in member for k in ('Name', 'Model', 'Message', 'Status')):
                    result.append(member)
                elif link(member):
                    result.append(self.get(link(member)))
            uri = first(page, 'Members@odata.nextLink', 'Items@odata.nextLink') or related(page, 'NextPage')
            # Older iLO 4 uses a numeric next page and a page query parameter.
            next_page = page.get('links', {}).get('NextPage')
            if not uri and isinstance(next_page, dict) and next_page.get('page') is not None:
                uri = base_uri + '?page=' + str(next_page['page'])
        return result

    def discover(self):
        for root in ('/redfish/v1/', '/rest/v1/'):
            try:
                systems = self.collection(root + 'Systems/')
                if not systems:
                    raise IloError('iLO returned no systems')
                self.root = root
                system = systems[0]
                self.paths['system'] = link(system) or related(system, 'self') or root + 'Systems/1/'
                chassis = self.collection(root + 'Chassis/')
                if not chassis:
                    raise IloError('iLO returned no chassis')
                chassis_obj = chassis[0]
                chassis_path = link(chassis_obj) or related(chassis_obj, 'self') or root + 'Chassis/1/'
                self.paths['thermal'] = related(chassis_obj, 'Thermal') or chassis_path.rstrip('/') + '/Thermal/'
                self.paths['power'] = related(chassis_obj, 'Power') or chassis_path.rstrip('/') + '/Power/'
                storage = related(system, 'SmartStorage') or self.paths['system'].rstrip('/') + '/SmartStorage/'
                self.paths['storage'] = storage.rstrip('/') + '/ArrayControllers/'
                self.paths['logs'] = self.paths['system'].rstrip('/') + '/LogServices/IML/Entries/'
                return
            except IloError as exc:
                if exc.status not in (404, 405, 501):
                    raise
        raise IloError('Neither Redfish nor legacy REST API is available')

    def storage(self):
        controllers = self.collection(self.paths['storage'])
        result = []
        for controller in controllers:
            item = dict(controller)
            base = link(controller) or related(controller, 'self')
            for key in ('DiskDrives', 'LogicalDrives'):
                path = related(controller, key)
                if key == 'DiskDrives':
                    path = path or related(controller, 'PhysicalDrives')
                path = path or (base.rstrip('/') + '/' + key + '/' if base else None)
                if not path:
                    raise IloError('No storage link for ' + key)
                item[key] = self.collection(path)
            result.append(item)
        return result

    def snapshot(self):
        if not self.root:
            self.discover()
        system = self.get(self.paths['system'])
        result = {'collected_at': time.time(), 'system': system, 'errors': {}}
        for section in ('thermal', 'power', 'storage'):
            try:
                result[section] = self.storage() if section == 'storage' else self.get(self.paths[section])
            except IloError as exc:
                if exc.status in (401, 403):
                    raise
                result[section] = [] if section == 'storage' else {}
                result['errors'][section] = str(exc)
        result['collected_at'] = time.time()
        return result

    def logs(self):
        if not self.root:
            self.discover()
        entries = self.collection(self.paths['logs'], limit=2048)
        return sorted(entries, key=lambda e: (log_time(e), int(e.get('Id', 0)) if str(e.get('Id', '')).isdigit() else 0), reverse=True)[:15]


def issues(snapshot):
    result = {}

    def check(key, obj):
        if not present(obj):
            return
        value = health(obj)
        if value in ('Warning', 'Critical'):
            result[key] = value

    system = snapshot['system']
    check('Сервер', system)
    for key in ('MemorySummary', 'Memory', 'ProcessorSummary', 'Processors'):
        if isinstance(system.get(key), dict):
            check(key, system[key])
    for vendor in system.get('Oem', {}).values():
        if isinstance(vendor, dict):
            for key, value in (vendor.get('AggregateHealthStatus') or {}).items():
                if isinstance(value, dict):
                    check(key, value)
    if system.get('PowerState') == 'Off':
        result['Питание сервера'] = 'Off'
    for section, collection in (('thermal', 'Temperatures'), ('thermal', 'Fans'),
                                ('power', 'PowerSupplies'), ('power', 'Redundancy')):
        for index, obj in enumerate(snapshot.get(section, {}).get(collection, [])):
            if not present(obj):
                continue
            label = {'Temperatures': 'Температура', 'Fans': 'Вентилятор',
                     'PowerSupplies': 'БП', 'Redundancy': 'Резервирование'}[collection]
            key = label + ' ' + str(index + 1) + ': ' + str(first(obj, 'Name', 'FanName', 'MemberId', default=index))
            check(key, obj)
            if collection == 'Temperatures':
                reading = first(obj, 'ReadingCelsius', 'CurrentReading')
                if reading is not None:
                    for threshold, severity in (('UpperThresholdNonCritical', 'Warning'),
                                                ('UpperThresholdCritical', 'Critical'),
                                                ('UpperThresholdFatal', 'Critical')):
                        # iLO 4 uses zero for unsupported upper thresholds (e.g. CPU Fatal).
                        if isinstance(obj.get(threshold), (int, float)) and obj[threshold] > 0 and reading >= obj[threshold]:
                            result[key] = severity
    for vendor in system.get('Oem', {}).values():
        if isinstance(vendor, dict):
            for battery in vendor.get('Battery', []):
                condition = battery.get('Condition')
                if condition and condition.lower() not in ('ok', 'other', 'unknown'):
                    result['Батарея кэша ' + str(battery.get('Index', '?'))] = condition
    for index, controller in enumerate(snapshot.get('storage', [])):
        prefix = 'RAID ' + str(first(controller, 'Location', 'Id', default=index))
        check(prefix, controller)
        for collection in ('DiskDrives', 'LogicalDrives'):
            for number, disk in enumerate(controller.get(collection, [])):
                name = first(disk, 'Location', 'Id', 'Name', default=number)
                check(prefix + '/' + collection + '/' + str(name), disk)
    for section in snapshot.get('errors', {}):
        result['Нет данных: ' + section] = 'Unknown'
    return result
