"""Non-scanning diagnostic decisions, with injectable bounded local I/O.

This module never starts Docker, a daemon, or a job. The owned runtime wrapper
supplies API, health, incremental log, report and schema observations. Successful
diagnostics cannot update the production capability catalog.
"""
import hashlib
import json
import re
from html.parser import HTMLParser
from urllib.parse import urlsplit

RULES = ('40012', '40014', '40016', '40017', '40018', '40019', '40020')
MANDATORY = ('initialization', 'authentication', 'policy', 'rateConfiguration',
             'concurrency', 'status', 'cancellationContract', 'report', 'automation')
EXIT_CODES = {'PASS': 0, 'PARTIAL': 2, 'BLOCKED': 3, 'FAIL': 1}
LIMIT = 250000
TIMEOUT = 12
POLICY = 'cloudsentinel-diagnostic'
REPORT = '/zap/wrk/empty-diagnostic.json'
# Exact operations, not a substring denylist. In particular stop, scan, spider,
# runPlan, accessUrl, arbitrary OTHER operations and invented IDs are forbidden.
OPERATIONS = {
    'JSON/ascan/action/setOptionThreadPerHost/': {'Integer'},
    'JSON/ascan/action/setOptionHostPerScan/': {'Integer'},
    'JSON/ascan/view/optionThreadPerHost/': set(),
    'JSON/ascan/view/optionHostPerScan/': set(),
    'JSON/ascan/action/addScanPolicy/': {'scanPolicyName', 'alertThreshold', 'attackStrength'},
    'JSON/ascan/action/disableAllScanners/': {'scanPolicyName'},
    'JSON/ascan/action/enableScanners/': {'scanPolicyName', 'ids'},
    'JSON/ascan/action/setScannerAlertThreshold/': {'scanPolicyName', 'id', 'alertThreshold'},
    'JSON/ascan/action/setScannerAttackStrength/': {'scanPolicyName', 'id', 'attackStrength'},
    'JSON/ascan/view/scanners/': {'scanPolicyName'},
    'JSON/ascan/view/scans/': set(),
    'JSON/network/action/addRateLimitRule/': {'description', 'enabled', 'matchRegex', 'matchString', 'requestsPerSecond', 'groupBy'},
    'JSON/network/view/getRateLimitRules/': set(),
    'UI/ascan/action/stop/': set(),
    'UI/ascan/view/status/': set(),
    'JSON/reports/view/templates/': set(),
    'JSON/reports/action/generate/': {'title', 'template', 'reportDir', 'reportFileName'},
}


class DiagnosticError(ValueError):
    pass


def validate_operation(endpoint, parameters, auth):
    if endpoint not in OPERATIONS or set(parameters) != OPERATIONS[endpoint]:
        raise DiagnosticError('UNSUPPORTED_OPERATION_OR_PARAMETERS')
    if any(not isinstance(v, str) or len(v) > 160 or re.search(r'[\r\n\x00]', v) for v in parameters.values()):
        raise DiagnosticError('UNSAFE_PARAMETERS')
    if auth not in (True, False, 'wrong') or (auth is not True and endpoint != 'JSON/ascan/action/setOptionThreadPerHost/'):
        raise DiagnosticError('UNAUTHENTICATED_OPERATION_BLOCKED')
    fixed = {'Integer': '1', 'scanPolicyName': POLICY, 'ids': ','.join(RULES),
             'groupBy': 'HOST', 'matchString': '127.0.0.1', 'matchRegex': 'false',
             'enabled': 'true', 'requestsPerSecond': '2', 'description': 'diagnostic-loopback-only',
             'template': 'traditional-json', 'reportDir': '/zap/wrk',
             'reportFileName': 'empty-diagnostic', 'title': 'CloudSentinel empty diagnostic',
             'attackStrength': 'LOW'}
    if any(k in fixed and v != fixed[k] for k, v in parameters.items()):
        raise DiagnosticError('UNSAFE_PARAMETERS')
    if 'id' in parameters and parameters['id'] not in RULES:
        raise DiagnosticError('UNSUPPORTED_RULE')
    if 'alertThreshold' in parameters and parameters['alertThreshold'] != ('OFF' if endpoint.endswith('/addScanPolicy/') else 'LOW'):
        raise DiagnosticError('UNSAFE_THRESHOLD')


def usable(value):
    return (isinstance(value, dict) and value.get('processExitCode') == 0 and
            value.get('httpStatus') == 200 and value.get('truncated') is False and
            not value.get('errorType') and isinstance(value.get('json'), dict) and
            'code' not in value['json'])


def ok(value):
    return usable(value) and value['json'].get('Result') == 'OK'


def healthy(value):
    return isinstance(value, dict) and all(value.get(k) is True for k in ('running', 'identityMatches', 'loopbackOnly')) and value.get('version') == '2.17.0'


def log_delta(before, after):
    if not all(isinstance(v, dict) and v.get('exitCode') == 0 and v.get('truncated') is False for v in (before, after)):
        return None
    parts = []
    for key in ('stdout', 'stderr'):
        a, b = before.get(key), after.get(key)
        if not isinstance(a, str) or not isinstance(b, str) or not b.startswith(a) or len(b.encode()) > 1048576:
            return None
        parts.append(b[len(a):])
    return '\n'.join(parts)


def secure_rejection(response, delta, missing):
    if not isinstance(response, dict) or response.get('truncated') is not False:
        return False
    # Explicit authentication errors are distinct from a generic HTTP 403.
    if response.get('processExitCode') == 0 and response.get('httpStatus') in (400, 401, 403) and response.get('json', {}).get('code') == 'bad_api_key':
        return True
    token = 'null' if missing else 'invalid-diagnostic-key'
    pattern = r'\bAPI key incorrect or not supplied: ' + re.escape(token) + r' in request from 127\.0\.0\.1\s*$'
    return (response.get('errorType') == 'RemoteDisconnected' and response.get('processExitCode') == 1 and
            not response.get('httpStatus') and not response.get('body') and not response.get('json') and delta is not None and
            len(re.findall(pattern, delta, re.MULTILINE)) == 1)


def result(status, rule):
    return {'status': status, 'rule': rule}


def final_status(checks, cleanup, error=False):
    if error or cleanup.get('status') == 'FAIL':
        return 'FAIL'
    if any(checks[k]['status'] != 'PASS' for k in ('initialization', 'authentication')):
        return 'BLOCKED'
    values = [checks[k]['status'] for k in MANDATORY]
    if 'FAIL' in values:
        return 'FAIL'
    if 'NOT_RUN' in values or cleanup.get('status') != 'PASS':
        return 'BLOCKED'
    return 'PASS' if all(v == 'PASS' for v in values) else 'PARTIAL'


def empty_report(raw):
    if not isinstance(raw, str) or len(raw.encode()) > LIMIT:
        return False
    try:
        value = json.loads(raw)
    except (ValueError, TypeError):
        return False
    return isinstance(value, dict) and isinstance(value.get('site'), list) and value['site'] == []


def api_form(value, endpoint):
    if not isinstance(value, dict) or value.get('httpStatus') != 200 or value.get('processExitCode') != 0 or value.get('truncated') is not False:
        return False
    body = value.get('body', '')
    if not isinstance(body, str) or len(body.encode()) > LIMIT:
        return False
    component, kind, name = endpoint.strip('/').split('/')
    class Form(HTMLParser):
        def __init__(self):
            super().__init__(); self.forms=[]; self.current=None; self.invalid=False
        def handle_starttag(self, tag, attrs):
            keys=[k for k,_ in attrs]
            if len(keys)!=len(set(keys)):
                self.invalid=True
            attrs=dict(attrs)
            if tag=='form':
                if self.current is not None:self.invalid=True
                self.current={'attrs':attrs,'inputs':[]};self.forms.append(self.current)
            elif tag=='input' and self.current is not None:self.current['inputs'].append(attrs)
        def handle_endtag(self, tag):
            if tag=='form':
                if self.current is None:self.invalid=True
                self.current=None
    parsed=Form();parsed.feed(body);parsed.close()
    if parsed.invalid or parsed.current is not None or len(parsed.forms)!=1:
        return False
    form=parsed.forms[0]
    if form['attrs'].get('action')!='override' or form['attrs'].get('id')!='zapform':
        return False
    scan=[x for x in form['inputs'] if x.get('id')=='scanId' or x.get('name')=='scanId']
    submit=[x for x in form['inputs'] if x.get('type')=='submit']
    return (len(scan)==1 and scan[0].get('id')==scan[0].get('name')=='scanId' and
            not scan[0].get('value') and 'disabled' not in scan[0] and len(submit)==1 and 'formaction' not in submit[0] and
            all(submit[0].get(k)==v for k,v in {'zap-component':component,'zap-type':kind,'zap-name':name}.items()))


def validate_automation(plans, evidence):
    """Compare generated YAML with authentic bundled job templates, without ZAP.

    PyYAML must already be installed. Missing parser/schema evidence returns
    unverified; it never installs anything or substitutes a permissive parser.
    This is structural compatibility, not job execution/completion evidence.
    """
    try:
        import yaml
    except ImportError:
        return False
    class UniqueLoader(yaml.SafeLoader):
        pass
    def mapping(loader, node):
        keys = [loader.construct_object(k) for k, _ in node.value]
        if len(keys) != len(set(keys)):
            raise DiagnosticError('DUPLICATE_YAML_KEYS')
        return yaml.SafeLoader.construct_mapping(loader, node)
    UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, mapping)
    schemas = {}
    for item in evidence.get('schemas', []):
        if hashlib.sha256(item['text'].encode()).hexdigest() != item['sha256']:
            return False
        value = yaml.load(item['text'], Loader=UniqueLoader)
        if not isinstance(value, list) or len(value) != 1 or value[0]['type'] in schemas:
            return False
        schemas[value[0]['type']] = value[0]
    types = ['activeScan-policy', 'spider', 'activeScan', 'report']
    if set(schemas) != set(types) or len(plans) != 2:
        return False
    paths = set()
    for raw in plans:
        if not isinstance(raw, str) or len(raw.encode()) > 65536:
            return False
        plan = yaml.load(raw, Loader=UniqueLoader)
        if set(plan) != {'env', 'jobs'} or [j.get('type') for j in plan['jobs']] != types:
            return False
        context, = plan['env']['contexts']
        url, = context['urls']
        origin = urlsplit(url)
        if origin.scheme != 'http' or not re.fullmatch(r'[a-z0-9-]+\.test', origin.hostname or '') or origin.port != 18080 or origin.username or origin.password or origin.query or origin.fragment or origin.path not in ('/test/sqli', '/test/xss'):
            return False
        paths.add(origin.path)
        if context['includePaths'] != ['^' + re.sub(r'[^A-Za-z0-9_]', lambda m: '\\' + m[0], url) + '(?:/.*)?$'] or not context.get('excludePaths'):
            return False
        for job in plan['jobs']:
            schema = schemas[job['type']]
            if set(job) - set(schema) or set(job.get('parameters', {})) - set(schema.get('parameters', {})):
                return False
        policy, spider, active, report = plan['jobs']
        definition = policy.get('policyDefinition', {})
        rules = definition.get('rules', [])
        if policy.get('parameters') != {'name': 'cloudsentinel-active-fixture-v1'} or set(definition) != {'defaultStrength', 'defaultThreshold', 'rules'} or definition.get('defaultThreshold') != 'Off' or definition.get('defaultStrength') != 'Low' or len(rules) != len(RULES) or {str(r['id']) for r in rules} != set(RULES) or any(set(r) != {'id', 'strength', 'threshold'} or r['strength'] != 'Low' or r['threshold'] != 'Low' for r in rules):
            return False
        sp, ap, rp = (j['parameters'] for j in (spider, active, report))
        if sp.get('context') != context['name'] or ap.get('context') != context['name'] or sp.get('url') != url or ap.get('url') != url or ap.get('policy') != policy['parameters']['name']:
            return False
        if sp.get('maxDuration') != 2 or sp.get('threadCount') != 1 or sp.get('maxChildren') != 20 or ap.get('maxScanDurationInMins') != 10 or ap.get('threadPerHost') != 1 or ap.get('delayInMs') != 500:
            return False
        if rp != {'template': 'traditional-json', 'reportDir': '/zap/wrk', 'reportFile': 'report.json'}:
            return False
    return paths == {'/test/sqli', '/test/xss'}


def run_diagnostic(api, health, logs, read_report, automation, initialization, cleanup=None):
    """Replayable decisions; independent capabilities continue after local failure.

    API callback receives a mandatory timeout. It must retain bounded/redacted
    native evidence privately. Health/log callbacks collect genuine observations
    between the auth requests; old rejection logs cannot establish enforcement.
    """
    checks = {name: result('NOT_RUN', 'PREREQUISITE_NOT_VERIFIED') for name in MANDATORY}
    for name in ('rateEnforcement', 'completionBehavior', 'cancellationBehavior'):
        checks[name] = result('UNVERIFIED', 'REQUIRES_AUTHORIZED_CONTAINED_JOB')
    observations = []
    cleaned = result('NOT_RUN', 'OWNED_WRAPPER_CLEANUP_PENDING')
    unexpected = False

    def request(name, endpoint, parameters=None, auth=True):
        parameters = parameters or {}
        validate_operation(endpoint, parameters, auth)
        value = api(name, endpoint, parameters, auth, timeout=TIMEOUT)
        if not isinstance(value, dict):
            raise DiagnosticError('MALFORMED_API_OBSERVATION')
        if len(json.dumps(value).encode()) > LIMIT * 2 or value.get('truncated') is not False:
            raise DiagnosticError('INCOMPLETE_API_OBSERVATION')
        observations.append({'operation': name, 'endpoint': endpoint,
                             'httpStatus': value.get('httpStatus'), 'processExitCode': value.get('processExitCode'),
                             'errorCategory': value.get('errorType') if value.get('errorType') in ('RemoteDisconnected', 'TimeoutError', 'URLError') else None,
                             'zapError': value.get('json', {}).get('code') if value.get('json', {}).get('code') in ('bad_view', 'bad_action', 'bad_api_key', 'internal_error', 'missing_parameter', 'does_not_exist', 'illegal_parameter') else None})
        return value

    def action(name, operation, params):
        if not ok(request(name, 'JSON/ascan/action/' + operation + '/', params)):
            raise DiagnosticError('ACTION_NOT_CONFIRMED')

    def auth_check():
        if not healthy(health()):
            return False
        first = request('auth-valid-before', 'JSON/ascan/action/setOptionThreadPerHost/', {'Integer': '1'})
        if not ok(first):
            return False
        for missing, auth in ((True, False), (False, 'wrong')):
            before = logs()
            if not healthy(health()):
                return False
            rejected = request('auth-missing' if missing else 'auth-wrong', 'JSON/ascan/action/setOptionThreadPerHost/', {'Integer': '1'}, auth)
            delta = log_delta(before, logs())
            if not healthy(health()) or not secure_rejection(rejected, delta, missing):
                return False
        return ok(request('auth-valid-after', 'JSON/ascan/action/setOptionThreadPerHost/', {'Integer': '1'})) and healthy(health())

    def policy_check():
        action('policy-create', 'addScanPolicy', {'scanPolicyName': POLICY, 'alertThreshold': 'OFF', 'attackStrength': 'LOW'})
        action('policy-disable-all', 'disableAllScanners', {'scanPolicyName': POLICY})
        action('policy-enable', 'enableScanners', {'scanPolicyName': POLICY, 'ids': ','.join(RULES)})
        for rule in RULES:
            action('threshold-' + rule, 'setScannerAlertThreshold', {'scanPolicyName': POLICY, 'id': rule, 'alertThreshold': 'LOW'})
            action('strength-' + rule, 'setScannerAttackStrength', {'scanPolicyName': POLICY, 'id': rule, 'attackStrength': 'LOW'})
        selected = request('policy-readback', 'JSON/ascan/view/scanners/', {'scanPolicyName': POLICY})
        if not usable(selected) or not isinstance(selected['json'].get('scanners'), list):
            return False
        rows = selected['json']['scanners']
        ids = [str(x.get('id')) for x in rows]
        if any(not re.fullmatch(r'\d{1,8}', str(x.get('id'))) or str(x.get('enabled')).lower() not in ('true', 'false') for x in rows):
            return False
        active = [x for x in rows if str(x.get('enabled')).lower() == 'true']
        return (len(set(ids)) == len(ids) and {str(x.get('id')) for x in active} == set(RULES) and
                all(str(x.get('alertThreshold')).upper() == 'LOW' and str(x.get('attackStrength')).upper() == 'LOW' for x in active))

    def rate_check():
        params = {'description': 'diagnostic-loopback-only', 'enabled': 'true', 'matchRegex': 'false', 'matchString': '127.0.0.1', 'requestsPerSecond': '2', 'groupBy': 'HOST'}
        added = request('rate-set', 'JSON/network/action/addRateLimitRule/', params)
        read = request('rate-get', 'JSON/network/view/getRateLimitRules/')
        if not ok(added) or not usable(read):
            return False
        rows = read['json'].get('getRateLimitRules')
        if not isinstance(rows, list):
            return False
        matches = [x for x in rows if x.get('description') == params['description']]
        return len(matches) == 1 and all(str(matches[0].get(k)).lower() == v.lower() for k, v in params.items())

    def concurrency_check():
        values = []
        for name in ('ThreadPerHost', 'HostPerScan'):
            action('set-' + name, 'setOption' + name, {'Integer': '1'})
            read = request('get-' + name, 'JSON/ascan/view/option' + name + '/')
            # Genuine 2.17.0 responses omit the endpoint's option prefix.
            values.append(usable(read) and set(read['json']) == {name} and str(read['json'][name]) == '1')
        return all(values)

    def status_check():
        read = request('status-list', 'JSON/ascan/view/scans/')
        return usable(read) and read['json'].get('scans') == []

    def cancellation_check():
        stop = request('stop-description', 'UI/ascan/action/stop/')
        status = request('status-description', 'UI/ascan/view/status/')
        return api_form(stop, '/ascan/action/stop/') and api_form(status, '/ascan/view/status/')

    def report_check():
        templates = request('report-templates', 'JSON/reports/view/templates/')
        if not usable(templates) or not isinstance(templates['json'].get('templates'), list) or 'traditional-json' not in templates['json']['templates']:
            return False
        generated = request('report-generate', 'JSON/reports/action/generate/', {'title': 'CloudSentinel empty diagnostic', 'template': 'traditional-json', 'reportDir': '/zap/wrk', 'reportFileName': 'empty-diagnostic'})
        # Reports 0.46 returns {generate: <path>}, not {Result: OK}.
        return usable(generated) and generated['json'].get('generate') == REPORT and empty_report(read_report(REPORT, timeout=TIMEOUT))

    try:
        checks['initialization'] = result('PASS' if initialization is True else 'FAIL', 'GENUINE_INITIALIZATION_GATE')
        if initialization is True:
            try:
                checks['authentication'] = result('PASS' if auth_check() else 'FAIL', 'VALID_KEY_HEALTH_AND_CORRELATED_REJECTIONS')
            except Exception:
                checks['authentication'] = result('FAIL', 'AUTH_OBSERVATION_FAILED')
            if checks['authentication']['status'] == 'PASS':
                for name, callback in (('policy', policy_check), ('rateConfiguration', rate_check), ('concurrency', concurrency_check), ('status', status_check), ('cancellationContract', cancellation_check), ('report', report_check)):
                    try:
                        passed = callback()
                        checks[name] = result('PASS' if passed else 'FAIL', 'OBSERVED_CONFIGURATION_READBACK' if name != 'cancellationContract' else 'DESCRIPTION_ONLY_NO_JOB_CANCELLATION')
                    except Exception:
                        checks[name] = result('FAIL', 'OPERATION_FAILED_OR_UNSUPPORTED')
                try:
                    checks['automation'] = result('PASS' if automation() is True else 'UNVERIFIED', 'OFFLINE_AUTHENTIC_SCHEMA_COMPARISON_NO_JOB_EXECUTION')
                except Exception:
                    checks['automation'] = result('FAIL', 'SCHEMA_VALIDATION_FAILED')
    except Exception:
        unexpected = True
    finally:
        if cleanup is not None:
            try:
                cleaned = result('PASS' if cleanup() is True else 'FAIL', 'OWNERSHIP_VERIFIED_CLEANUP')
            except Exception:
                cleaned = result('FAIL', 'CLEANUP_FAILED')
    status = final_status(checks, cleaned, unexpected)
    return {'status': status, 'exitCode': EXIT_CODES[status], 'diagnosticOnly': True,
            'activeExecutionReady': False, 'checks': checks, 'cleanup': cleaned, 'operations': observations}
