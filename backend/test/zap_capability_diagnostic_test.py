import copy
import ast
import io
import contextlib
import hashlib
import types
import urllib.parse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).parents[2]
sys.path.insert(0, str(ROOT / 'backend/scripts'))
import zap_capability_diagnostic as diagnostic


def response(value, status=200):
    return {'processExitCode': 0, 'httpStatus': status, 'truncated': False,
            'json': value, 'body': json.dumps(value)}


class Replay:
    """Mocked unexecuted capabilities; genuine auth fixture stays identifiable."""
    def __init__(self):
        self.genuine = json.loads((ROOT / 'backend/test/fixtures/zap-auth-rejection-eumqv32d.json').read_text())
        self.calls = []
        self.overrides = {}
        self.lines = []
        self.cleaned = 0
        self.health_value = {'running': True, 'identityMatches': True, 'loopbackOnly': True, 'version': '2.17.0'}
        self.report = '{"@version":"2.17.0","site":[]}'
        self.automation = True
        self.cleanup_value = True

    def api(self, name, endpoint, params, auth, timeout):
        diagnostic.validate_operation(endpoint, params, auth)
        assert timeout == 12
        self.calls.append((name, endpoint, copy.deepcopy(params), auth))
        if name in self.overrides:
            value = self.overrides[name]
            if isinstance(value, Exception):
                raise value
            return copy.deepcopy(value)
        if auth is not True:
            missing = auth is False
            self.lines.append(self.genuine['logs']['stdout'].splitlines()[0 if missing else 1])
            value = copy.deepcopy(self.genuine['missing' if missing else 'wrong'])
            # The native wrapper now propagates run().truncated for every result,
            # including the genuine error JSON that previously omitted the field.
            value['truncated'] = False
            return value
        if endpoint.endswith('/scanners/'):
            return response({'scanners': [{'id': r, 'enabled': 'true', 'alertThreshold': 'LOW', 'attackStrength': 'LOW'} for r in diagnostic.RULES] + [{'id': '90026', 'enabled': 'false'}]})
        if endpoint.endswith('/getRateLimitRules/'):
            return response({'getRateLimitRules': [{'description': 'diagnostic-loopback-only', 'enabled': True, 'matchRegex': False, 'matchString': '127.0.0.1', 'requestsPerSecond': 2, 'groupBy': 'HOST'}]})
        if '/view/option' in endpoint:
            return response({endpoint.split('/')[-2].removeprefix('option'): '1'})
        if endpoint.endswith('/scans/'):
            return response({'scans': []})
        if endpoint.startswith('UI/'):
            return {'httpStatus': 200, 'processExitCode': 0, 'truncated': False,
                    'body': '<form id="zapform" action="override"><input id="scanId" name="scanId"><input type="submit" zap-component="ascan" zap-type="' + endpoint.split('/')[2] + '" zap-name="' + endpoint.split('/')[3] + '"></form>'}
        if endpoint.endswith('/templates/'):
            return response({'templates': ['traditional-json']})
        if endpoint.endswith('/generate/'):
            return response({'generate': diagnostic.REPORT})
        return copy.deepcopy(self.genuine['valid'])

    def logs(self):
        return {'exitCode': 0, 'truncated': False, 'stdout': '\n'.join(self.lines), 'stderr': ''}

    def cleanup(self):
        self.cleaned += 1
        return self.cleanup_value

    def run(self, initialized=True):
        return diagnostic.run_diagnostic(self.api, lambda: self.health_value, self.logs,
                                         lambda p, timeout: self.report,
                                         lambda: self.automation, initialized, self.cleanup)


class DiagnosticTest(unittest.TestCase):
    def test_complete_saved_native_exchange_passes_offline_without_rewriting_history(self):
        native=json.loads((ROOT/'backend/test/fixtures/zap-capabilities-2aspu6vu.json').read_text())
        self.assertEqual((native['historicalRunnerStatus'],native['historicalRunnerExitCode']),('FAIL',1))
        reached=[];phase=[0]
        raw=native['finalLogs']
        def api(name,endpoint,params,auth,timeout):
            value=copy.deepcopy(native['responses'][name])
            self.assertEqual((endpoint,params),(value['endpoint'],value['parameters']))
            self.assertEqual(timeout,12);reached.append(name)
            if name=='auth-missing':phase[0]=1
            if name=='auth-wrong':phase[0]=2
            return value
        def logs():
            # Chronological prefixes of genuine retained log lines, not newly
            # observed snapshots. Only the offline replay reconstructs timing.
            lines=raw['stdout'].splitlines(keepends=True);indices=[i for i,l in enumerate(lines) if 'API key incorrect or not supplied:' in l]
            end=indices[phase[0]] if phase[0]<2 else len(lines)
            return {**raw,'stdout':''.join(lines[:end])}
        cleaned=[]
        got=diagnostic.run_diagnostic(api,lambda:{'running':True,'identityMatches':True,'loopbackOnly':not native['listeners'].get('errorCode'),'version':native['daemonVersion']},logs,lambda p,timeout:native['reportText'],lambda:native['observedChecks']['automation']['status']=='PASS',native['initialization']=='PASS',lambda:cleaned.append(True) or True)
        self.assertEqual((got['status'],got['exitCode']),('PASS',0))
        self.assertEqual(set(reached),set(native['responses']))
        self.assertEqual(cleaned,[True]);self.assertFalse(got['activeExecutionReady'])
        self.assertEqual(native['productionParser']['findingsCount'],0)
        self.assertEqual(native['historicalRunnerStatus'],'FAIL')

    def test_genuine_ui_override_form_is_discovery_only_and_rejects_unsafe_variants(self):
        native=json.loads((ROOT/'backend/test/fixtures/zap-capabilities-2aspu6vu.json').read_text())
        for name,endpoint in [('stop-description','/ascan/action/stop/'),('status-description','/ascan/view/status/')]:
            value=native['responses'][name]
            self.assertTrue(diagnostic.api_form(value,endpoint))
            for before,after in [('action="override"','action="https://external.invalid/"'),('zap-component="ascan"','zap-component="spider"'),('zap-name="stop"','zap-name="scan"'),('type="submit"','type="submit" formaction="https://external.invalid/"'),('id="scanId" name="scanId"','id="other" name="other"'),('</form>',''),('name="scanId"','name="scanId" disabled'),('name="scanId"','name="scanId" name="duplicate"')]:
                altered={**value,'body':value['body'].replace(before,after)}
                if altered['body']!=value['body']:self.assertFalse(diagnostic.api_form(altered,endpoint),(name,before))
        self.assertEqual(Replay().run()['checks']['cancellationBehavior']['status'],'UNVERIFIED')

    def test_native_concurrency_keys_and_unsupported_prefixes(self):
        native=json.loads((ROOT/'backend/test/fixtures/zap-capabilities-2aspu6vu.json').read_text())
        r=Replay()
        for name in ('ThreadPerHost','HostPerScan'):r.overrides['get-'+name]=native['responses']['get-'+name]
        self.assertEqual(r.run()['checks']['concurrency']['status'],'PASS')
        for name in ('ThreadPerHost','HostPerScan'):
            r=Replay();r.overrides['get-'+name]=response({'option'+name:'1'})
            self.assertEqual(r.run()['checks']['concurrency']['status'],'FAIL')
            r=Replay();r.overrides['get-'+name]=response({name:'1','option'+name:'2'})
            self.assertEqual(r.run()['checks']['concurrency']['status'],'FAIL')

    def test_complete_non_scanning_replay_with_genuine_auth_closure(self):
        replay = Replay()
        got = replay.run()
        self.assertEqual((got['status'], got['exitCode'], replay.cleaned), ('PASS', 0, 1))
        self.assertTrue(all(got['checks'][k]['status'] == 'PASS' for k in diagnostic.MANDATORY))
        self.assertFalse(got['activeExecutionReady'])
        self.assertEqual(got['checks']['cancellationBehavior']['status'], 'UNVERIFIED')
        self.assertEqual(got['checks']['completionBehavior']['status'], 'UNVERIFIED')
        self.assertEqual(got['checks']['rateEnforcement']['status'], 'UNVERIFIED')
        self.assertEqual(len([x for x in replay.calls if x[1].endswith('/setScannerAlertThreshold/')]), 7)
        self.assertEqual(len([x for x in replay.calls if x[1].endswith('/setScannerAttackStrength/')]), 7)
        self.assertFalse(any('/automation/view/plans/' in x[1] for x in replay.calls))

    def test_explicit_auth_errors_not_just_http_403(self):
        for status in (400, 401, 403):
            r = Replay()
            r.overrides.update({n: response({'code': 'bad_api_key'}, status) for n in ('auth-missing', 'auth-wrong')})
            self.assertEqual(r.run()['checks']['authentication']['status'], 'PASS')
        for value in (response({'message': 'Forbidden'}, 403), response({'Result': 'OK'}), {'errorType': 'TimeoutError', 'processExitCode': 1, 'truncated': False}):
            r = Replay(); r.overrides['auth-missing'] = value
            self.assertEqual(r.run()['status'], 'BLOCKED')
            self.assertEqual(r.cleaned, 1)

    def test_connection_failure_requires_fresh_exact_rejection_log_and_health(self):
        for category in ('TimeoutError', 'URLError', 'ConnectionRefusedError', 'RemoteDisconnected'):
            r = Replay()
            r.overrides['auth-missing'] = {'errorType': category, 'processExitCode': 1, 'truncated': False}
            self.assertEqual(r.run()['checks']['authentication']['status'], 'FAIL')
        for field, value in (('running', False), ('identityMatches', False), ('loopbackOnly', False), ('version', '2.16.0')):
            r = Replay(); r.health_value[field] = value
            self.assertEqual(r.run()['status'], 'BLOCKED')
        for change in ('wrong_key', 'remote_peer', 'duplicate', 'truncated', 'old'):
            r = Replay(); original = r.logs
            if change == 'wrong_key': r.genuine['logs']['stdout'] = r.genuine['logs']['stdout'].replace(': null ', ': wrong-value ')
            if change == 'remote_peer': r.genuine['logs']['stdout'] = r.genuine['logs']['stdout'].replace('127.0.0.1', '172.30.0.2')
            if change == 'duplicate':
                r.logs = lambda: {**original(), 'stdout': original()['stdout'] + '\n' + original()['stdout']}
            if change == 'truncated': r.logs = lambda: {**original(), 'truncated': True}
            if change == 'old': r.logs = lambda: {**original(), 'stdout': r.genuine['logs']['stdout']}
            self.assertEqual(r.run()['status'], 'BLOCKED', change)

    def test_each_operation_failure_is_recorded_and_cleanup_always_runs(self):
        baseline = Replay(); baseline.run()
        for name, _, _, _ in baseline.calls:
            with self.subTest(operation=name):
                r = Replay(); r.overrides[name] = response({'code': 'internal_error'}, 500)
                got = r.run()
                self.assertNotEqual(got['exitCode'], 0)
                self.assertEqual(r.cleaned, 1)
                if not name.startswith('auth-'):
                    self.assertTrue(any(x[0] == 'report-templates' for x in r.calls))
                    self.assertNotIn('NOT_RUN', [got['checks'][k]['status'] for k in diagnostic.MANDATORY])

    def test_local_unsupported_or_timeout_does_not_hide_other_capabilities(self):
        for error in (response({'code': 'bad_view'}, 400), response({'code': 'missing_parameter'}, 400), TimeoutError('secret token must not appear')):
            r = Replay(); r.overrides['rate-set'] = error
            got = r.run()
            self.assertEqual(got['checks']['rateConfiguration']['status'], 'FAIL')
            self.assertEqual(got['checks']['report']['status'], 'PASS')
            self.assertEqual(got['checks']['automation']['status'], 'PASS')
            self.assertNotIn('secret token', json.dumps(got))
            self.assertEqual(got['status'], 'FAIL')

    def test_wrong_policy_duplicate_ids_or_extra_enabled_rule_fails(self):
        for mutation in ('extra', 'missing', 'duplicate', 'threshold', 'strength'):
            r = Replay(); rows = r.api('ignored', 'JSON/ascan/view/scanners/', {'scanPolicyName': diagnostic.POLICY}, True, 12)['json']['scanners']
            if mutation == 'extra': rows[-1]['enabled'] = 'true'
            if mutation == 'missing': rows.pop(0)
            if mutation == 'duplicate': rows.append(copy.deepcopy(rows[0]))
            if mutation == 'threshold': rows[0]['alertThreshold'] = 'OFF'
            if mutation == 'strength': rows[0]['attackStrength'] = 'HIGH'
            r.overrides['policy-readback'] = response({'scanners': rows})
            self.assertEqual(r.run()['checks']['policy']['status'], 'FAIL')

    def test_rate_and_concurrency_need_exact_configuration_readback(self):
        for name, payload in (('rate-get', {'getRateLimitRules': []}), ('rate-get', {'rules': [{'description': 'diagnostic-loopback-only'}]}), ('get-ThreadPerHost', {'optionThreadPerHost': '1'}), ('get-HostPerScan', {'HostPerScan': '2'})):
            r = Replay(); r.overrides[name] = response(payload)
            self.assertEqual(r.run()['status'], 'FAIL')

    def test_report_uses_generate_path_and_actual_empty_json_schema(self):
        for raw in ('{}', '{"site":null}', '{"site":{}}', '{"site":[{}]}', 'truncated', 'x' * 250001):
            r = Replay(); r.report = raw
            self.assertEqual(r.run()['checks']['report']['status'], 'FAIL')
        for name, value in (('report-templates', {'templates': []}), ('report-generate', {'Result': 'OK'}), ('report-generate', {'generate': '/tmp/untrusted.json'})):
            r = Replay(); r.overrides[name] = response(value)
            self.assertEqual(r.run()['checks']['report']['status'], 'FAIL')

    def test_status_and_cancellation_contract_cannot_invent_or_start_job(self):
        r = Replay(); r.overrides['status-list'] = response({'scans': [{'id': '1'}]})
        self.assertEqual(r.run()['checks']['status']['status'], 'FAIL')
        r = Replay(); r.overrides['stop-description'] = {'processExitCode': 0, 'httpStatus': 200, 'truncated': False, 'body': 'scanId'}
        self.assertEqual(r.run()['checks']['cancellationContract']['status'], 'FAIL')
        for endpoint in ('JSON/ascan/action/scan/', 'JSON/ascan/action/stop/', 'JSON/automation/action/runPlan/', 'JSON/spider/action/scan/', 'OTHER/core/other/jsonreport/', 'JSON/core/action/accessUrl/'):
            with self.assertRaises(diagnostic.DiagnosticError): diagnostic.validate_operation(endpoint, {}, True)
        with self.assertRaises(diagnostic.DiagnosticError):
            diagnostic.validate_operation('JSON/ascan/action/setScannerAlertThreshold/', {'scanPolicyName': diagnostic.POLICY, 'ids': '40018', 'alertThreshold': 'LOW'}, True)

    def test_not_run_unverified_failure_and_exit_statuses_are_distinct(self):
        r = Replay(); got = r.run(False)
        self.assertEqual((got['status'], got['exitCode']), ('BLOCKED', 3))
        self.assertEqual(got['checks']['policy']['status'], 'NOT_RUN')
        self.assertEqual(got['checks']['completionBehavior']['status'], 'UNVERIFIED')
        r = Replay(); r.automation = False
        self.assertEqual((r.run()['status'], r.run()['exitCode']), ('PARTIAL', 2))
        r = Replay(); r.cleanup_value = False
        got = r.run(); self.assertEqual((got['status'], got['exitCode']), ('FAIL', 1))
        r = Replay(); r.overrides['policy-create'] = response({'code': 'internal_error'}, 500)
        self.assertEqual(r.run()['status'], 'FAIL')
        self.assertEqual(r.cleaned, 1)

    def test_oversized_malformed_observations_and_cleanup_exception(self):
        for value in (None, {'truncated': True}, {'body': 'x' * 500001, 'truncated': False}):
            r = Replay(); r.overrides['rate-get'] = value
            self.assertEqual(r.run()['checks']['rateConfiguration']['status'], 'FAIL')
        r = Replay()
        def broken_cleanup(): raise RuntimeError('cleanup secret')
        r.cleanup = broken_cleanup
        self.assertEqual(r.run()['status'], 'FAIL')

    def test_authentic_af_schema_and_real_plan_generator_offline(self):
        evidence = json.loads((ROOT / 'backend/config/zap-diagnostic-contracts.json').read_text())
        code = "const m=require('./backend/services/dastActiveScanner');console.log(JSON.stringify(['/test/sqli','/test/xss'].map(p=>m.automationPlan('http://diagnostic-fixture.test:18080'+p))))"
        run = subprocess.run(['node', '-e', code], cwd=ROOT, capture_output=True, text=True, timeout=12, env={**os.environ, 'DAST_ACTIVE_ENABLED': 'false'})
        self.assertEqual(run.returncode, 0, run.stderr)
        plans = json.loads(run.stdout)
        self.assertTrue(diagnostic.validate_automation(plans, evidence))
        for before, after in (('    policyDefinition:', '      policyDefinition:'), ('delayInMs: 500', 'delayInMs: 0'), ('threadPerHost: 1', 'unsupportedParameter: 1'), ('id: 40018', 'id: 90026'), ('http://diagnostic-fixture.test', 'http://external.example')):
            self.assertFalse(diagnostic.validate_automation([p.replace(before, after) for p in plans], evidence))
        altered = copy.deepcopy(evidence); altered['schemas'][0]['text'] += 'changed'
        self.assertFalse(diagnostic.validate_automation(plans, altered))

    def test_persistent_wrapper_is_inert_on_import_and_rejects_unowned_preflight(self):
        spec = importlib.util.spec_from_file_location('owned_wrapper', ROOT / 'backend/scripts/zap_runtime_diagnostic.py')
        module = importlib.util.module_from_spec(spec)
        with patch('subprocess.run', side_effect=AssertionError('No execution allowed')):
            spec.loader.exec_module(module)
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory); path.chmod(0o755)
                with self.assertRaisesRegex(ValueError, 'PRIVATE_EVIDENCE_DIRECTORY_REQUIRED'): module.main(path)

    def test_every_embedded_native_python_payload_compiles_before_runtime(self):
        source = ROOT / 'backend/scripts/zap_runtime_diagnostic.py'
        spec = importlib.util.spec_from_file_location('payload_wrapper', source)
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        found = {}
        for node in ast.walk(ast.parse(source.read_text())):
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id in ('code', 'collect', 'profile_detail_code') and node.value.value.startswith('import '):
                        raw = node.value.value
                        compiled = module.native_python(raw) if '\n' in raw else raw
                        compile(compiled, target.id, 'exec')
                        found.setdefault(target.id, []).append(compiled)
        self.assertEqual(set(found), {'code', 'collect', 'profile_detail_code'})
        self.assertTrue(any('timeout=8' in code for code in found['code']))

    def test_optimized_python_cannot_disable_runtime_security_assertions(self):
        source = ROOT / 'backend/scripts/zap_runtime_diagnostic.py'
        namespace = {'__file__': str(source), '__name__': 'offline_optimized_wrapper'}
        with patch('subprocess.run', side_effect=AssertionError('No execution allowed')):
            exec(compile(source.read_text(), str(source), 'exec', optimize=1), namespace)
            with self.assertRaisesRegex(ValueError, 'OPTIMIZED_PYTHON_NOT_ALLOWED'):
                namespace['main'](Path('/unused'))

    def test_native_api_transport_redaction_and_closure_offline(self):
        import urllib.request
        import urllib.error
        source = ROOT / 'backend/scripts/zap_runtime_diagnostic.py'
        spec = importlib.util.spec_from_file_location('transport_wrapper', source)
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        raw = next(n.value.value for n in ast.walk(ast.parse(source.read_text())) if isinstance(n, ast.Assign) and isinstance(n.value, ast.Constant) and isinstance(n.value.value, str) and 'urllib.request.urlopen' in n.value.value)
        code = module.native_python(raw)
        class Reply:
            status = 200
            def read(self, count):
                self.count = count
                return b'{"Result":"OK","testSecret":"private-api-key"}'
        for auth in ('true', 'false', 'wrong'):
            output = io.StringIO(); reply = Reply()
            with patch('sys.argv', ['probe', 'JSON/ascan/action/setOptionThreadPerHost/', 'Integer=1', auth]), patch('builtins.open', return_value=io.StringIO('private-api-key')), patch('urllib.request.urlopen', return_value=reply) as request, contextlib.redirect_stdout(output):
                exec(compile(code, 'native-transport', 'exec'), {})
            self.assertNotIn('private-api-key', output.getvalue())
            url = request.call_args.args[0]
            self.assertTrue(url.startswith('http://127.0.0.1:8090/JSON/ascan/action/setOptionThreadPerHost/'))
            self.assertEqual(request.call_args.kwargs['timeout'], 8)
            self.assertEqual('apikey=' in url, auth != 'false')
        import http.client
        output = io.StringIO()
        with patch('sys.argv', ['probe', 'JSON/ascan/action/setOptionThreadPerHost/', 'Integer=1', 'false']), patch('builtins.open', return_value=io.StringIO('private-api-key')), patch('urllib.request.urlopen', side_effect=http.client.RemoteDisconnected()), contextlib.redirect_stdout(output), self.assertRaises(SystemExit) as raised:
            exec(compile(code, 'native-transport', 'exec'), {})
        self.assertEqual(raised.exception.code, 1)
        self.assertEqual(json.loads(output.getvalue()), {'errorType': 'RemoteDisconnected'})

    def test_complete_persistent_wrapper_replay_without_any_real_process_or_docker(self):
        import tarfile
        from unittest.mock import MagicMock
        import builtins
        source = ROOT / 'backend/scripts/zap_runtime_diagnostic.py'
        spec = importlib.util.spec_from_file_location('full_wrapper', source)
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        genuine = json.loads((ROOT / 'backend/test/fixtures/zap-runtime-init-eumqv32d.json').read_text())
        contracts = json.loads((ROOT / 'backend/config/zap-diagnostic-contracts.json').read_text())
        real_open, real_hash = builtins.open, hashlib.sha256
        config = {'config': {'User': 'zap'}, 'rootfs': {'diff_ids': []}}
        raw_config = json.dumps(config).encode()
        class ArchiveHash:
            def update(self, data): self.data = data
            def hexdigest(self): return contracts['sourceImageArchiveSha256']
        def fake_hash(data=None, **kwargs):
            if data is None: return ArchiveHash()
            if data == raw_config: return types.SimpleNamespace(hexdigest=lambda: contracts['expectedImageConfigId'].split(':')[1])
            return real_hash(data, **kwargs)
        def fake_open(path, mode='r', *args, **kwargs):
            if str(path) == '/tmp/cs-zap-offline-cwa6clxp/assembly-1.tar': return io.BytesIO(b'MOCK_ARCHIVE_NOT_REAL_IMAGE_VERIFICATION')
            return real_open(path, mode, *args, **kwargs)
        archive = MagicMock()
        archive.__enter__.return_value = archive
        archive.extractfile.side_effect = lambda name: io.BytesIO(json.dumps([{'Config': 'config.json'}]).encode() if name == 'manifest.json' else raw_config)
        # Success plus failures before and throughout capability execution.
        for failure in (None, 'import', 'inspection', 'profile', 'policy', 'rate', 'report', 'cleanup'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                path = Path(directory); path.chmod(0o700)
                owner = 'cs-zap-offline-replay'
                native = copy.deepcopy(genuine['inspection']); cid = native['Id']; image = native['Image']
                native['Name'] = '/' + owner; native['Config']['Hostname'] = owner
                native['Config']['Labels']['cloudsentinel.owner'] = owner
                native['HostConfig']['ExtraHosts'] = [owner + ':127.0.0.1']
                pods = json.dumps({'items': [{'metadata': {'uid': 'mock-pod'}, 'status': {'containerStatuses': [{'name': 'mock', 'ready': True, 'restartCount': 0}]}}]})
                baseline = {'containers': {'stdout': 'mock-original-containers\n'}, 'networks': {'stdout': 'mock-original-networks\n'}, 'project17': {'stdout': pods}}
                (path / 'before.json').write_text(json.dumps(baseline))
                (path / 'preflight.json').write_text(json.dumps({'status': 'PASS', 'owner': owner}))
                replay = Replay(); calls = []; state = {'loaded': False, 'created': False}
                def process(args, **kwargs):
                    self.assertGreater(kwargs.get('timeout', 0), 0)
                    calls.append(args)
                    out, code, err = '', 0, ''
                    if args[:3] == ['docker', 'image', 'load']:
                        if failure == 'import': code = 1
                        else: state['loaded'] = True
                    elif args[:3] == ['docker', 'image', 'inspect']:
                        if state['loaded']: out = json.dumps([{'Id': image, 'Config': config['config'], 'RootFS': {'Layers': []}, 'Architecture': 'amd64', 'Os': 'linux', 'Descriptor': {'digest': image}, 'RepoTags': ['cloudsentinel/zap-offline:verified-closure']}])
                        else: code, err = 1, 'No such image'
                    elif args[:3] == ['docker', 'image', 'rm']: state['loaded'] = False
                    elif args[:2] == ['docker', 'run']: state['created'] = True; out = cid
                    elif args[:2] == ['docker', 'inspect']:
                        seen = copy.deepcopy(native)
                        if failure == 'inspection': seen['HostConfig']['ReadonlyRootfs'] = False
                        out = json.dumps([seen])
                    elif args[:3] == ['docker', 'container', 'inspect']: code = 1
                    elif args[:2] == ['docker', 'rm']:
                        if failure == 'cleanup': code = 1
                        else: state['created'] = False
                    elif args[:2] == ['docker', 'logs']:
                        out = 'Extensions loaded\nZAP is now listening on 127.0.0.1:8090\n' + replay.logs()['stdout']
                    elif args[:2] == ['docker', 'exec']:
                        payload = args[5]
                        if args[-3].startswith(('JSON/', 'UI/')):
                            endpoint, query, auth = args[-3:]; params = dict(urllib.parse.parse_qsl(query))
                            if endpoint == 'JSON/core/view/version/': value = response({'version': '2.17.0'})
                            elif endpoint == 'JSON/autoupdate/view/installedAddons/': value = response({'installedAddons': genuine['addons']})
                            elif endpoint == 'JSON/ascan/view/scanners/' and not params: value = response({'scanners': [{'id': r} for r in diagnostic.RULES]})
                            elif failure == 'policy' and endpoint.endswith('/addScanPolicy/'): value = response({'code': 'internal_error'}, 500)
                            elif failure == 'rate' and endpoint.endswith('/getRateLimitRules/'): value = response({'code': 'bad_view'}, 400)
                            else: value = replay.api('mocked-' + endpoint, endpoint, params, {'true': True, 'false': False, 'wrong': 'wrong'}[auth], 12)
                            code = value.get('processExitCode', 0)
                            out = json.dumps({k: v for k, v in value.items() if k in ('httpStatus', 'body', 'truncated', 'errorType')})
                        elif 'xml.etree' in payload: out = json.dumps(genuine['storagePolicy'])
                        elif 'collect_writable_observations' in payload: out = json.dumps(genuine['writable'])
                        elif 'extension-preferences.json' in payload:
                            out = json.dumps({} if failure == 'profile' else genuine['profile'])
                        elif args[-1] == diagnostic.REPORT: out = '{}' if failure == 'report' else replay.report
                        else: self.fail('Unexpected native payload')
                    elif args[:3] == ['docker', 'ps', '-a']:
                        if '--filter' in args: out = cid if state['created'] else ''
                        elif args[-1] == '{{.ID}}': out = baseline['containers']['stdout'] + (cid if state['created'] else '')
                    elif args[:3] == ['docker', 'network', 'ls']: out = baseline['networks']['stdout']
                    elif args[:2] == ['docker', 'info']: out = '29.7.2'
                    elif args[:3] == ['docker', 'image', 'ls']: pass
                    elif args[0] == 'kubectl': out = pods
                    elif args[0] in ('curl', 'pg_isready', 'minikube'): out = '{}'
                    elif args[0] == 'node':
                        # Real generator is separately tested; this transport is fully mocked.
                        out = '[]'
                    else: self.fail('Unexpected process invocation')
                    return types.SimpleNamespace(returncode=code, stdout=out, stderr=err)
                with patch('builtins.open', side_effect=fake_open), patch('hashlib.sha256', side_effect=fake_hash), patch('tarfile.open', return_value=archive), patch('subprocess.run', side_effect=process), patch('zap_capability_diagnostic.validate_automation', return_value=True), contextlib.redirect_stdout(io.StringIO()):
                    exit_code = module.main(path)
                report = json.loads((path / 'result.json').read_text())
                self.assertEqual(exit_code, 0 if failure is None else diagnostic.EXIT_CODES[report['status']])
                self.assertEqual(report['status'], 'PASS' if failure is None else ('BLOCKED' if failure in ('import', 'inspection', 'profile') else 'FAIL'))
                self.assertEqual(len([c for c in calls if c[:3] == ['docker', 'image', 'load']]), 1)
                self.assertLessEqual(len([c for c in calls if c[:2] == ['docker', 'run']]), 1)
                if failure != 'import': self.assertTrue(any(c[:2] == ['docker', 'rm'] for c in calls))
                self.assertEqual((path / 'result.json').stat().st_mode & 0o777, 0o600)


if __name__ == '__main__':
    unittest.main()
