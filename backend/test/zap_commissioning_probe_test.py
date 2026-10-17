import importlib.util
import unittest
import tempfile
import os
from pathlib import Path
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('commissioning_probe', Path(__file__).parents[1] / 'scripts/zap_commissioning_probe.py')
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class DriverTests(unittest.TestCase):
    def request(self):
        return ('GET http://fixture.test:18080/test/sqli?id=1&cs_commission=' + 'a' * 32 +
                '-0 HTTP/1.1\r\nHost: fixture.test:18080\r\nConnection: close\r\n\r\n')

    def test_exact_benign_request_uses_only_loopback_zap_api(self):
        with patch.object(probe, 'api', return_value={'sendRequest': []}) as api:
            probe.run('request', {'key': 'private', 'request': self.request()})
        api.assert_called_once_with('core/action/sendRequest', 'private',
                                    {'request': self.request(), 'followRedirects': 'false'})

    def test_injection_and_target_mismatch_fail_before_api(self):
        for request in (self.request().replace('Host: fixture.test', 'Host: another.test'),
                        self.request().replace('/test/sqli', '/health'),
                        self.request().replace('Connection: close', 'X-Injected: yes')):
            with patch.object(probe, 'api') as api, self.assertRaises(ValueError):
                probe.run('request', {'key': 'private', 'request': request})
            api.assert_not_called()

    def test_authentication_rejection_requires_valid_key_before_and_after(self):
        with patch.object(probe, 'api', side_effect=[{'version': '2.17.0'},
                         OSError(), OSError(), {'version': '2.17.0'}]):
            result = probe.run('authentication', {'key': 'private'})
        self.assertEqual(result['rejections'], [{'rejected': True}, {'rejected': True}])
        with patch.object(probe, 'api', side_effect=OSError()), self.assertRaises(OSError):
            probe.run('authentication', {'key': 'private'})

    def test_reuse_rotates_only_private_stopped_daemon_artifacts(self):
        with tempfile.TemporaryDirectory() as root:
            log, pid = str(Path(root) / 'log'), str(Path(root) / 'pid')
            for name in (log, pid):
                Path(name).write_text('private evidence')
                os.chmod(name, 0o600)
            marker = str(Path(root) / 'passive.exit')
            Path(marker).write_text('0\n')
            original = probe.run
            def dispatch(mode, args):
                return {'stopped': True} if mode == 'stopped' else original(mode, args)
            with patch.object(probe, 'LOG', log), patch.object(probe, 'PID', pid), patch.object(probe, 'PASSIVE_EXIT', marker), patch.object(probe, 'run', side_effect=dispatch):
                self.assertEqual(original('prepare-reuse', {}), {'prepared': True})
            for name in (log, pid):
                self.assertFalse(Path(name).exists())
                self.assertEqual(Path(name + '.passive').read_text(), 'private evidence')

    def test_reuse_rejects_live_daemon_symlink_or_insecure_artifact(self):
        for scenario in ('live', 'symlink', 'permissions', 'existing'):
            with tempfile.TemporaryDirectory() as root:
                log, pid = str(Path(root) / 'log'), str(Path(root) / 'pid')
                for name in (log, pid):
                    Path(name).write_text('evidence')
                    os.chmod(name, 0o600)
                if scenario == 'symlink':
                    os.unlink(log)
                    os.symlink(pid, log)
                elif scenario == 'permissions':
                    os.chmod(log, 0o644)
                elif scenario == 'existing':
                    Path(log + '.passive').write_text('earlier')
                marker = str(Path(root) / 'passive.exit')
                Path(marker).write_text('0\n')
                original = probe.run
                def dispatch(mode, args):
                    return {'stopped': scenario != 'live'} if mode == 'stopped' else original(mode, args)
                with patch.object(probe, 'LOG', log), patch.object(probe, 'PID', pid), patch.object(probe, 'PASSIVE_EXIT', marker), patch.object(probe, 'run', side_effect=dispatch), self.assertRaises((ValueError, FileExistsError)):
                    original('prepare-reuse', {})
                self.assertTrue(Path(log).exists())

    def test_configure_accepts_only_exact_preexisting_rate_rule(self):
        params = {'description': 'commissioning-fixture-only', 'enabled': 'true',
                  'matchRegex': 'false', 'matchString': 'fixture.test',
                  'requestsPerSecond': '2', 'groupBy': 'HOST'}
        for wrong in (False, True):
            calls = []
            def api(path, key, parameters=None):
                calls.append(path)
                if path == 'network/view/getRateLimitRules':
                    return {'getRateLimitRules': [{**params, 'requestsPerSecond': '3' if wrong else '2'}]}
                if path.startswith('ascan/action/'):
                    return {'Result': 'OK'}
                return {path.split('option')[-1]: '1'}
            with patch.object(probe, 'api', side_effect=api):
                if wrong:
                    with self.assertRaises(ValueError):
                        probe.run('configure', {'key': 'private', 'hostname': 'fixture.test'})
                else:
                    self.assertEqual(probe.run('configure', {'key': 'private', 'hostname': 'fixture.test'})['rateConfigured'], 2)
            self.assertNotIn('network/action/addRateLimitRule', calls)

    def test_no_scan_or_arbitrary_api_operation(self):
        for mode in ('scan', 'spider', 'accessUrl', 'runPlan'):
            with self.assertRaises(ValueError):
                probe.run(mode, {})


if __name__ == '__main__':
    unittest.main()
