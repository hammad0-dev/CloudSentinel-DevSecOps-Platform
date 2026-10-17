import copy
import hashlib
import json
import os
import stat
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import io
import types
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parents[1] / 'scripts'))
from zap_writable_runtime import listener_observation, profile_seed_arguments, jvm_seed_arguments, directory_observation, collect_writable_observations

HEADER = '  sl  local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n'


def table(address=None, port='1F9A', state='0A'):
    if address is None:
        return HEADER
    remote = '0' * len(address)
    return HEADER + f'0: {address}:{port} {remote}:0000 {state} 00000000:00000000 00:00000000 00000000 1000 0 42\n'


class WritableRuntimeTest(unittest.TestCase):
    def setUp(self):
        self.config = json.loads((Path(__file__).parents[1] / 'config' / 'zap-writable-paths.json').read_text())

    def test_ipv4_loopback(self):
        result = listener_observation(table('0100007F'), HEADER)
        self.assertTrue(result['complete'])
        self.assertNotIn('errorCode', result)
        self.assertEqual(result['listeners'][0]['address'], '127.0.0.1')

    def test_ipv6_loopback(self):
        result = listener_observation(HEADER, table('00000000000000000000000001000000'))
        self.assertNotIn('errorCode', result)
        self.assertEqual(result['listeners'][0]['address'], '::1')

    def test_ipv6_mapped_loopback_is_observed_not_configured(self):
        result = listener_observation(HEADER, table('0000000000000000FFFF00000100007F'))
        self.assertNotIn('errorCode', result)
        self.assertEqual(result['listeners'][0]['family'], 'IPv6')
        self.assertEqual(result['listeners'][0]['address'], '127.0.0.1')
        self.assertEqual(result['listeners'][0]['nativeAddress'], '0000000000000000FFFF00000100007F')

    def test_any_non_loopback_listener_blocks_even_on_other_port(self):
        for address in ['00000000', '010200C0']:
            native = table('0100007F') + table(address, '9D37').split('\n', 1)[1]
            result = listener_observation(native, HEADER)
            self.assertEqual(result['errorCode'], 'NON_LOOPBACK_LISTENER')
        result = listener_observation(table('0100007F'), table('0' * 32, '9D37'))
        self.assertEqual(result['errorCode'], 'NON_LOOPBACK_LISTENER')

    def test_missing_truncated_or_unknown_tables_fail_closed(self):
        for bad in [None, '', 'unknown\n', HEADER + '0: 0100007F:1F9A\n', HEADER + 'garbage\n', table('0100007F', state='FF')]:
            result = listener_observation(table('0100007F'), bad)
            self.assertFalse(result['complete'])
            self.assertIn('errorCode', result)

    def test_valid_empty_tables_are_not_api_readiness(self):
        self.assertEqual(listener_observation(HEADER, HEADER)['errorCode'], 'API_LISTENER_MISSING')
        self.assertEqual(listener_observation(table('0100007F', state='01'), HEADER)['errorCode'], 'API_LISTENER_MISSING')

    def test_ambiguous_duplicate_listener_rejected(self):
        native = table('0100007F') + table('0100007F').split('\n', 1)[1]
        self.assertEqual(listener_observation(native, HEADER)['errorCode'], 'AMBIGUOUS_TCP_LISTENER')

    @unittest.skipUnless(os.getuid() == 1000 and os.getgid() == 1000, 'Native seed write requires the approved UID/GID')
    def test_native_seed_bootstrap_preserves_audited_bytes_and_is_exclusive(self):
        with tempfile.TemporaryDirectory() as root:
            os.chmod(root, 0o700)
            config = copy.deepcopy(self.config);config['profilePath'] = root
            args = profile_seed_arguments(config)
            result = subprocess.run(args, capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            path = Path(root) / config['profileSeed']['name']
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), config['profileSeed']['sha256'])
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertNotEqual(subprocess.run(args, capture_output=True, timeout=5).returncode, 0)

    def test_bootstrap_hash_symlink_and_permissions_fail_closed(self):
        with tempfile.TemporaryDirectory() as root:
            config = copy.deepcopy(self.config);config['profilePath'] = root
            config['profileSeed']['sha256'] = '0' * 64
            result = subprocess.run(profile_seed_arguments(config), capture_output=True, timeout=5)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((Path(root) / config['profileSeed']['name']).exists())
            config = copy.deepcopy(self.config);config['profilePath'] = root
            seed = Path(root) / config['profileSeed']['name'];seed.symlink_to('/nonexistent-seed-test')
            self.assertNotEqual(subprocess.run(profile_seed_arguments(config), capture_output=True, timeout=5).returncode, 0)
            os.chmod(root, 0o755)
            self.assertNotEqual(subprocess.run(profile_seed_arguments(config), capture_output=True, timeout=5).returncode, 0)

    def test_missing_or_symlink_directory_is_not_writable_evidence(self):
        with tempfile.TemporaryDirectory() as root:
            missing = directory_observation(root + '/absent')
            self.assertFalse(missing['writable'])
            link = Path(root) / 'link';link.symlink_to(root, target_is_directory=True)
            self.assertFalse(directory_observation(str(link))['writable'])

    def test_python_and_javascript_seed_commands_cannot_drift(self):
        code = "console.log(JSON.stringify(require('./services/zapInitialization').profileBootstrapArguments()))"
        child = subprocess.run(['node', '-e', code], cwd=Path(__file__).parents[1], capture_output=True, text=True, timeout=5)
        self.assertEqual(child.returncode, 0, child.stderr)
        self.assertEqual(json.loads(child.stdout), profile_seed_arguments(self.config))
        code = "console.log(JSON.stringify(require('./services/zapInitialization').jvmBootstrapArguments()))"
        child = subprocess.run(['node', '-e', code], cwd=Path(__file__).parents[1], capture_output=True, text=True, timeout=5)
        self.assertEqual(child.returncode, 0, child.stderr)
        self.assertEqual(json.loads(child.stdout), jvm_seed_arguments(self.config))

    @unittest.skipUnless(os.getuid() == 1000 and os.getgid() == 1000, 'Native seed write requires the approved UID/GID')
    def test_jvm_properties_are_staged_privately_before_launcher(self):
        with tempfile.TemporaryDirectory() as root:
            config = copy.deepcopy(self.config);config['javaPreferencesRoot'] = root
            result = subprocess.run(jvm_seed_arguments(config), capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            file = Path(root) / config['jvmPropertiesName']
            self.assertEqual(file.read_text(), '-Xmx512m -Djava.util.prefs.userRoot=' + root + '\n')
            self.assertEqual(file.stat().st_mode & 0o777, 0o600)

    def test_native_observer_collects_actual_properties_profile_and_both_tables_without_secrets(self):
        data = __import__('base64').b64decode(self.config['profileSeed']['base64'])
        with tempfile.TemporaryFile() as seed:
            seed.write(data);seed.seek(0)
            def fake_open(path, *args, **kwargs):
                if path == '/proc/77/cmdline':
                    return io.BytesIO(b'/usr/bin/java\0-Xmx512m\0-Djava.util.prefs.userRoot=/home/zap/.ZAP\0-api.key=SENSITIVE_TEST_VALUE\0')
                if path == '/proc/net/tcp':return io.StringIO(HEADER)
                if path == '/proc/net/tcp6':return io.StringIO(table('0000000000000000FFFF00000100007F'))
                raise AssertionError('Unexpected filesystem read: ' + str(path))
            def lstat(path):
                mode = stat.S_IFREG | 0o600 if path.endswith(self.config['profileSeed']['name']) else stat.S_IFDIR | 0o700
                return types.SimpleNamespace(st_mode=mode, st_uid=1000, st_gid=1000)
            with patch('builtins.open', fake_open), patch('os.lstat', lstat), patch('os.access', return_value=True), \
                 patch('os.statvfs', return_value=types.SimpleNamespace(f_blocks=1024, f_frsize=4096, f_bavail=1000)), \
                 patch('os.open', side_effect=lambda *a, **k: os.dup(seed.fileno())), patch('glob.glob', return_value=['/proc/77/cmdline']):
                observed = collect_writable_observations(self.config)
            self.assertEqual(observed['profile']['seedSha256'], self.config['profileSeed']['sha256'])
            self.assertEqual(observed['javaPreferences']['rootProperty'], self.config['javaPreferencesRoot'])
            self.assertTrue(observed['listeners']['complete'])
            self.assertNotIn('errorCode', observed['listeners'])
            self.assertNotIn('SENSITIVE_TEST_VALUE', json.dumps(observed))


if __name__ == '__main__':
    unittest.main()
