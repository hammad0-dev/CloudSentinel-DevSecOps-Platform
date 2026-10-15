"""Offline synthetic image tests; no Docker daemon or network required."""
import ast
import copy
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
import zipfile

SCRIPT = Path(__file__).parents[1] / 'scripts' / 'assemble-zap-image.py'
spec = importlib.util.spec_from_file_location('assembly', SCRIPT)
assembly = importlib.util.module_from_spec(spec)
spec.loader.exec_module(assembly)


class OfflineAssemblyTest(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory()
        self.addCleanup(self.work.cleanup)
        self.path = Path(self.work.name)
        self.selected = {}
        self.files = {}
        for name in sorted(assembly.NAMES):
            output = io.BytesIO()
            with zipfile.ZipFile(output, 'w') as archive:
                deps = '<dependencies><addons><addon><id>network</id><version>&gt;= 0.3.0</version></addon></addons></dependencies>' if name == 'ascanrules' else ''
                archive.writestr('ZapAddOn.xml', '<zapaddon><version>0.29.0</version><not-before-version>2.17.0</not-before-version>' + deps + '</zapaddon>')
            data = output.getvalue()
            self.selected[name] = {'version': '0.29.0', 'sha256': assembly.digest(data)}
            self.files['zap/plugin/' + name + '-release-0.29.0.zap'] = data
        self.files['zap/plugin/ascanrules-release-0.1.0.zap'] = b'old archive'
        self.files['zap/plugin/unrelated-release-1.zap'] = b'untouched'
        layer = io.BytesIO()
        with tarfile.open(fileobj=layer, mode='w') as archive:
            for name in ('zap', 'zap/plugin'):
                info = tarfile.TarInfo(name)
                info.type, info.mode = tarfile.DIRTYPE, 0o755
                archive.addfile(info)
            for name, data in self.files.items():
                assembly.add_file(archive, name, data)
        self.layer = layer.getvalue()
        self.config = {'architecture': 'amd64', 'os': 'linux',
                       'config': {'User': 'zap', 'Env': ['HOME=/home/zap'], 'Entrypoint': ['/zap/zap.sh']},
                       'rootfs': {'type': 'layers', 'diff_ids': ['sha256:' + assembly.digest(self.layer)]},
                       'history': [{'created_by': 'base'}]}
        config_bytes = assembly.canonical(self.config)
        self.base = self.path / 'base.tar'
        with tarfile.open(self.base, 'w') as archive:
            assembly.add_file(archive, 'manifest.json', assembly.canonical([{'Config': assembly.digest(config_bytes) + '.json', 'Layers': ['layer.tar']}]))
            assembly.add_file(archive, assembly.digest(config_bytes) + '.json', config_bytes)
            assembly.add_file(archive, 'layer.tar', self.layer)
        self.manifest = {'base': {'reference': 'example@sha256:' + 'a' * 64},
                         'selection': {n: v for n, v in self.selected.items() if n in ('ascanrules', 'network', 'reports', 'automation')},
                         'dependencyResolution': {'verified': True, 'transitiveEvidence': {n: v for n, v in self.selected.items() if n in ('commonlib', 'oast', 'database')}}}
        self.inspect = {'Os': 'linux', 'Architecture': 'amd64', 'Id': 'sha256:' + 'a' * 64,
                        'RootFS': {'Layers': self.config['rootfs']['diff_ids']}}

    def assemble(self, name='result.tar', manifest=None, inspected=None):
        return assembly.assemble(self.base, manifest or self.manifest, inspected or self.inspect, self.path / name)

    def test_deterministic_config_layers_and_permissions(self):
        first, second = self.assemble(), self.assemble('second.tar')
        self.assertEqual(first, second)
        self.assertEqual((self.path / 'result.tar').read_bytes(), (self.path / 'second.tar').read_bytes())
        config = assembly.validate_archive(self.path / 'result.tar')
        self.assertEqual(config['config'], self.config['config'])
        self.assertEqual(config['rootfs']['diff_ids'][:-1], self.config['rootfs']['diff_ids'])
        with tarfile.open(self.path / 'result.tar') as outer:
            record, = json.load(outer.extractfile('manifest.json'))
            with tarfile.open(fileobj=outer.extractfile(record['Layers'][-1])) as layer:
                self.assertIn('zap/plugin/.wh.ascanrules-release-0.1.0.zap', layer.getnames())
                self.assertEqual(len([x for x in layer if x.name.endswith('.zap') and '/.wh.' not in x.name]), 7)
                for entry in layer:
                    self.assertEqual(entry.mtime, 0)
                    self.assertEqual(entry.uid, 0)
                    if '/.wh.' not in entry.name:
                        self.assertEqual(entry.mode, 0o644)
                effective = dict(self.files)
                for entry in layer:
                    if '/.wh.' in entry.name:
                        effective.pop(entry.name.replace('/.wh.', '/'))
                    else:
                        effective[entry.name] = layer.extractfile(entry).read()
                self.assertNotIn('zap/plugin/ascanrules-release-0.1.0.zap', effective)
                self.assertEqual(effective['zap/plugin/unrelated-release-1.zap'], b'untouched')

    def test_hash_tampering_fails_before_output(self):
        changed = copy.deepcopy(self.manifest)
        changed['selection']['network']['sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            self.assemble(manifest=changed)
        self.assertFalse((self.path / 'result.tar').exists())

    def test_identity_and_layer_mismatch_fail(self):
        changed = copy.deepcopy(self.inspect)
        changed['RootFS']['Layers'] = ['sha256:' + '0' * 64]
        with self.assertRaisesRegex(ValueError, 'layer mismatch'):
            self.assemble(inspected=changed)
        changed = copy.deepcopy(self.inspect)
        changed['Id'] = 'sha256:' + 'b' * 64
        with self.assertRaisesRegex(ValueError, 'base identity'):
            self.assemble(inspected=changed)

    def test_incomplete_closure_and_unsupported_versions_fail(self):
        changed = copy.deepcopy(self.manifest)
        del changed['dependencyResolution']['transitiveEvidence']['database']
        with self.assertRaisesRegex(ValueError, 'closure'):
            self.assemble(manifest=changed)
        self.assertTrue(assembly.satisfies('0.29.0', '>= 0.3.0'))
        self.assertTrue(assembly.satisfies('0.24.0', '>= 0.7.0'))
        self.assertFalse(assembly.satisfies('2.0.0', '>= 1.40.0 & < 2.0.0'))
        with self.assertRaises(ValueError):
            assembly.version('1.2.3-unknown')
        with self.assertRaises(ValueError):
            assembly.satisfies('1.2.3', 'anything')

    def test_no_external_process_or_network_imports(self):
        tree = ast.parse(SCRIPT.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                self.assertTrue(all(alias.name not in {'subprocess', 'socket', 'requests', 'urllib', 'http'} for alias in node.names))
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                self.assertNotIn(node.func.attr, {'system', 'popen', 'execv', 'spawnv'})

    def test_output_collision_and_unsafe_paths_rejected(self):
        self.assemble()
        with self.assertRaises(FileExistsError):
            self.assemble()
        for name in ('../zap/plugin', '/zap/plugin', 'zap/../plugin'):
            with self.assertRaises(ValueError):
                assembly.safe_name(name)

    def test_validation_rejects_corrupt_layer_and_config(self):
        self.assemble()
        with tarfile.open(self.path / 'result.tar') as original:
            entries = [(member.name, original.extractfile(member).read()) for member in original]
        for target in ('layer.tar', '.json'):
            bad = self.path / ('bad-' + target.replace('.', '_') + '.tar')
            with tarfile.open(bad, 'w') as archive:
                for name, data in entries:
                    if name.endswith(target) and name != 'manifest.json':
                        data += b'corrupt'
                    assembly.add_file(archive, name, data)
            with self.assertRaisesRegex(ValueError, 'digest mismatch'):
                assembly.validate_archive(bad)

    def test_manifest_version_and_minimum_rejected(self):
        for xml in ('<zapaddon><version>wrong</version></zapaddon>',
                    '<zapaddon><version>0.29.0</version><not-before-version>2.18.0</not-before-version></zapaddon>'):
            data = io.BytesIO()
            with zipfile.ZipFile(data, 'w') as archive:
                archive.writestr('ZapAddOn.xml', xml)
            expected = {'version': '0.29.0', 'sha256': assembly.digest(data.getvalue())}
            with self.assertRaises(ValueError):
                assembly.inspect_addon(data.getvalue(), expected)


if __name__ == '__main__':
    unittest.main()
