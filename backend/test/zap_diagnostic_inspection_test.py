import copy
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).parents[1] / 'scripts'))
from zap_diagnostic_inspection import InspectionError, validate_inspection, WRITABLE


class DiagnosticInspectionTest(unittest.TestCase):
    def setUp(self):
        path = Path(__file__).parent / 'fixtures' / 'zap-diagnostic-inspection-712c7658.json'
        self.genuine = json.loads(path.read_text())['inspection']
        self.native = copy.deepcopy(self.genuine)
        # Explicit proposed configuration, not a claim that this mount ran.
        self.native['HostConfig']['Tmpfs'][WRITABLE['profilePath']] = 'rw,noexec,nosuid,nodev,size=4m,uid=1000,gid=1000,mode=0700'
        self.owner = self.native['Config']['Labels']['cloudsentinel.owner']

    def validate(self, native=None):
        return validate_inspection(native if native is not None else self.native,
                                   self.native['Id'], self.native['Image'], self.owner)

    def rejects(self, mutate, code):
        native = copy.deepcopy(self.native)
        mutate(native)
        with self.assertRaisesRegex(InspectionError, '^' + code + '$'):
            self.validate(native)

    def test_genuine_mounts_empty_regression(self):
        self.assertEqual(self.native['Mounts'], [])
        with self.assertRaises(AssertionError):
            assert len(self.native['Mounts']) == 3
        self.assertEqual(self.validate(), {'configurationVerified': True,
                         'tmpfsSource': 'HostConfig.Tmpfs', 'initializationVerified': False})

    def test_starting_health_does_not_prevent_initialization_measurement(self):
        self.assertEqual(self.native['State']['Health']['Status'], 'starting')
        self.assertFalse(self.validate()['initializationVerified'])

    def test_prior_genuine_three_mounts_cannot_pass_new_profile_requirement(self):
        with self.assertRaisesRegex(InspectionError, 'TMPFS_PATHS_MISMATCH'):
            self.validate(self.genuine)

    def test_missing_and_extra_tmpfs_paths(self):
        for path in ['/home/zap/.ZAP', '/tmp', '/zap/wrk']:
            self.rejects(lambda n: n['HostConfig']['Tmpfs'].pop(path), 'TMPFS_PATHS_MISMATCH')
        self.rejects(lambda n: n['HostConfig']['Tmpfs'].update({'/extra': 'rw'}), 'TMPFS_PATHS_MISMATCH')
        self.rejects(lambda n: n['HostConfig'].pop('Tmpfs'), 'TMPFS_PATHS_MISMATCH')

    def test_exact_capacity_for_every_path(self):
        for path in ['/home/zap/.ZAP', '/tmp', '/zap/wrk']:
            def mutate(n):
                n['HostConfig']['Tmpfs'][path] = n['HostConfig']['Tmpfs'][path].replace('256m', '32m').replace('64m', '32m')
            self.rejects(mutate, 'TMPFS_CAPACITY_MISMATCH')

    def test_equivalent_units_option_order_and_octal_modes(self):
        native = copy.deepcopy(self.native)
        for path, options in native['HostConfig']['Tmpfs'].items():
            native['HostConfig']['Tmpfs'][path] = ','.join(reversed(options.replace('256m', '268435456').replace('64m', '65536k').replace('mode=0700', 'mode=700').split(',')))
        self.assertTrue(self.validate(native)['configurationVerified'])

    def test_wrong_uid_gid_and_permissions(self):
        for before, after, code in [('uid=1000', 'uid=0', 'TMPFS_OWNERSHIP_MISMATCH'),
                                    ('gid=1000', 'gid=0', 'TMPFS_OWNERSHIP_MISMATCH'),
                                    ('mode=0700', 'mode=0777', 'TMPFS_MODE_MISMATCH')]:
            self.rejects(lambda n: n['HostConfig']['Tmpfs'].update({'/home/zap/.ZAP': n['HostConfig']['Tmpfs']['/home/zap/.ZAP'].replace(before, after)}), code)

    def test_ambiguous_or_unsafe_options_fail(self):
        for suffix, code in [(',exec', 'TMPFS_OPTIONS_UNSAFE'), (',size=1m', 'TMPFS_OPTIONS_AMBIGUOUS'),
                             (',ro', 'TMPFS_OPTIONS_UNSAFE'), (',suid', 'TMPFS_OPTIONS_UNSAFE')]:
            self.rejects(lambda n: n['HostConfig']['Tmpfs'].update({'/tmp': n['HostConfig']['Tmpfs']['/tmp'] + suffix}), code)
        self.rejects(lambda n: n['HostConfig']['Tmpfs'].update({'/tmp': None}), 'TMPFS_OPTIONS_MALFORMED')

    def test_bind_socket_volume_and_structured_host_mounts_fail(self):
        for key, value in [('Binds', ['/tmp:/zap/wrk:rw']), ('VolumesFrom', ['foreign']),
                           ('Mounts', [{'Type': 'bind', 'Source': '/var/run/docker.sock', 'Target': '/sock'}])]:
            self.rejects(lambda n: n['HostConfig'].update({key: value}), 'HOST_OR_VOLUME_MOUNT_BLOCKED')
        for kind, source in [('bind', '/var/run/docker.sock'), ('volume', 'volume-name')]:
            self.rejects(lambda n: n.update({'Mounts': [{'Type': kind, 'Source': source, 'Destination': '/zap/wrk', 'RW': True}]}), 'UNEXPECTED_MOUNT_BLOCKED')

    def test_optional_tmpfs_mount_mirror_is_accepted(self):
        native = copy.deepcopy(self.native)
        native['Mounts'] = [{'Type': 'tmpfs', 'Source': '', 'Destination': path, 'RW': True}
                            for path in native['HostConfig']['Tmpfs']]
        self.assertTrue(self.validate(native)['configurationVerified'])
        native['Mounts'].append(native['Mounts'][0])
        with self.assertRaisesRegex(InspectionError, 'DUPLICATE_MOUNT'):
            self.validate(native)

    def test_network_and_rootfs_controls(self):
        self.rejects(lambda n: n['HostConfig'].update({'NetworkMode': 'bridge'}), 'NETWORK_NOT_DISABLED')
        self.rejects(lambda n: n['HostConfig'].update({'ReadonlyRootfs': False}), 'ROOTFS_NOT_READONLY')
        self.rejects(lambda n: n['Config'].update({'User': '0:0'}), 'USER_MISMATCH')
        self.rejects(lambda n: n['NetworkSettings']['Networks'].update({'bridge': {}}), 'UNEXPECTED_NETWORK_ATTACHMENT')

    def test_resource_limits(self):
        for key, value, code in [('Memory', 1024 * 1024 * 1024, 'MEMORY_LIMIT_MISMATCH'),
                                 ('NanoCpus', 0, 'CPU_LIMIT_MISMATCH'), ('PidsLimit', 0, 'PID_LIMIT_MISMATCH')]:
            self.rejects(lambda n: n['HostConfig'].update({key: value}), code)

    def test_privilege_capability_and_no_new_privileges_controls(self):
        for key, value in [('Privileged', True), ('CapAdd', ['NET_ADMIN']), ('CapDrop', [])]:
            self.rejects(lambda n: n['HostConfig'].update({key: value}), 'CAPABILITY_OR_PRIVILEGE_MISMATCH')
        for value in [[], ['no-new-privileges:false'], ['no-new-privileges:true', 'no-new-privileges:false']]:
            self.rejects(lambda n: n['HostConfig'].update({'SecurityOpt': value}), 'NO_NEW_PRIVILEGES_MISSING')

    def test_published_ports_and_hostname(self):
        self.rejects(lambda n: n['HostConfig'].update({'PublishAllPorts': True}), 'PUBLISHED_PORT_BLOCKED')
        self.rejects(lambda n: n['HostConfig'].update({'PortBindings': {'8090/tcp': [{}]}}), 'PUBLISHED_PORT_BLOCKED')
        self.rejects(lambda n: n['NetworkSettings'].update({'Ports': {'8090/tcp': [{}]}}), 'PUBLISHED_PORT_BLOCKED')
        self.rejects(lambda n: n['HostConfig'].update({'ExtraHosts': ['host:192.0.2.1']}), 'LOCAL_HOSTNAME_MISMATCH')

    def test_identity_and_missing_native_fields(self):
        self.rejects(lambda n: n.update({'Id': 'f' * 64}), 'IMMUTABLE_IDENTITY_MISMATCH')
        self.rejects(lambda n: n.update({'Image': 'sha256:' + 'f' * 64}), 'IMMUTABLE_IDENTITY_MISMATCH')
        self.rejects(lambda n: n['Config']['Labels'].update({'cloudsentinel.owner': 'foreign'}), 'OWNERSHIP_MISMATCH')
        self.rejects(lambda n: n.update({'HostConfig': None}), 'INSPECTION_MALFORMED')


if __name__ == '__main__':
    unittest.main()
