"""Pure fixture inspection decisions. No Docker, network or process execution."""
import copy
import json
import re

CHECKS = ('image', 'startup', 'runtimeIdentity', 'health', 'SQLi', 'reflectedXss',
          'SQLiteCleanup', 'isolation', 'resourceLimits', 'sourceIntegrity')


class FixtureDiagnosticError(ValueError):
    pass


def require(value, code):
    if not value:
        raise FixtureDiagnosticError(code)


def compare_config(expected, observed):
    require(isinstance(expected, dict) and isinstance(observed, dict), 'CONFIG_MALFORMED')
    # This is the sole normalization. Empty lists/strings and real commands are
    # not null. Missing/null fields other than Cmd remain different.
    left, right = copy.deepcopy(expected), copy.deepcopy(observed)
    left.setdefault('Cmd', None)
    right.setdefault('Cmd', None)
    require(left == right, 'IMPORTED_CONFIG_MISMATCH')
    return True


def validate_image(value, expected, layers, owner, source_hash):
    require(isinstance(value, dict) and re.fullmatch(r'sha256:[a-f0-9]{64}', value.get('Id', '')), 'IMAGE_ID_MALFORMED')
    require(value.get('Architecture') == 'amd64' and value.get('Os') == 'linux', 'IMAGE_PLATFORM_MISMATCH')
    require(value.get('RootFS', {}).get('Layers') == layers and layers and
            all(re.fullmatch(r'sha256:[a-f0-9]{64}', x) for x in layers), 'IMAGE_LAYERS_MISMATCH')
    compare_config(expected, value.get('Config'))
    labels = value['Config'].get('Labels', {})
    require(labels.get('cloudsentinel.build.owner') == owner and
            labels.get('cloudsentinel.fixture.source.sha256') == source_hash and
            labels.get('cloudsentinel.fixture.kind') == 'cloudsentinel-vulnerable-v1', 'IMAGE_OWNERSHIP_OR_SOURCE_MISMATCH')
    return value['Id']


def validate_container(value, container_id, image_id, owner):
    require(isinstance(value, dict) and re.fullmatch(r'[a-f0-9]{64}', container_id or ''), 'CONTAINER_ID_MALFORMED')
    c, h, network = value.get('Config', {}), value.get('HostConfig', {}), value.get('NetworkSettings', {})
    require(value.get('Id') == container_id and value.get('Image') == image_id and
            c.get('Labels', {}).get('cloudsentinel.owner') == owner and
            c.get('Labels', {}).get('cloudsentinel.role') == 'active-fixture-validation', 'CONTAINER_IDENTITY_MISMATCH')
    require(value.get('State', {}).get('Running') is True and c.get('User') == '10001:10001', 'CONTAINER_NOT_READY')
    require(h.get('NetworkMode') == 'none' and set(network.get('Networks', {})) == {'none'}, 'NETWORK_NOT_DISABLED')
    require(h.get('ReadonlyRootfs') is True and h.get('Privileged') is False and
            h.get('CapDrop') == ['ALL'] and not h.get('CapAdd') and
            'no-new-privileges:true' in h.get('SecurityOpt', []) and
            'no-new-privileges:false' not in h.get('SecurityOpt', []), 'SECURITY_MISMATCH')
    require(h.get('Memory') == 268435456 and h.get('NanoCpus') == 1000000000 and h.get('PidsLimit') == 64, 'RESOURCE_LIMIT_MISMATCH')
    require(not h.get('Binds') and not h.get('Mounts') and not h.get('VolumesFrom') and
            not h.get('PortBindings') and h.get('PublishAllPorts') is False and
            not any(network.get('Ports', {}).values()), 'MOUNT_OR_PORT_BLOCKED')
    require(h.get('Tmpfs') == {'/tmp': 'rw,noexec,nosuid,nodev,size=16m,uid=10001,gid=10001,mode=0700'}, 'TMPFS_MISMATCH')
    mounts = value.get('Mounts')
    require(isinstance(mounts, list) and all(m.get('Type') == 'tmpfs' and m.get('Destination') == '/tmp' and
            not m.get('Source') and m.get('RW') is True for m in mounts) and len(mounts) <= 1, 'UNEXPECTED_MOUNT')
    return True


def assess_probe(value, source_hash):
    require(isinstance(value, dict) and len(json.dumps(value).encode()) <= 262144, 'PROBE_MALFORMED')
    from fixture_probe import CASES
    rows = value.get('observations', [])
    require(isinstance(rows, list), 'PROBE_MALFORMED')
    def response(name):
        selected = [x for x in rows if isinstance(x, dict) and x.get('name') == name]
        if len(selected) != 1:
            return None
        row = selected[0]
        case = CASES[name]
        if (row.get('path') != case['path'] or row.get('query') != case['query'] or
                row.get('status') != case['status'] or row.get('errorType') or row.get('truncated') is not False or
                not isinstance(row.get('body'), str) or len(row['body'].encode()) > 8192):
            return None
        return row['body']
    def parsed(name, expected):
        try:
            return json.loads(response(name)) == expected
        except (TypeError, ValueError):
            return False
    runtime = value.get('runtime', {})
    tmp = runtime.get('tmp', {})
    limits = runtime.get('cgroupLimits', {})
    listeners = value.get('listeners', {})
    ipv4, ipv6 = listeners.get('ipv4'), listeners.get('ipv6')
    valid_listener = (isinstance(ipv4, list) and len(ipv4) == 1 and isinstance(ipv4[0], dict) and
                      ipv4[0].get('address') == '0.0.0.0' and ipv4[0].get('port') == 18080 and
                      ipv4[0].get('nativeAddress') == '00000000' and ipv6 == [])
    try:
        quota, period = map(int, limits.get('cpuMax', '').split())
        cpu = quota == period and period > 0
    except (ValueError, TypeError):
        cpu = False
    outcomes = {
        'runtimeIdentity': runtime.get('uid') == runtime.get('gid') == 10001 and runtime.get('rootFilesystemReadOnly') is True,
        'health': response('health') == response('health-constant') == 'fixture-ready',
        'SQLi': parsed('normal-one', [['demo-one']]) and parsed('normal-two', [['demo-two']]) and parsed('injection', [['demo-one'], ['demo-two']]),
        'reflectedXss': response('reflection') is not None and CASES['reflection']['query']['q'] in response('reflection'),
        'SQLiteCleanup': len(rows) == len(CASES) and {r.get('name') for r in rows} == set(CASES) and
            parsed('normal-one', [['demo-one']]) and parsed('normal-two', [['demo-two']]) and
            parsed('injection', [['demo-one'], ['demo-two']]) and all(r.get('sqliteResidualFiles') == [] for r in rows),
        'isolation': value.get('targetOrigin') == 'http://127.0.0.1:18080' and runtime.get('networkInterfaces') == ['lo'] and valid_listener and response('scope') == 'not found',
        'resourceLimits': limits.get('memoryMax') == '268435456' and limits.get('pidsMax') == '64' and cpu and
            tmp.get('capacityBytes') == 16777216 and tmp.get('uid') == tmp.get('gid') == 10001 and tmp.get('mode') == '0700' and
            runtime.get('effectiveCapabilities') == 0 and runtime.get('noNewPrivileges') is True,
        'sourceIntegrity': runtime.get('appSha256') == source_hash and runtime.get('appDirectoryFiles') == ['app.py'] and
            runtime.get('appUid') == runtime.get('appGid') == 10001 and runtime.get('appMode') == '0444',
    }
    return {k: 'PASS' if v else 'FAIL' for k, v in outcomes.items()}


def finish(checks, cleanup_ok, error=False):
    if error or cleanup_ok is not True or any(v == 'FAIL' for v in checks.values()):
        return 'FAIL', 1
    if any(checks.get(k) != 'PASS' for k in CHECKS):
        return 'BLOCKED', 3
    return 'PASS', 0


def replay_validation(imported, expected, layers, owner, source_hash, start, inspect, probe, cleanup):
    """Offline-injectable control flow; never substitutes production observations."""
    checks = dict.fromkeys(CHECKS, 'NOT_RUN')
    try:
        image_id = validate_image(imported, expected, layers, owner, source_hash)
        checks['image'] = 'PASS'
        cid = start(image_id)
        validate_container(inspect(cid), cid, image_id, owner)
        checks['startup'] = 'PASS'
        checks.update(assess_probe(probe(cid), source_hash))
    except Exception:
        first = next((k for k in ('image', 'startup') if checks[k] == 'NOT_RUN'), None)
        if first:
            checks[first] = 'FAIL'
        else:
            checks['runtimeIdentity'] = 'FAIL'
    finally:
        try:
            cleaned = cleanup() is True
        except Exception:
            cleaned = False
    status, code = finish(checks, cleaned)
    return {'status': status, 'exitCode': code, 'checks': checks, 'cleanup': 'PASS' if cleaned else 'FAIL',
            'diagnosticOnly': True, 'activeExecutionReady': False}
