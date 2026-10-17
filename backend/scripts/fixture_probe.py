"""Bounded loopback fixture observations. Importing this module performs no I/O."""
import glob
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import urllib.error
import urllib.parse
import urllib.request

ORIGIN = 'http://127.0.0.1:18080'
CASES = {
    'health': {'path': '/health', 'query': {}, 'status': 200},
    'health-constant': {'path': '/health', 'query': {'id': '1 OR 1=1', 'q': '<script>health-marker</script>'}, 'status': 200},
    'normal-one': {'path': '/test/sqli', 'query': {'id': '1'}, 'status': 200},
    'normal-two': {'path': '/test/sqli', 'query': {'id': '2'}, 'status': 200},
    'injection': {'path': '/test/sqli', 'query': {'id': '1 OR 1=1'}, 'status': 200},
    'reflection': {'path': '/test/xss', 'query': {'q': '<script>alert("fixture-marker")</script>'}, 'status': 200},
    'scope': {'path': '/admin', 'query': {}, 'status': 404},
}


def measure():
    result = {}
    try:
        app = Path('/app/app.py');s = app.lstat();t = Path('/tmp').stat();v = os.statvfs('/tmp')
        if not stat.S_ISREG(s.st_mode):
            raise ValueError('UNSAFE_APP_FILE')
        result.update({'uid': os.getuid(), 'gid': os.getgid(), 'rootFilesystemReadOnly': bool(os.statvfs('/').f_flag & os.ST_RDONLY),
                       'appSha256': hashlib.sha256(app.read_bytes()).hexdigest(), 'appDirectoryFiles': sorted(os.listdir('/app')),
                       'appUid': s.st_uid, 'appGid': s.st_gid, 'appMode': format(stat.S_IMODE(s.st_mode), '04o'),
                       'networkInterfaces': sorted(os.listdir('/sys/class/net')),
                       'tmp': {'capacityBytes': v.f_blocks*v.f_frsize, 'availableBytes': v.f_bavail*v.f_frsize,
                               'uid': t.st_uid, 'gid': t.st_gid, 'mode': format(stat.S_IMODE(t.st_mode), '04o')}})
        fields = dict(line.strip().split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
        result['effectiveCapabilities'] = int(fields['CapEff'].strip(), 16)
        result['noNewPrivileges'] = fields['NoNewPrivs'].strip() == '1'
        result['cgroupLimits'] = {key: Path(path).read_text().strip() for key, path in (
            ('memoryMax', '/sys/fs/cgroup/memory.max'), ('pidsMax', '/sys/fs/cgroup/pids.max'), ('cpuMax', '/sys/fs/cgroup/cpu.max'))}
    except (OSError, ValueError, KeyError):
        result['errorCategory'] = 'NATIVE_RUNTIME_OBSERVATION_INCOMPLETE'
    return result


def collect(source_hash, client=None):
    runtime = measure()
    result = {'targetOrigin': ORIGIN, 'runtime': runtime, 'observations': []}
    if (runtime.get('uid') != 10001 or runtime.get('gid') != 10001 or
            runtime.get('rootFilesystemReadOnly') is not True or runtime.get('networkInterfaces') != ['lo'] or
            runtime.get('appSha256') != source_hash):
        result['errorCategory'] = 'NATIVE_PRECONDITION_FAILED'
        return result
    client = client or urllib.request.build_opener(urllib.request.ProxyHandler({}))
    for name, case in CASES.items():
        row = {'name': name, 'path': case['path'], 'query': case['query']}
        try:
            url = ORIGIN+case['path']+('?' + urllib.parse.urlencode(case['query']) if case['query'] else '')
            try:
                response = client.open(url, timeout=2)
            except urllib.error.HTTPError as error:
                response = error
            with response:
                data = response.read(8193)
                row.update({'status': response.code, 'body': data[:8192].decode('utf-8'), 'truncated': len(data) > 8192})
        except Exception as error:
            row['errorType'] = type(error).__name__ if type(error).__name__ in ('TimeoutError', 'URLError', 'UnicodeDecodeError') else 'REQUEST_FAILED'
        try:
            row['sqliteResidualFiles'] = glob.glob('/tmp/cs-sqli-*')
        except OSError:
            row['sqliteObservationError'] = True
        result['observations'].append(row)
    return result


if __name__ == '__main__':
    print(json.dumps(collect(sys.argv[1])))
