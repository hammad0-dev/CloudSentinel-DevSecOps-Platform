"""Read-only writable-path measurements and strict Linux TCP table decoding.

No Docker calls, sockets or HTTP requests. The prepared diagnostic executes
this source inside its owned container and supplies the verified path config.
"""
import glob
import base64
import hashlib
import ipaddress
import json
import os
import re
import stat
import sys


def profile_seed_arguments(config):
    code = "import os,sys,base64,hashlib;p,n,b,h=sys.argv[1:];d=base64.b64decode(b,validate=True);assert hashlib.sha256(d).hexdigest()==h;s=os.lstat(p);assert s.st_uid==s.st_gid==1000 and s.st_mode&511==448;fd=os.open(p,os.O_DIRECTORY|os.O_NOFOLLOW);f=os.open(n,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,384,dir_fd=fd);w=os.fdopen(f,'wb');w.write(d);w.close();os.close(fd)"
    return ['python3', '-I', '-c', code, config['profilePath'], config['profileSeed']['name'],
            config['profileSeed']['base64'], config['profileSeed']['sha256']]


def jvm_seed_arguments(config):
    data = ('-Xmx512m -Djava.util.prefs.userRoot=' + config['javaPreferencesRoot'] + '\n').encode()
    return ['python3', '-I', '-c', profile_seed_arguments(config)[3], config['javaPreferencesRoot'],
            config['jvmPropertiesName'], base64.b64encode(data).decode(), hashlib.sha256(data).hexdigest()]


def tcp_listeners(text, family):
    if not isinstance(text, str) or not text or len(text.encode()) > 1048576:
        raise ValueError('MISSING_OR_OVERSIZED_TCP_TABLE')
    lines = text.splitlines()
    header = lines[0].split()
    if len(header) < 4 or header[:2] != ['sl', 'local_address'] or header[2] not in ('rem_address', 'remote_address') or header[3] != 'st':
        raise ValueError('MALFORMED_TCP_HEADER')
    width = 8 if family == 'IPv4' else 32 if family == 'IPv6' else 0
    if not width:
        raise ValueError('UNKNOWN_TCP_FAMILY')
    observed = []
    seen = set()
    for line in lines[1:]:
        parts = line.split()
        if len(parts) < 10 or not re.fullmatch(r'\d+:', parts[0]):
            raise ValueError('MALFORMED_TCP_ROW')
        for endpoint in parts[1:3]:
            if not re.fullmatch(r'[0-9A-Fa-f]{' + str(width) + r'}:[0-9A-Fa-f]{4}', endpoint):
                raise ValueError('MALFORMED_TCP_ENDPOINT')
        if parts[3] not in {f'{state:02X}' for state in range(1, 13)} or not parts[9].isdigit():
            raise ValueError('MALFORMED_TCP_STATE_OR_INODE')
        if parts[3] != '0A':
            continue
        raw, raw_port = parts[1].split(':')
        packed = bytes.fromhex(raw)
        packed = packed[::-1] if family == 'IPv4' else b''.join(packed[i:i+4][::-1] for i in range(0, 16, 4))
        address = ipaddress.ip_address(packed)
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
            address = address.ipv4_mapped
        port = int(raw_port, 16)
        if not port or (str(address), port) in seen:
            raise ValueError('AMBIGUOUS_TCP_LISTENER')
        seen.add((str(address), port))
        observed.append({'family': family, 'address': str(address), 'port': port,
                         'nativeAddress': raw, 'loopback': address.is_loopback})
    return observed


def listener_observation(ipv4, ipv6):
    result = {'complete': False, 'tcpComplete': False, 'tcp6Complete': False, 'listeners': []}
    try:
        result['listeners'].extend(tcp_listeners(ipv4, 'IPv4'))
        result['tcpComplete'] = True
        result['listeners'].extend(tcp_listeners(ipv6, 'IPv6'))
        result['tcp6Complete'] = True
        result['complete'] = True
        if any(not entry['loopback'] for entry in result['listeners']):
            result['errorCode'] = 'NON_LOOPBACK_LISTENER'
        elif not any(entry['port'] == 8090 for entry in result['listeners']):
            result['errorCode'] = 'API_LISTENER_MISSING'
    except ValueError as error:
        result['errorCode'] = str(error)
    return result


def directory_observation(path):
    observed = {'path': path, 'writable': False}
    try:
        value = os.lstat(path)
        if not stat.S_ISDIR(value.st_mode):
            raise ValueError('NOT_A_REAL_DIRECTORY')
        volume = os.statvfs(path)
        observed.update({'uid': value.st_uid, 'gid': value.st_gid,
                         'mode': format(stat.S_IMODE(value.st_mode), '04o'),
                         'writable': os.access(path, os.W_OK),
                         'capacityBytes': volume.f_blocks * volume.f_frsize,
                         'availableBytes': volume.f_bavail * volume.f_frsize})
    except (OSError, ValueError) as error:
        observed['errorType'] = type(error).__name__
    return observed


def collect_writable_observations(config):
    profile = directory_observation(config['profilePath'])
    try:
        path = os.path.join(config['profilePath'], config['profileSeed']['name'])
        info = os.lstat(path)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError('UNSAFE_SEED_FILE')
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, 'rb') as stream:
            data = stream.read(4097)
        if len(data) > 4096:
            raise ValueError('OVERSIZED_SEED_FILE')
        profile.update({'seedSha256': hashlib.sha256(data).hexdigest(),
                        'seedMode': format(stat.S_IMODE(info.st_mode), '04o')})
    except (OSError, ValueError) as error:
        profile['seedErrorType'] = type(error).__name__
    roots = []
    heap = []
    for path in glob.glob('/proc/[0-9]*/cmdline'):
        try:
            with open(path, 'rb') as stream:
                arguments = stream.read(65536).split(b'\0')
            if not arguments or not arguments[0].endswith(b'java'):
                continue
            heap.extend(arg.decode('ascii') for arg in arguments if arg.startswith(b'-Xmx'))
            roots.extend(arg.decode('ascii').split('=', 1)[1] for arg in arguments
                         if arg.startswith(b'-Djava.util.prefs.userRoot='))
        except (OSError, UnicodeError):
            continue
    preferences = directory_observation(config['javaPreferencesEffectivePath'])
    preferences['rootProperty'] = roots[0] if len(roots) == 1 else None
    tables = {}
    for family, path in [('ipv4', '/proc/net/tcp'), ('ipv6', '/proc/net/tcp6')]:
        try:
            with open(path, encoding='ascii') as stream:
                tables[family] = stream.read(1048577)
        except (OSError, UnicodeError):
            tables[family] = None
    return {'profile': profile, 'javaPreferences': preferences,
            'observedJavaHeapArguments': heap,
            'listeners': listener_observation(tables['ipv4'], tables['ipv6'])}
