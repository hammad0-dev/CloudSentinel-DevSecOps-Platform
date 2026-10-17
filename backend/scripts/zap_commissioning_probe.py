"""Fixed lifecycle-owned ZAP API driver. Never opens a target socket itself."""
import json
import os
import subprocess
import sys
import urllib.parse
import urllib.request

LIMIT = 65536
LOG = '/tmp/cloudsentinel-commissioning-zap.log'
PID = '/tmp/cloudsentinel-commissioning-zap.pid'
PASSIVE_EXIT = '/tmp/commissioning-plan-0.exit'


def api(path, key, parameters=None):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    url = 'http://127.0.0.1:8090/JSON/' + path + '/'
    data = urllib.parse.urlencode(parameters).encode() if parameters is not None else None
    request = urllib.request.Request(url, data=data, headers={'X-ZAP-API-Key': key})
    with opener.open(request, timeout=2) as response:
        raw = response.read(LIMIT + 1)
    if len(raw) > LIMIT:
        raise ValueError('API_RESPONSE_TOO_LARGE')
    result = json.loads(raw)
    if isinstance(result, dict) and 'code' in result:
        raise ValueError('API_REJECTED')
    return result


def run(mode, arguments):
    if mode == 'prepare-reuse':
        # A previous successful autorun has exited. Never rotate files while a
        # daemon/listener is still alive, and never overwrite passive evidence.
        import stat
        if run('stopped', {}) != {'stopped': True}:
            raise ValueError('PREVIOUS_DAEMON_RUNNING')
        fd = os.open(PASSIVE_EXIT, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, 'r', encoding='ascii') as stream:
            value = os.fstat(stream.fileno())
            if not stat.S_ISREG(value.st_mode) or value.st_uid != os.getuid() or stream.read(16) != '0\n':
                raise ValueError('PASSIVE_AUTORUN_NOT_COMPLETED')
        for source in (LOG, PID):
            value = os.lstat(source)
            if not stat.S_ISREG(value.st_mode) or value.st_uid != os.getuid() or value.st_mode & 0o077 or value.st_size > 1048576:
                raise ValueError('UNSAFE_REUSE_ARTIFACT')
            if os.path.lexists(source + '.passive'):
                raise ValueError('REUSE_ALREADY_PREPARED')
        for source in (LOG, PID):
            os.link(source, source + '.passive', follow_symlinks=False)
            os.unlink(source)
        return {'prepared': True}
    if mode == 'start':
        # Arguments come only from the verified, hashed server-side driver.
        if not isinstance(arguments, list) or arguments[0] != 'zap.sh':
            raise ValueError('INVALID_STARTUP')
        fd = os.open(LOG, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as output:
            process = subprocess.Popen(arguments, stdin=subprocess.DEVNULL, stdout=output,
                                       stderr=subprocess.STDOUT, cwd='/tmp', start_new_session=True)
        pid_fd = os.open(PID, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(pid_fd, 'w', encoding='ascii') as record:
            record.write(str(process.pid))
        return {'started': True, 'pid': process.pid}
    if mode == 'stopped':
        with open(PID, encoding='ascii') as record:
            pid = int(record.read(16))
        try:
            with open('/proc/' + str(pid) + '/stat', encoding='ascii') as stream:
                exited = stream.read(4096).rsplit(')', 1)[1].split()[0] == 'Z'
        except FileNotFoundError:
            exited = True
        listening = False
        for table in ('tcp', 'tcp6'):
            with open('/proc/net/' + table, encoding='ascii') as stream:
                for row in stream.readlines()[1:]:
                    fields = row.split()
                    if fields[1].split(':')[1].upper() == '1F9A' and fields[3] == '0A':
                        listening = True
        return {'stopped': exited and not listening}
    if mode == 'views':
        return {name: api(path, arguments['key']) for name, path in (
            ('version', 'core/view/version'), ('addons', 'autoupdate/view/installedAddons'),
            ('rules', 'ascan/view/scanners'))}
    if mode == 'configure':
        import re
        host = arguments['hostname']
        if not re.fullmatch(r'[a-z0-9-]+\.test', host):
            raise ValueError('HOST_BLOCKED')
        parameters = {'description': 'commissioning-fixture-only', 'enabled': 'true',
                      'matchRegex': 'false', 'matchString': host,
                      'requestsPerSecond': '2', 'groupBy': 'HOST'}
        existing = api('network/view/getRateLimitRules', arguments['key']).get('getRateLimitRules')
        if existing == []:
            if api('network/action/addRateLimitRule', arguments['key'], parameters) != {'Result': 'OK'}:
                raise ValueError('RATE_CONFIGURATION_FAILED')
        elif not isinstance(existing, list) or len(existing) != 1 or any(str(existing[0].get(k)).lower() != v.lower() for k, v in parameters.items()):
            raise ValueError('UNEXPECTED_EXISTING_RATE_RULE')
        rows = api('network/view/getRateLimitRules', arguments['key']).get('getRateLimitRules')
        if not isinstance(rows, list) or len(rows) != 1 or any(str(rows[0].get(k)).lower() != v.lower() for k, v in parameters.items()):
            raise ValueError('RATE_READBACK_FAILED')
        for name in ('ThreadPerHost', 'HostPerScan'):
            if api('ascan/action/setOption' + name, arguments['key'], {'Integer': '1'}) != {'Result': 'OK'}:
                raise ValueError('CONCURRENCY_CONFIGURATION_FAILED')
            if str(api('ascan/view/option' + name, arguments['key']).get(name)) != '1':
                raise ValueError('CONCURRENCY_READBACK_FAILED')
        return {'rateConfigured': 2, 'concurrencyConfigured': 1, 'rateRules': rows}
    if mode == 'authentication':
        # The same harmless view succeeds with the valid key before and after
        # both rejection tests. Closure alone remains insufficient evidence.
        before = api('core/view/version', arguments['key'])
        outcomes = []
        for key in ('', 'commissioning-invalid-key'):
            try:
                value = api('core/view/version', key)
                outcomes.append({'rejected': False, 'value': value})
            except Exception:
                outcomes.append({'rejected': True})
        after = api('core/view/version', arguments['key'])
        return {'before': before, 'after': after, 'rejections': outcomes}
    if mode == 'log':
        size = os.stat(LOG).st_size
        if size > 1048576:
            raise ValueError('STARTUP_LOG_TRUNCATED')
        with open(LOG, encoding='utf-8', errors='strict') as stream:
            return {'log': stream.read(), 'bytes': size}
    if mode == 'request':
        request = arguments['request']
        # Only a benign numeric-free fixture authority and exact two paths.
        import re
        if not re.fullmatch(r'GET http://[a-z0-9-]+\.test:18080/test/(sqli\?id=1|xss\?q=hello)&cs_commission=[a-f0-9]{32}-[01] HTTP/1\.1\r\nHost: [a-z0-9-]+\.test:18080\r\nConnection: close\r\n\r\n', request):
            raise ValueError('REQUEST_SCOPE_BLOCKED')
        if request.split(' ')[1].split('/')[2] != request.split('\r\n')[1][6:]:
            raise ValueError('REQUEST_AUTHORITY_MISMATCH')
        return api('core/action/sendRequest', arguments['key'],
                   {'request': request, 'followRedirects': 'false'})
    if mode == 'stop':
        return api('core/action/shutdown', arguments['key'], {})
    raise ValueError('OPERATION_BLOCKED')


if __name__ == '__main__':
    try:
        result = run(sys.argv[1], json.loads(''.join(sys.argv[2:])))
        print(json.dumps(result, separators=(',', ':')))
    except Exception:
        # Never include API keys, request credentials, or unrestricted exceptions.
        print('{"error":"COMMISSIONING_DRIVER_FAILED"}')
        sys.exit(1)
