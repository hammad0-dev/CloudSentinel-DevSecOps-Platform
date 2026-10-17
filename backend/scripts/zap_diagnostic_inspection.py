"""Pure validation of native Docker inspection for the isolated ZAP diagnostic."""
import re
import json
from pathlib import Path

MiB = 1024 * 1024
TMPFS = {
    '/home/zap/.ZAP': (256 * MiB, 0o700),
    '/tmp': (64 * MiB, 0o1777),
    '/zap/wrk': (64 * MiB, 0o700),
}
WRITABLE = json.loads((Path(__file__).parents[1] / 'config' / 'zap-writable-paths.json').read_text())
TMPFS[WRITABLE['profilePath']] = (WRITABLE['profileMiB'] * MiB, 0o700)


class InspectionError(ValueError):
    """Bounded error codes; never include native configuration or credentials."""


def require(condition, code):
    if not condition:
        raise InspectionError(code)


def options(text):
    require(isinstance(text, str) and len(text) <= 512, 'TMPFS_OPTIONS_MALFORMED')
    result = {}
    for token in text.split(','):
        pair = token.split('=', 1)
        require(pair[0] and pair[0] not in result, 'TMPFS_OPTIONS_AMBIGUOUS')
        result[pair[0]] = pair[1] if len(pair) == 2 else None
    require(set(result) == {'rw', 'noexec', 'nosuid', 'nodev', 'size', 'uid', 'gid', 'mode'},
            'TMPFS_OPTIONS_UNSAFE')
    require(all(result[key] is None for key in ('rw', 'noexec', 'nosuid', 'nodev')),
            'TMPFS_FLAGS_MALFORMED')
    return result


def size_bytes(text):
    match = re.fullmatch(r'([1-9][0-9]*)([kKmMgG]?)', text or '')
    require(match is not None, 'TMPFS_SIZE_MALFORMED')
    return int(match[1]) * {'': 1, 'k': 1024, 'm': MiB, 'g': 1024 * MiB}[match[2].lower()]


def validate_inspection(value, container_id, image_id, owner):
    require(isinstance(value, dict), 'INSPECTION_MALFORMED')
    require(re.fullmatch('[a-f0-9]{64}', container_id or '') is not None, 'CONTAINER_ID_MALFORMED')
    require(re.fullmatch('sha256:[a-f0-9]{64}', image_id or '') is not None, 'IMAGE_ID_MALFORMED')
    require(isinstance(owner, str) and re.fullmatch('[a-z0-9][a-z0-9_.-]{0,62}', owner), 'OWNER_MALFORMED')
    require(value.get('Id') == container_id and value.get('Image') == image_id, 'IMMUTABLE_IDENTITY_MISMATCH')
    config, host, state = value.get('Config'), value.get('HostConfig'), value.get('State')
    require(all(isinstance(x, dict) for x in (config, host, state)), 'INSPECTION_MALFORMED')
    require(isinstance(config.get('Labels'), dict) and config['Labels'].get('cloudsentinel.owner') == owner,
            'OWNERSHIP_MISMATCH')
    require(value.get('Name') == '/' + owner, 'CONTAINER_NAME_MISMATCH')
    require(config.get('Hostname') == owner and host.get('ExtraHosts') == [owner + ':127.0.0.1'],
            'LOCAL_HOSTNAME_MISMATCH')
    require(state.get('Running') is True and state.get('Restarting') is False, 'CONTAINER_NOT_RUNNING')
    # Health may legitimately still be "starting" here. API/initialization
    # readiness is checked later, not inferred from Docker's health status.
    require(host.get('NetworkMode') == 'none', 'NETWORK_NOT_DISABLED')
    require(host.get('ReadonlyRootfs') is True, 'ROOTFS_NOT_READONLY')
    require(config.get('User') == '1000:1000', 'USER_MISMATCH')
    require(host.get('Memory') == 1536 * MiB, 'MEMORY_LIMIT_MISMATCH')
    require(host.get('NanoCpus') == 1000000000, 'CPU_LIMIT_MISMATCH')
    require(host.get('PidsLimit') == 128, 'PID_LIMIT_MISMATCH')
    require(host.get('Privileged') is False and not host.get('CapAdd') and host.get('CapDrop') == ['ALL'],
            'CAPABILITY_OR_PRIVILEGE_MISMATCH')
    security = host.get('SecurityOpt')
    require(isinstance(security, list) and 'no-new-privileges:true' in security and
            'no-new-privileges:false' not in security, 'NO_NEW_PRIVILEGES_MISSING')
    require(not host.get('Binds') and not host.get('VolumesFrom') and not host.get('Mounts'),
            'HOST_OR_VOLUME_MOUNT_BLOCKED')
    require(host.get('PublishAllPorts') is False and not host.get('PortBindings'), 'PUBLISHED_PORT_BLOCKED')
    network = value.get('NetworkSettings')
    require(isinstance(network, dict) and isinstance(network.get('Ports'), dict) and
            not any(network['Ports'].values()), 'PUBLISHED_PORT_BLOCKED')
    require(isinstance(network.get('Networks'), dict) and set(network['Networks']) == {'none'},
            'UNEXPECTED_NETWORK_ATTACHMENT')

    tmpfs = host.get('Tmpfs')
    require(isinstance(tmpfs, dict) and set(tmpfs) == set(TMPFS), 'TMPFS_PATHS_MISMATCH')
    for path, (capacity, mode) in TMPFS.items():
        parsed = options(tmpfs[path])
        require(size_bytes(parsed['size']) == capacity, 'TMPFS_CAPACITY_MISMATCH')
        require(parsed['uid'] == '1000' and parsed['gid'] == '1000', 'TMPFS_OWNERSHIP_MISMATCH')
        require(re.fullmatch(r'0?[0-7]{3,4}', parsed['mode'] or '') is not None and
                int(parsed['mode'], 8) == mode, 'TMPFS_MODE_MISMATCH')

    # --tmpfs is represented by HostConfig.Tmpfs and need not appear in Mounts.
    # If the engine supplies a mirror, reject binds, volumes, unknown paths and
    # contradictory metadata rather than requiring a particular list length.
    mounts = value.get('Mounts')
    require(isinstance(mounts, list), 'MOUNTS_MALFORMED')
    destinations = set()
    for mount in mounts:
        require(isinstance(mount, dict) and mount.get('Type') == 'tmpfs' and
                mount.get('Destination') in TMPFS and mount.get('Source') in ('', None) and
                mount.get('RW') is True, 'UNEXPECTED_MOUNT_BLOCKED')
        require(mount['Destination'] not in destinations, 'DUPLICATE_MOUNT')
        destinations.add(mount['Destination'])
    return {'configurationVerified': True, 'tmpfsSource': 'HostConfig.Tmpfs',
            'initializationVerified': False}
