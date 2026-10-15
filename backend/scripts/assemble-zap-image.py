#!/usr/bin/env python3
"""Offline Docker-save archive assembly. No subprocess, Docker or network APIs."""
import argparse
import copy
import hashlib
import io
import json
import os
from pathlib import PurePosixPath
import re
import tarfile
import tempfile
import xml.etree.ElementTree as ET
import zipfile

NAMES = {'ascanrules', 'automation', 'network', 'reports', 'commonlib', 'oast', 'database'}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def version(value):
    # ZAP release integers are major versions (83 == 83.0.0).
    if not re.fullmatch(r'(0|[1-9][0-9]*)(\.(0|[1-9][0-9]*)){0,2}', value):
        raise ValueError('Unsupported version: ' + value)
    parts = tuple(map(int, value.split('.')))
    return parts + (0,) * (3 - len(parts))


def satisfies(value, constraint):
    for clause in constraint.split('&'):
        match = re.fullmatch(r'\s*(>=|<=|>|<|=)\s*([0-9.]+)\s*', clause)
        if not match:
            raise ValueError('Unsupported constraint: ' + constraint)
        left, right = version(value), version(match[2])
        if not {'>=': left >= right, '<=': left <= right, '>': left > right,
                '<': left < right, '=': left == right}[match[1]]:
            return False
    return True


def safe_name(name):
    while name.startswith('./'):
        name = name[2:]
    if name.startswith('/') or '..' in PurePosixPath(name).parts:
        raise ValueError('Unsafe archive path')
    return name.rstrip('/')


def add_file(archive, name, data, mode=0o644, uid=0, gid=0):
    info = tarfile.TarInfo(name)
    info.size, info.mode, info.uid, info.gid = len(data), mode, uid, gid
    info.mtime = 0
    archive.addfile(info, io.BytesIO(data))


def selections(manifest):
    if manifest['dependencyResolution']['verified'] is not True:
        raise ValueError('Unverified dependency closure')
    selected = dict(manifest['selection'])
    selected.update(manifest['dependencyResolution']['transitiveEvidence'])
    if set(selected) != NAMES:
        raise ValueError('Unexpected selected closure')
    for value in selected.values():
        version(value['version'])
        if not re.fullmatch('[a-f0-9]{64}', value['sha256']):
            raise ValueError('Invalid archive hash')
    return selected


def inspect_addon(data, expected):
    if digest(data) != expected['sha256']:
        raise ValueError('Archive SHA-256 mismatch')
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        if archive.namelist().count('ZapAddOn.xml') != 1:
            raise ValueError('Missing or duplicate ZapAddOn.xml')
        entry = archive.getinfo('ZapAddOn.xml')
        if entry.file_size > 1024 * 1024:
            raise ValueError('Oversized add-on manifest')
        xml = archive.read(entry)
    if b'<!DOCTYPE' in xml or b'<!ENTITY' in xml:
        raise ValueError('Unsafe XML')
    root = ET.fromstring(xml)
    if root.tag != 'zapaddon' or root.findtext('version') != expected['version']:
        raise ValueError('Add-on version mismatch')
    minimum = root.findtext('not-before-version')
    if minimum is None or version(minimum) > version('2.17.0'):
        raise ValueError('Unsupported minimum ZAP version')
    if root.find('not-from-version') is not None:
        if version('2.17.0') >= version(root.findtext('not-from-version')):
            raise ValueError('Unsupported maximum ZAP version')
    dependencies = {}
    for addon in root.findall('./dependencies/addons/addon'):
        name, constraint = addon.findtext('id'), addon.findtext('version')
        if not name or not constraint or name in dependencies:
            raise ValueError('Ambiguous dependency')
        dependencies[name] = constraint
    return {'minimumZapVersion': minimum, 'dependencies': dependencies,
            'manifestSha256': digest(xml)}


def validate_archive(path):
    """Validate minimal Docker-save format and all actual uncompressed diff IDs."""
    with tarfile.open(path, 'r:') as archive:
        names = archive.getnames()
        if len(names) != len(set(names)):
            raise ValueError('Duplicate image archive entries')
        record, = json.load(archive.extractfile('manifest.json'))
        config_bytes = archive.extractfile(record['Config']).read()
        if record['Config'] != digest(config_bytes) + '.json':
            raise ValueError('Config digest mismatch')
        config = json.loads(config_bytes)
        layers = record['Layers']
        if len(layers) != len(config['rootfs']['diff_ids']):
            raise ValueError('Layer count mismatch')
        if config['rootfs'].get('type') != 'layers':
            raise ValueError('Unsupported rootfs type')
        if sum(not item.get('empty_layer', False) for item in config.get('history', [])) != len(layers):
            raise ValueError('History/layer count mismatch')
        for name, expected in zip(layers, config['rootfs']['diff_ids']):
            h = hashlib.sha256()
            stream = archive.extractfile(name)
            for block in iter(lambda: stream.read(1024 * 1024), b''):
                h.update(block)
            if 'sha256:' + h.hexdigest() != expected:
                raise ValueError('Layer digest mismatch')
        return config


def assemble(base_path, manifest, inspected, output):
    selected = selections(manifest)
    if inspected['Os'] != 'linux' or inspected['Architecture'] != 'amd64':
        raise ValueError('Incorrect base platform')
    reference = manifest['base']['reference']
    if reference not in inspected.get('RepoDigests', []):
        # Docker containerd store may expose the immutable index as Id.
        if inspected['Id'] != reference.rsplit('@', 1)[1]:
            raise ValueError('Unverified pinned base identity')
    with tempfile.TemporaryDirectory(prefix='zap-assembly-') as work:
        paths, plugins, parents = [], {}, {}
        with tarfile.open(base_path, 'r:') as outer:
            record, = json.load(outer.extractfile('manifest.json'))
            config_bytes = outer.extractfile(record['Config']).read()
            config = json.loads(config_bytes)
            config_hash = digest(config_bytes)
            if config_hash not in record['Config']:
                raise ValueError('Base config hash mismatch')
            if config.get('architecture') != 'amd64' or config.get('os') != 'linux':
                raise ValueError('Base config platform mismatch')
            if config.get('config', {}).get('User') not in ('zap', '1000', '1000:1000'):
                raise ValueError('Unexpected base runtime user')
            if config['rootfs']['diff_ids'] != inspected['RootFS']['Layers']:
                raise ValueError('Base inspection/archive layer mismatch')
            if len(record['Layers']) != len(config['rootfs']['diff_ids']):
                raise ValueError('Base layer count mismatch')
            for index, layer in enumerate(record['Layers']):
                local = os.path.join(work, str(index) + '.tar')
                stream = outer.extractfile(layer)
                # Re-serialize nothing: decompress layer bytes only when needed.
                import gzip
                import shutil
                magic = stream.read(2)
                stream.seek(0)
                source = gzip.GzipFile(fileobj=stream) if magic == b'\x1f\x8b' else stream
                with open(local, 'wb') as dest:
                    shutil.copyfileobj(source, dest)
                h = hashlib.sha256()
                with open(local, 'rb') as f:
                    for block in iter(lambda: f.read(1024 * 1024), b''):
                        h.update(block)
                if 'sha256:' + h.hexdigest() != config['rootfs']['diff_ids'][index]:
                    raise ValueError('Base diff ID mismatch')
                paths.append(local)
                with tarfile.open(local, 'r:') as inner:
                    members = inner.getmembers()
                    # Whiteouts apply to lower layers before same-layer additions.
                    for member in members:
                        name = safe_name(member.name)
                        if name in ('zap/.wh.plugin', '.wh.zap', 'zap/.wh..wh..opq', '.wh..wh..opq') or name == 'zap/plugin/.wh..wh..opq':
                            plugins.clear()
                        elif name.startswith('zap/plugin/.wh.'):
                            plugins.pop('zap/plugin/' + name.split('/.wh.', 1)[1], None)
                    for member in members:
                        name = safe_name(member.name)
                        if name in ('zap', 'zap/plugin'):
                            if not member.isdir():
                                raise ValueError('Unsafe plugin parent')
                            parents[name] = True
                        if name.startswith('zap/plugin/') and name.endswith('.zap'):
                            if not member.isfile() or member.size > 64 * 1024 * 1024:
                                raise ValueError('Unsafe plugin archive')
                            plugins[name] = inner.extractfile(member).read()
        if not all(parents.get(x) for x in ('zap', 'zap/plugin')):
            raise ValueError('Plugin directory not established')
        chosen, evidence = {}, {}
        for name, expected in sorted(selected.items()):
            matches = [(p, data) for p, data in plugins.items()
                       if re.fullmatch(r'zap/plugin/' + re.escape(name) + r'-(release|beta|alpha)-' + re.escape(expected['version']) + r'\.zap', p)]
            if len(matches) != 1:
                raise ValueError('Selected archive unavailable: ' + name)
            path, data = matches[0]
            evidence[name] = inspect_addon(data, expected)
            chosen[path] = data
        for name, details in evidence.items():
            for dependency, constraint in details['dependencies'].items():
                if dependency not in selected or not satisfies(selected[dependency]['version'], constraint):
                    raise ValueError('Unsatisfied dependency: ' + name + ':' + dependency)
        removed = sorted(p for p in plugins if any(re.fullmatch(r'zap/plugin/' + re.escape(n) + r'-(release|beta|alpha)-.+\.zap', p) for n in selected) and p not in chosen)
        layer_bytes = io.BytesIO()
        with tarfile.open(fileobj=layer_bytes, mode='w', format=tarfile.USTAR_FORMAT) as layer:
            for path in removed:
                parent, base = path.rsplit('/', 1)
                add_file(layer, parent + '/.wh.' + base, b'', mode=0)
            for path, data in sorted(chosen.items()):
                add_file(layer, path, data)
        added = layer_bytes.getvalue()
        result = copy.deepcopy(config)
        result['rootfs']['diff_ids'].append('sha256:' + digest(added))
        result.setdefault('history', []).append({'created': '1970-01-01T00:00:00Z', 'created_by': 'CloudSentinel offline verified add-on assembly v1'})
        result_bytes = canonical(result)
        config_name = digest(result_bytes) + '.json'
        layer_names = [value.split(':')[1] + '/layer.tar' for value in result['rootfs']['diff_ids']]
        output_manifest = [{'Config': config_name, 'RepoTags': ['cloudsentinel/zap-offline:verified-closure'], 'Layers': layer_names}]
        with open(output, 'xb') as dest:
            os.chmod(output, 0o600)
            with tarfile.open(fileobj=dest, mode='w', format=tarfile.USTAR_FORMAT) as archive:
                add_file(archive, 'manifest.json', canonical(output_manifest))
                add_file(archive, config_name, result_bytes)
                for local, name in zip(paths, layer_names):
                    info = tarfile.TarInfo(name)
                    info.size, info.mode = os.path.getsize(local), 0o644
                    with open(local, 'rb') as source:
                        archive.addfile(info, source)
                add_file(archive, layer_names[-1], added)
        validate_archive(output)
        if result['config'] != config['config']:
            raise ValueError('Runtime configuration changed')
        return {'imageConfigId': 'sha256:' + digest(result_bytes), 'baseConfigId': 'sha256:' + config_hash,
                'addedDiffId': 'sha256:' + digest(added), 'removed': removed,
                'selected': selected, 'manifests': evidence, 'runtimeCapabilitiesVerified': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', required=True)
    parser.add_argument('--manifest', required=True)
    parser.add_argument('--inspection', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    with open(args.manifest) as f:
        manifest = json.load(f)
    with open(args.inspection) as f:
        inspected, = json.load(f)
    print(json.dumps(assemble(args.base, manifest, inspected, args.output), indent=2))
