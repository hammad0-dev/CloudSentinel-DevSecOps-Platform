"""Approved offline-built fixture validation. No execution on import.

Runtime use requires separate authorization, --execute and fresh private build /
preflight evidence. This source-only repair does not authorize execution.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time

from fixture_image_diagnostic import CHECKS, assess_probe, compare_config, finish, validate_container, validate_image

ROOT = Path(__file__).resolve().parents[2]


def native_payload():
    source = (ROOT/'backend/scripts/fixture_probe.py').read_text()
    parser = (ROOT/'backend/scripts/zap_writable_runtime.py').read_text()
    return ("__name__='fixture_probe_native'\n" + source + '\nresult=collect(sys.argv[1])\n' +
            'try:\n ns={"__name__":"tcp_parser"};exec(' + repr(parser) + ',ns)\n' +
            ' result["listeners"]={"ipv4":ns["tcp_listeners"](Path("/proc/net/tcp").read_text(),"IPv4"),"ipv6":ns["tcp_listeners"](Path("/proc/net/tcp6").read_text(),"IPv6")}\n' +
            'except Exception:result["listenerError"]="NATIVE_LISTENERS_INCOMPLETE"\n' +
            'print(json.dumps(result))\n')


def filehash(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1048576), b''):
            h.update(block)
    return h.hexdigest()


def main(directory):
    if not __debug__:
        raise ValueError('OPTIMIZED_PYTHON_NOT_ALLOWED')
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError('PRIVATE_EVIDENCE_DIRECTORY_REQUIRED')
    if any((directory/n).exists() for n in ('result.json', 'runtime-attempt-started.json')):
        raise ValueError('FRESH_EVIDENCE_DIRECTORY_REQUIRED')
    os.umask(0o077);os.environ['DAST_ACTIVE_ENABLED']='false'
    pre = json.loads((directory/'preflight.json').read_text())
    before = json.loads((directory/'before.json').read_text())
    build = json.loads((directory/'build-1.json').read_text())
    owner = pre['owner']
    if not re.fullmatch(r'cs-fixture-[a-z0-9-]{1,40}', owner):
        raise ValueError('INVALID_OWNER')
    cid = image = None
    attempted = retained = False
    checks = dict.fromkeys(CHECKS, 'NOT_RUN')
    report = {'diagnosticOnly': True, 'activeExecutionReady': False, 'activeEnabled': False, 'checks': checks}
    stage = 'image'

    def save(name, value):
        (directory/(name+'.json')).write_text(json.dumps(value, indent=2))

    def run(args, timeout=20):
        try:
            out = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
            return {'exitCode': out.returncode, 'stdout': out.stdout[:262144], 'stderr': out.stderr[:262144],
                    'truncated': len(out.stdout.encode())>262144 or len(out.stderr.encode())>262144}
        except subprocess.TimeoutExpired:
            return {'exitCode': None, 'stdout': '', 'stderr': 'COMMAND_DEADLINE_EXCEEDED', 'truncated': False}

    def check(args, timeout=20):
        out = run(args, timeout)
        if out['exitCode'] != 0 or out['truncated']:
            raise ValueError('COMMAND_FAILED')
        return out['stdout']

    def native():
        return json.loads(check(['docker','inspect',cid]))[0]

    def pod_identity(raw):
        return sorted((p['metadata']['uid'], sorted((c['name'],c['ready'],c['restartCount']) for c in p['status'].get('containerStatuses',[]))) for p in json.loads(raw)['items'])

    try:
        if pre['status'] != 'PASS' or json.loads((directory/'reproducibility.json').read_text())['status'] != 'PASS' or json.loads((directory/'independent-archive-comparison.json').read_text())['status'] != 'PASS':
            raise ValueError('BUILD_PRECONDITION_FAILED')
        for name, digest in pre['sourceHashes'].items():
            if filehash(ROOT/'backend/fixtures/active-vulnerable'/name) != digest:
                raise ValueError('SOURCE_HASH_MISMATCH')
        if filehash(directory/'fixture-1.tar') != build['archiveSha256']:
            raise ValueError('ARCHIVE_HASH_MISMATCH')
        for key, args in [('containers',['docker','ps','-a','--no-trunc','--format','{{.ID}}']),('networks',['docker','network','ls','--no-trunc','--format','{{.ID}}'])]:
            if sorted(check(args).splitlines()) != sorted(before[key]['stdout'].splitlines()):
                raise ValueError('BASELINE_CHANGED')
        existing_tags = check(['docker','image','ls','--format','{{.Repository}}:{{.Tag}}']).splitlines()
        if set(pre['buildTags']+[pre['finalTag']]) & set(existing_tags) or owner in check(['docker','ps','-a','--format','{{.Names}}']).splitlines():
            raise ValueError('RESOURCE_COLLISION')
        with (directory/'runtime-attempt-started.json').open('x') as marker:
            json.dump({'attempt':1,'archiveSha256':build['archiveSha256']},marker)
        attempted = True
        loaded = run(['docker','image','load','--input',str(directory/'fixture-1.tar')],120)
        save('import',loaded)
        if loaded['exitCode'] != 0 or loaded['truncated']:
            raise ValueError('IMPORT_FAILED')
        imported = json.loads(check(['docker','image','inspect',pre['buildTags'][0]]))[0]
        save('imported-image',imported)
        image = imported.get('Id')
        validate_image(imported, build['config']['config'], build['layerDiffIds'], owner, build['appSha256'])
        checks['image']='PASS';report['localImageId']=image;stage='startup'
        cid = check(['docker','run','--detach','--pull=never','--name',owner,'--label','cloudsentinel.owner='+owner,'--label','cloudsentinel.role=active-fixture-validation','--network','none','--read-only','--user','10001:10001','--cap-drop','ALL','--security-opt','no-new-privileges:true','--pids-limit','64','--memory','256m','--cpus','1','--tmpfs','/tmp:rw,noexec,nosuid,nodev,size=16m,uid=10001,gid=10001,mode=0700',image],30).strip()
        observed=native();save('container-inspection',observed);validate_container(observed,cid,image,owner)
        deadline=time.monotonic()+20
        while observed['State'].get('Health',{}).get('Status') != 'healthy':
            if observed['State'].get('Health',{}).get('Status') == 'unhealthy' or time.monotonic()>=deadline:
                raise ValueError('STARTUP_NOT_HEALTHY')
            time.sleep(0.5);observed=native();validate_container(observed,cid,image,owner)
        checks['startup']='PASS';stage='runtimeIdentity'
        outcome=run(['docker','exec',cid,'python3','-I','-B','-c',native_payload(),build['appSha256']],25)
        save('functional-command',outcome)
        if outcome['exitCode'] != 0 or outcome['stderr'] or outcome['truncated']:
            raise ValueError('NATIVE_PROBE_INCOMPLETE')
        facts=json.loads(outcome['stdout']);save('functional-evidence',facts)
        checks.update(assess_probe(facts,build['appSha256']))
        if all(checks[k]=='PASS' for k in CHECKS):
            current=json.loads(check(['docker','image','inspect',image]))[0]
            validate_image(current,build['config']['config'],build['layerDiffIds'],owner,build['appSha256'])
            if pre['finalTag'] in check(['docker','image','ls','--format','{{.Repository}}:{{.Tag}}']).splitlines():
                raise ValueError('FINAL_TAG_COLLISION')
            check(['docker','image','tag',image,pre['finalTag']]);retained=True;report['finalTag']=pre['finalTag']
    except Exception as error:
        report['errorCategory']=str(error) if re.fullmatch('[A-Z_]{1,64}',str(error)) else 'VALIDATION_FAILED'
        if checks[stage]=='NOT_RUN':checks[stage]='FAIL'
    finally:
        failures=[]
        try:
            if cid is None:
                candidate=run(['docker','container','inspect',owner])
                if candidate['exitCode']==0:
                    item=json.loads(candidate['stdout'])[0]
                    if item['Config']['Labels'].get('cloudsentinel.owner') != owner:
                        raise ValueError('CLEANUP_OWNERSHIP_MISMATCH')
                    cid=item['Id']
            if cid:
                item=native()
                if item['Id']!=cid or item['Image']!=image or item['Config']['Labels'].get('cloudsentinel.owner')!=owner or item['Config']['Labels'].get('cloudsentinel.role')!='active-fixture-validation':
                    raise ValueError('CLEANUP_IDENTITY_MISMATCH')
                removed=run(['docker','rm','--force',cid],30);save('container-cleanup',removed)
                if removed['exitCode']!=0:raise ValueError('CONTAINER_CLEANUP_FAILED')
        except Exception:failures.append('CONTAINER_CLEANUP_FAILED')
        try:
            if attempted:
                found=run(['docker','image','inspect',pre['buildTags'][0]])
                if found['exitCode']==0:
                    target=json.loads(found['stdout'])[0]
                    # A failed runtime-config assertion must not prevent removal
                    # of our unvalidated image. Cleanup verifies immutable ID,
                    # owner, source and filesystem identity, not execution readiness.
                    labels=target.get('Config',{}).get('Labels',{})
                    if (not re.fullmatch(r'sha256:[a-f0-9]{64}',target.get('Id','')) or
                            labels.get('cloudsentinel.build.owner')!=owner or
                            labels.get('cloudsentinel.fixture.kind')!='cloudsentinel-vulnerable-v1' or
                            labels.get('cloudsentinel.fixture.source.sha256')!=build['appSha256'] or
                            target.get('RootFS',{}).get('Layers')!=build['layerDiffIds']):raise ValueError('IMAGE_OWNERSHIP_MISMATCH')
                    if image is not None and image!=target['Id']:raise ValueError('IMAGE_CHANGED')
                    expected_tags={pre['buildTags'][0],pre['finalTag']} if retained else {pre['buildTags'][0]}
                    if set(target['RepoTags'])!=expected_tags:raise ValueError('IMAGE_REFERENCES_CHANGED')
                    if not retained and check(['docker','ps','-a','--filter','ancestor='+target['Id'],'--format','{{.ID}}']).strip():raise ValueError('IMAGE_IN_USE')
                    check(['docker','image','rm',pre['buildTags'][0]],30)
                elif 'No such image' not in found['stderr']:
                    raise ValueError('IMAGE_CLEANUP_UNVERIFIED')
        except Exception:failures.append('IMAGE_CLEANUP_FAILED')
        try:
            for index in (1,2):
                context=directory/f'context-{index}'
                if context.exists():
                    if context.is_symlink() or set(f.name for f in context.iterdir())!={'app.py','Dockerfile','.dockerignore'}:raise ValueError('ARTIFACT_OWNERSHIP_MISMATCH')
                    for f in context.iterdir():
                        if f.is_symlink() or filehash(f)!=pre['sourceHashes'][f.name]:raise ValueError('ARTIFACT_CHANGED')
                        f.unlink()
                    context.rmdir()
            for name in ('base.tar','fixture-1.tar','fixture-2.tar'):
                f=directory/name
                if f.exists():
                    if f.is_symlink() or not f.is_file():raise ValueError('UNSAFE_ARCHIVE')
                    f.unlink()
        except Exception:failures.append('ARTIFACT_CLEANUP_FAILED')
        try:
            commands={'docker':['docker','info','--format','{{.ServerVersion}}'],'containers':['docker','ps','-a','--no-trunc','--format','{{.ID}}'],'networks':['docker','network','ls','--no-trunc','--format','{{.ID}}'],'images':['docker','image','ls','--no-trunc','--quiet'],'backend':['curl','--max-time','5','--fail','--silent','http://127.0.0.1:3000/api/health'],'postgres':['pg_isready'],'minikube':['minikube','status','-o','json'],'project17':['kubectl','get','pods','-n','cloudsentinel-p-17','-o','json'],'ownedContainers':['docker','ps','-a','--filter','label=cloudsentinel.owner='+owner,'--format','{{.ID}}'],'ownedNetworks':['docker','network','ls','--filter','label=cloudsentinel.owner='+owner,'--format','{{.ID}}'],'ownedImages':['docker','image','ls','--no-trunc','--filter','label=cloudsentinel.build.owner='+owner,'--format','{{.ID}}']}
            after={k:run(v) for k,v in commands.items()};save('after',after)
            if any(v['exitCode']!=0 for v in after.values()):raise ValueError('POSTFLIGHT_INCOMPLETE')
            if any(sorted(after[k]['stdout'].splitlines())!=sorted(before[k]['stdout'].splitlines()) for k in ('containers','networks')):raise ValueError('INVENTORY_CHANGED')
            if pod_identity(after['project17']['stdout'])!=pod_identity(before['project17']['stdout']):raise ValueError('PROJECT17_CHANGED')
            if after['ownedContainers']['stdout'].strip() or after['ownedNetworks']['stdout'].strip():raise ValueError('RESIDUAL_RESOURCES')
            if not set(before['images']['stdout'].splitlines()).issubset(set(after['images']['stdout'].splitlines())):raise ValueError('ORIGINAL_IMAGE_REMOVED')
            if set(after['ownedImages']['stdout'].splitlines())!=({image} if retained else set()):raise ValueError('IMAGE_RESIDUAL_MISMATCH')
        except Exception:failures.append('POSTFLIGHT_FAILED')
        status,code=finish(checks,not failures,bool(report.get('errorCategory')))
        report.update({'status':status,'exitCode':code,'fixtureReadiness':'PASS' if status=='PASS' else 'BLOCKED',
                       'cleanup':'PASS' if not failures else 'FAIL','cleanupErrors':failures,'imageRetained':retained})
        save('result',report);print(json.dumps(report,indent=2))
    return report['exitCode']


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute',action='store_true');parser.add_argument('--evidence-dir',type=Path)
    args=parser.parse_args()
    if not args.execute or args.evidence_dir is None:parser.error('Explicit approval scope and fresh --evidence-dir required')
    try:code=main(args.evidence_dir)
    except Exception:
        print(json.dumps({'status':'BLOCKED','exitCode':3,'errorCategory':'PRIVATE_PREFLIGHT_REQUIRED','activeExecutionReady':False}));code=3
    raise SystemExit(code)
