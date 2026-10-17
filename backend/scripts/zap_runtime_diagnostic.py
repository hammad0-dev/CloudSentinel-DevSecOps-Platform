"""Owned, network-disabled ZAP diagnostic. Never run without fresh approval.

Default invocation only prints help. Runtime execution requires --execute plus
fresh private preflight/baseline evidence; offline tests inject I/O into the
separate zap_capability_diagnostic decision module.
"""
import argparse
from pathlib import Path
import os,stat
import textwrap

def native_python(source):
    # Embedded payloads have an unindented first line and four source-indentation
    # spaces on subsequent lines. Remove only that wrapper indentation.
    lines=source.splitlines()
    return lines[0]+'\n'+textwrap.dedent('\n'.join(lines[1:]))+'\n'

def main(evidence_dir):
    if not __debug__:
        raise ValueError('OPTIMIZED_PYTHON_NOT_ALLOWED')
    info=evidence_dir.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o700:
        raise ValueError('PRIVATE_EVIDENCE_DIRECTORY_REQUIRED')
    import json, subprocess, time, re, urllib.parse, tarfile, hashlib
    import sys
    import shlex
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from zap_capability_diagnostic import run_diagnostic,final_status,EXIT_CODES,MANDATORY,result as check_result,validate_operation,validate_automation
    from zap_diagnostic_inspection import validate_inspection
    from zap_writable_runtime import profile_seed_arguments,jvm_seed_arguments
    ROOT=Path(__file__).resolve().parents[2]
    writable=json.loads((ROOT/'backend/config/zap-writable-paths.json').read_text())
    observation_source=(ROOT/'backend/scripts/zap_writable_runtime.py').read_text()
    os.umask(0o077)
    os.environ['DAST_ACTIVE_ENABLED']='false'
    DIR=str(evidence_dir)+'/'
    preflight=json.loads((evidence_dir/'preflight.json').read_text())
    if (evidence_dir/'result.json').exists() or (evidence_dir/'import.json').exists():
        raise ValueError('FRESH_EVIDENCE_DIRECTORY_REQUIRED')
    OWNER=preflight['owner']
    assert re.fullmatch(r'cs-zap-[a-z0-9-]{1,40}',OWNER), 'INVALID_OWNER'
    TAG='cloudsentinel/zap-offline:verified-closure'
    ARCHIVE='/tmp/cs-zap-offline-cwa6clxp/assembly-1.tar'
    REQUIRED={'40012','40014','40016','40017','40018','40019','40020'}
    contracts=json.loads((ROOT/'backend/config/zap-diagnostic-contracts.json').read_text())
    addon_manifest=json.loads((ROOT/'backend/config/active-zap-image-manifest.json').read_text())
    expected={'imageConfigId':contracts['expectedImageConfigId'],'selected':{**addon_manifest['selection'],**addon_manifest['dependencyResolution']['transitiveEvidence']}}
    cid=None
    image=None
    import_attempted=False
    diagnostic=None
    execution_deadline=time.monotonic()+900
    cleaning=False
    result={'activeEnabled':False,'preflight':'PASS','runtimeCapabilityReadiness':'BLOCKED','capabilities':{}}

    def redacted(text):
        text=re.sub(r'(?i)(api[.]key\s*[=:]\s*)[^\s]+',r'\1[REDACTED]',text)
        return re.sub(r'\b[a-fA-F0-9]{64}\b','[REDACTED_HEX64]',text)

    def save(name,value):
        with open(DIR+name+'.json','w') as f:json.dump(value,f,indent=2)

    def run(args,timeout=20,input=None):
        if not cleaning and time.monotonic()>execution_deadline:
            return {'exitCode':None,'stdout':'','stderr':'DIAGNOSTIC_DEADLINE_EXCEEDED','truncated':False}
        try:
            r=subprocess.run(args,capture_output=True,text=True,timeout=timeout,input=input)
            stdout,stderr=redacted(r.stdout) if args[:2]==['docker','logs'] else r.stdout,r.stderr
            if args[:2]==['docker','logs']:stderr=redacted(stderr)
            return {'exitCode':r.returncode,'stdout':stdout[:1048576],'stderr':stderr[:1048576],
                    'truncated':len(stdout.encode())>1048576 or len(stderr.encode())>1048576}
        except subprocess.TimeoutExpired:
            return {'exitCode':None,'stdout':'','stderr':'COMMAND_DEADLINE_EXCEEDED','truncated':False}

    def check(args,timeout=20,input=None):
        r=run(args,timeout,input)
        if r['exitCode']!=0:raise RuntimeError('Operation failed: '+str(args[:2])+'; '+r['stderr'][:300])
        return r['stdout']

    def api(name,endpoint,params=None,auth=True,timeout=12):
        if endpoint not in {'JSON/core/view/version/','JSON/autoupdate/view/installedAddons/','JSON/ascan/view/scanners/'}:
            validate_operation(endpoint,params or {},auth)
        assert timeout==12
        assert endpoint.startswith(('JSON/','OTHER/','UI/'))
        assert not any(x in endpoint.lower() for x in ('/scan/','/spider/','/runplan/','/accessurl/'))
        code='''import json,sys,urllib.request,urllib.parse,urllib.error
    endpoint,query,auth=sys.argv[1:]
    key=open('/tmp/.key').read().strip()
    params=urllib.parse.parse_qs(query)
    if auth=='true':params['apikey']=[key]
    elif auth=='wrong':params['apikey']=['invalid-diagnostic-key']
    url='http://127.0.0.1:8090/'+endpoint+'?'+urllib.parse.urlencode(params,doseq=True)
    try:
     response=urllib.request.urlopen(url,timeout=8);status=response.status;body=response.read(250001).decode('utf-8',errors='replace')
    except urllib.error.HTTPError as e:
     status=e.code;body=e.read(250001).decode('utf-8',errors='replace')
    except Exception as e:
     print(json.dumps({'errorType':type(e).__name__}));sys.exit(1)
    print(json.dumps({'httpStatus':status,'body':body[:250000].replace(key,'[REDACTED]'),'truncated':len(body)>250000}))
    '''
        r=run(['docker','exec',cid,'python3','-c',native_python(code),endpoint,urllib.parse.urlencode(params or {}),str(auth).lower()],12)
        try:value=json.loads(r['stdout'])
        except Exception:value={'malformed':True}
        value['truncated']=r['truncated'] or value.get('truncated',False)
        value.update({'processExitCode':r['exitCode'],'endpoint':endpoint,'parameters':params or {}})
        try:value['json']=json.loads(value.get('body',''))
        except Exception:pass
        save(name,value)
        return value

    def success(value):
        return value.get('processExitCode')==0 and value.get('httpStatus')==200 and not value.get('truncated') and value.get('json',{}).get('Result')=='OK'

    def pod_identity(raw):
        return sorted((p['metadata']['uid'],sorted((c['name'],c['ready'],c['restartCount']) for c in p['status'].get('containerStatuses',[]))) for p in json.loads(raw)['items'])

    try:
        assert preflight['status']=='PASS'
        before=json.loads((evidence_dir/'before.json').read_text())
        for name,args in {'containers':['docker','ps','-a','--no-trunc','--format','{{.ID}}'], 'networks':['docker','network','ls','--no-trunc','--format','{{.ID}}']}.items():
            assert sorted(check(args).splitlines())==sorted(before[name]['stdout'].splitlines()),'Pre-import inventory changed'
        assert pod_identity(check(['kubectl','get','pods','-n','cloudsentinel-p-17','-o','json']))==pod_identity(before['project17']['stdout'])
        check(['curl','--max-time','5','--fail','--silent','http://127.0.0.1:3000/api/health']);check(['pg_isready']);check(['minikube','status'])
        assert TAG not in check(['docker','image','ls','--format','{{.Repository}}:{{.Tag}}']).splitlines()
        assert OWNER not in check(['docker','ps','-a','--format','{{.Names}}']).splitlines()
        digest=hashlib.sha256()
        with open(ARCHIVE,'rb') as archive_file:
            for chunk in iter(lambda:archive_file.read(8388608),b''):digest.update(chunk)
        assert digest.hexdigest()=='3e3604f70c39e65b2637e179b1fc2835c7165e3ff7cc53636f07c3fb01e125f8','ARCHIVE_CHANGED'
        import_attempted=True
        loaded=run(['docker','image','load','--input',ARCHIVE],180);save('import',loaded)
        assert loaded['exitCode']==0,'Image import failed'
        imported=json.loads(check(['docker','image','inspect',TAG]))[0]
        save('imported-image',imported)
        image=imported['Id']
        with tarfile.open(ARCHIVE) as outer:
            record,=json.load(outer.extractfile('manifest.json'));raw=outer.extractfile(record['Config']).read();config=json.loads(raw)
        assert 'sha256:'+hashlib.sha256(raw).hexdigest()==expected['imageConfigId']
        assert imported['Config']==config['config'] and imported['RootFS']['Layers']==config['rootfs']['diff_ids']
        assert imported['Architecture']=='amd64' and imported['Os']=='linux'
        assert image==contracts['expectedImportedImageId'] and imported['Descriptor']['digest']==image
        result.update({'import':'PASS','imageId':image,'configDigest':expected['imageConfigId']})
        start=['docker','run','--detach','--pull=never','--name',OWNER,'--label','cloudsentinel.owner='+OWNER,'--label','cloudsentinel.role=zap-initialization-diagnostic',
            '--network','none','--read-only','--user','1000:1000','--cap-drop','ALL','--security-opt','no-new-privileges:true',
            '--pids-limit','128','--memory','1536m','--cpus','1','--hostname',OWNER,'--add-host',OWNER+':127.0.0.1',
            '--tmpfs','/tmp:rw,noexec,nosuid,nodev,size=64m,uid=1000,gid=1000,mode=1777',
            '--tmpfs','/home/zap/.ZAP:rw,noexec,nosuid,nodev,size=256m,uid=1000,gid=1000,mode=0700',
            '--tmpfs','/zap/wrk:rw,noexec,nosuid,nodev,size=64m,uid=1000,gid=1000,mode=0700',
            '--tmpfs',writable['profilePath']+':rw,noexec,nosuid,nodev,size=4m,uid=1000,gid=1000,mode=0700',
            '--entrypoint','/bin/sh',image,'-c',
            'umask 077; '+shlex.join(profile_seed_arguments(writable))+' || exit 1; '+shlex.join(jvm_seed_arguments(writable))+' || exit 1; k=$(head -c 32 /dev/urandom | sha256sum | cut -d" " -f1); printf "%s" "$k" >/tmp/.key; exec zap.sh -silent -daemon -host 127.0.0.1 -port 8090 -config oast.callback.localaddr=127.0.0.1 -config api.disablekey=false -config api.key="$k" -config autoupdate.checkOnStart=false -config autoupdate.downloadNewRelease=false -config autoupdate.installAddonUpdates=false -dir /home/zap/.ZAP']
        cid=check(start,30).strip()
        observed=json.loads(check(['docker','inspect',cid]))[0];save('container-inspection',observed)
        save('configuration-verification',validate_inspection(observed,cid,image,OWNER))
        assert observed['Config']['Labels'].get('cloudsentinel.role')=='zap-initialization-diagnostic','Diagnostic role mismatch'
        deadline=time.monotonic()+120
        while True:
            version=api('version','JSON/core/view/version/')
            if version.get('json',{}).get('version')=='2.17.0':break
            if time.monotonic()>deadline:raise RuntimeError('ZAP version readiness deadline exceeded')
            if not json.loads(check(['docker','inspect',cid]))[0]['State']['Running']:raise RuntimeError('Daemon exited during startup')
            time.sleep(2)
        result['daemonStartup']='PASS'
        # Poll only readiness observations; never retry provisioning or a failed action.
        initialization_deadline=time.monotonic()+90
        while True:
            installed=api('installed-addons','JSON/autoupdate/view/installedAddons/')
            scanners=api('scanner-inventory','JSON/ascan/view/scanners/')
            observed_ids={str(x['id']) for x in scanners.get('json',{}).get('scanners',[])}
            initialization_logs=run(['docker','logs',cid])
            if REQUIRED<=observed_ids and 'Extensions loaded' in initialization_logs['stdout']+initialization_logs['stderr']:break
            if time.monotonic()>initialization_deadline:break
            time.sleep(2)
        addons=installed.get('json',{}).get('installedAddons',[])
        ids={str(x['id']) for x in scanners.get('json',{}).get('scanners',[])}
        wanted=expected['selected']
        result['selectedInstalledAddons']={a['id']:{'version':a['version'],'installationStatus':a['installationStatus']} for a in addons if a['id'] in wanted}
        result['missingInstalledAddons']=sorted(set(wanted)-set(result['selectedInstalledAddons']))
        result['scannerIds']=sorted(ids);result['requiredRuleIdsObserved']=sorted(REQUIRED&ids);result['missingRuleIds']=sorted(REQUIRED-ids)
        collect='''import os,glob,json,stat,hashlib,xml.etree.ElementTree as ET
    home='/home/zap/.ZAP';v=os.statvfs(home);st=os.stat(home);total=0;allocated=0;files=0
    for root,dirs,names in os.walk(home,followlinks=False):
     for name in names:
      f=os.lstat(os.path.join(root,name))
      if stat.S_ISREG(f.st_mode):total+=f.st_size;allocated+=f.st_blocks*512;files+=1
    policy={'path':home+'/policies/Default Policy.policy','xmlParsed':False,'complete':False}
    try:
     data=open(policy['path'],'rb').read(1048577);policy['bytes']=len(data);policy['sha256']=hashlib.sha256(data).hexdigest()
     if len(data)>1048576:raise ValueError('policy too large')
     ET.fromstring(data);policy['xmlParsed']=True;policy['complete']=True
    except Exception as e:policy['errorType']=type(e).__name__
    heap=[]
    for path in glob.glob('/proc/[0-9]*/cmdline'):
     try:
      args=open(path,'rb').read().split(b'\\0')
      if any(a.endswith(b'java') for a in args[:1]):heap.extend(a.decode() for a in args if a.startswith(b'-Xmx'))
     except OSError:pass
    print(json.dumps({'storage':{'homeCapacityBytes':v.f_blocks*v.f_frsize,'homeAvailableBytes':v.f_bavail*v.f_frsize,'usedFilesystemBytes':(v.f_blocks-v.f_bfree)*v.f_frsize,'regularFileBytes':total,'allocatedFileBytes':allocated,'fileCount':files,'uid':st.st_uid,'gid':st.st_gid,'mode':format(stat.S_IMODE(st.st_mode),'04o'),'homeWritable':os.access(home,os.W_OK)},'policy':policy,'observedJavaHeapArguments':heap}))
    '''
        actual=json.loads(check(['docker','exec',cid,'python3','-c',native_python(collect)]));save('storage-policy-heap',actual)
        logs=run(['docker','logs',cid]);save('initialization-logs',logs)
        text=logs['stdout']+'\n'+logs['stderr']
        errors={'enospc':bool(re.search(r'No space left on device|ENOSPC|Disk quota exceeded',text,re.I)),
          'policyParsing':bool(re.search(r'Premature end of file|SAXParseException|Error parsing.*[.]policy',text,re.I)),
          'preferences':bool(re.search(r"Couldn't create user preferences directory|User preferences are unusable|BackingStoreException",text)),
          'otherInitializationErrors':bool(re.search(r'\bERROR\b|Failed to install|Failed to initialise|Failed to initialize|Exception',text))}
        result['initializationErrors']=errors;result['storage']=actual['storage'];result['observedJavaHeapArguments']=actual['observedJavaHeapArguments']
        result['policyXml']=actual['policy']
        native_code=observation_source+'\nprint(json.dumps(collect_writable_observations(json.loads(sys.argv[1]))))'
        writable_observed=json.loads(check(['docker','exec',cid,'python3','-c',native_code,json.dumps(writable)]));save('writable-paths-and-listeners',writable_observed)
        binding=writable_observed['listeners'];save('listener',binding)
        result['capabilities']['loopbackBinding']='PASS' if binding['complete'] and not binding.get('errorCode') else 'UNVERIFIED'
        profile_detail_code="""import os,json,stat,hashlib
    p='/home/zap/.mozilla/firefox/1337hack.zap-client-profile/extension-preferences.json'
    r={'path':p,'exists':False}
    try:
     s=os.lstat(p);d=open(p,'rb').read(65537);r.update({'exists':True,'regular':stat.S_ISREG(s.st_mode),'uid':s.st_uid,'gid':s.st_gid,'bytes':s.st_size,'bounded':len(d)<=65536,'validJson':isinstance(json.loads(d),dict),'sha256':hashlib.sha256(d).hexdigest()})
    except Exception as e:r['errorType']=type(e).__name__
    print(json.dumps(r))"""
        profile_detail=json.loads(check(['docker','exec',cid,'python3','-c',native_python(profile_detail_code)]));save('actual-client-profile',profile_detail)
        result['firefoxProfile']='PASS' if profile_detail.get('exists') and profile_detail.get('regular') and profile_detail.get('uid')==1000 and profile_detail.get('validJson') and profile_detail.get('bounded') else 'FAIL'
        result['writableObservations']=writable_observed
        actual['storage']['profile']=writable_observed['profile'];actual['storage']['javaPreferences']=writable_observed['javaPreferences']
        norm=lambda version:tuple(int(x) for x in str(version).split('.'))+(0,)*(3-len(str(version).split('.')))
        versions_ok=all(len([a for a in addons if a['id']==name and a['installationStatus']=='INSTALLED' and norm(a['version'])==norm(item['version'])])==1 for name,item in wanted.items())
        initialized=(not any(errors.values()) and not logs['truncated'] and len(text.encode())<=1048576
          and 'Extensions loaded' in text and 'ZAP is now listening on 127.0.0.1:8090' in text
          and actual['policy']['xmlParsed'] and actual['policy']['complete'] and versions_ok and not REQUIRED-ids
          and actual['storage']['homeAvailableBytes']>=32*1024*1024 and actual['observedJavaHeapArguments']==['-Xmx512m']
          and actual['storage']['homeCapacityBytes']==256*1024*1024 and actual['storage']['uid']==1000 and actual['storage']['gid']==1000
          and actual['storage']['mode']=='0700' and actual['storage']['homeWritable']
          and binding['complete'] and not binding.get('errorCode')
          and writable_observed['profile'].get('seedSha256')==writable['profileSeed']['sha256']
          and writable_observed['profile'].get('capacityBytes')==4*1024*1024
          and writable_observed['profile'].get('mode')=='0700' and writable_observed['profile'].get('uid')==1000 and writable_observed['profile'].get('gid')==1000
          and writable_observed['profile'].get('writable') is True
          and writable_observed['javaPreferences'].get('rootProperty')==writable['javaPreferencesRoot']
          and writable_observed['javaPreferences'].get('mode')=='0700' and writable_observed['javaPreferences'].get('uid')==1000
          and writable_observed['javaPreferences'].get('gid')==1000 and writable_observed['javaPreferences'].get('writable') is True
          and result['firefoxProfile']=='PASS'
          and not re.search(r"Couldn't create user preferences directory|User preferences are unusable|BackingStoreException",text))
        result['initialization']='PASS' if initialized else 'FAIL'
        def health():
            current=json.loads(check(['docker','inspect',cid]))[0]
            version=api('auth-health-version','JSON/core/view/version/')
            native=json.loads(check(['docker','exec',cid,'python3','-c',native_code,json.dumps(writable)]))
            return {'running':current['State']['Running'] is True,'identityMatches':current['Id']==cid and current['Image']==image and current['Config']['Labels'].get('cloudsentinel.owner')==OWNER,
                    'loopbackOnly':native['listeners']['complete'] and not native['listeners'].get('errorCode'), 'version':version.get('json',{}).get('version')}
        def read_report(path,timeout=12):
            assert path=='/zap/wrk/empty-diagnostic.json' and timeout==12
            code="import os,stat,sys;p=sys.argv[1];s=os.lstat(p);assert stat.S_ISREG(s.st_mode) and s.st_uid==1000;f=os.open(p,os.O_RDONLY|os.O_NOFOLLOW);d=os.read(f,250001);os.close(f);assert len(d)<=250000;sys.stdout.write(d.decode())"
            return check(['docker','exec',cid,'python3','-I','-c',code,path],timeout)
        def automation():
            code="const m=require('./backend/services/dastActiveScanner');console.log(JSON.stringify(['/test/sqli','/test/xss'].map(p=>m.automationPlan('http://diagnostic-fixture.test:18080'+p))));"
            out=subprocess.run(['node','-e',code],cwd=str(ROOT),capture_output=True,text=True,timeout=12)
            if out.returncode!=0:return False
            evidence=json.loads((ROOT/'backend/config/zap-diagnostic-contracts.json').read_text())
            return validate_automation(json.loads(out.stdout),evidence)
        diagnostic=run_diagnostic(api,health,lambda:run(['docker','logs',cid]),read_report,automation,initialized)
        result['diagnostic']=diagnostic
    except Exception as e:
        result['error']=str(e)[:1000] or type(e).__name__
    finally:
        cleaning=True
        # Every cleanup branch is independent. Ownership failure prevents removal,
        # but cannot skip postflight or erase the diagnostic's failed verdict.
        cleanup_errors=[]
        try:
            if not cid:
                probe=run(['docker','container','inspect',OWNER])
                if probe['exitCode']==0:
                    candidate=json.loads(probe['stdout'])[0]
                    if candidate['Config']['Labels'].get('cloudsentinel.owner')==OWNER:cid=candidate['Id']
                    else:raise RuntimeError('CLEANUP_OWNERSHIP_MISMATCH')
            if cid:
                save('final-daemon-logs',run(['docker','logs',cid]))
                current=json.loads(check(['docker','inspect',cid]))[0]
                assert current['Id']==cid and current['Config']['Labels'].get('cloudsentinel.owner')==OWNER and current['Image']==image
                assert current['Config']['Labels'].get('cloudsentinel.role')=='zap-initialization-diagnostic'
                removed=run(['docker','rm','--force',cid],30);save('container-cleanup',removed)
                if removed['exitCode']!=0:raise RuntimeError('CONTAINER_CLEANUP_FAILED')
        except Exception as error:cleanup_errors.append({'stage':'container','category':type(error).__name__})
        try:
            if import_attempted:
                inspected=run(['docker','image','inspect',TAG])
                if inspected['exitCode']==0:
                    target=json.loads(inspected['stdout'])[0]
                    users=check(['docker','ps','-a','--filter','ancestor='+target['Id'],'--format','{{.ID}}']).strip()
                    assert target['RepoTags']==[TAG] and not users and target['Id']==contracts['expectedImportedImageId'] and (image is None or target['Id']==image)
                    removed=run(['docker','image','rm',TAG],30);save('image-cleanup',removed)
                    if removed['exitCode']!=0:raise RuntimeError('IMAGE_CLEANUP_FAILED')
        except Exception as error:cleanup_errors.append({'stage':'image','category':type(error).__name__})
        try:
            before=json.loads((evidence_dir/'before.json').read_text());after={}
            commands={'docker':['docker','info','--format','{{.ServerVersion}}'],'containers':['docker','ps','-a','--no-trunc','--format','{{.ID}}'],'networks':['docker','network','ls','--no-trunc','--format','{{.ID}}'],'backend':['curl','--max-time','5','--fail','--silent','http://127.0.0.1:3000/api/health'],'postgres':['pg_isready'],'minikube':['minikube','status','-o','json'],'project17':['kubectl','get','pods','-n','cloudsentinel-p-17','-o','json']}
            for key,args in commands.items():after[key]=run(args)
            save('after',after)
            inventory=all(after[k]['exitCode']==0 and sorted(before[k]['stdout'].splitlines())==sorted(after[k]['stdout'].splitlines()) for k in ('containers','networks'))
            pods=pod_identity(before['project17']['stdout'])==pod_identity(after['project17']['stdout'])
            health_ok=all(after[k]['exitCode']==0 for k in ('docker','backend','postgres','minikube','project17'))
            residual=check(['docker','ps','-a','--filter','label=cloudsentinel.owner='+OWNER,'--format','{{.ID}}']).splitlines()
            if import_attempted:
                missing=run(['docker','image','inspect',TAG])
                assert missing['exitCode']!=0 and 'No such image' in missing['stderr'],'TEMPORARY_IMAGE_RESIDUAL'
            result.update({'inventoryUnchanged':inventory,'project17Unchanged':pods,'healthAfter':health_ok,'residualOwnedContainers':residual})
            if not inventory or not pods or not health_ok or residual:raise RuntimeError('POSTFLIGHT_FAILED')
        except Exception as error:cleanup_errors.append({'stage':'postflight','category':type(error).__name__})
        cleaned=check_result('FAIL' if cleanup_errors else 'PASS','OWNERSHIP_AND_INDEPENDENT_INVENTORY_CHECKS')
        result['cleanupErrors']=cleanup_errors;result['cleanup']=cleaned
        if diagnostic is None:
            checks={name:check_result('NOT_RUN','RUNTIME_PRECONDITION_FAILED') for name in MANDATORY}
            checks['initialization']=check_result('FAIL','RUNTIME_PRECONDITION_FAILED')
            diagnostic={'checks':checks,'diagnosticOnly':True,'activeExecutionReady':False}
        diagnostic['cleanup']=cleaned
        status=final_status(diagnostic['checks'],cleaned)
        if result.get('error') and status=='PASS':status='FAIL'
        diagnostic.update({'status':status,'exitCode':EXIT_CODES[status]})
        result.update({'status':status,'exitCode':EXIT_CODES[status],'diagnostic':diagnostic,'runtimeCapabilityReadiness':'BLOCKED','activeEnabled':False})
        save('result',result)
        print(json.dumps(result,indent=2))
    return result['exitCode']

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute',action='store_true')
    parser.add_argument('--evidence-dir',type=Path)
    args=parser.parse_args()
    if not args.execute or args.evidence_dir is None:
        parser.error('Explicit --execute and fresh private --evidence-dir are required')
    try:
        exit_code=main(args.evidence_dir)
    except Exception:
        import json
        print(json.dumps({'status':'BLOCKED','exitCode':3,'diagnosticOnly':True,'activeExecutionReady':False,'error':'INVALID_OR_MISSING_PRIVATE_PREFLIGHT'}))
        exit_code=3
    raise SystemExit(exit_code)
