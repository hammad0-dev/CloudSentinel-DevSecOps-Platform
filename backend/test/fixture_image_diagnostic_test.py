import copy
import json
from pathlib import Path
import sys
import hashlib
import tempfile
import subprocess
import contextlib
import io
import os
import unittest
from unittest.mock import Mock, patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'scripts'))
import fixture_image_diagnostic as d
import fixture_probe as p
import fixture_runtime_validation as runner
F = json.loads((Path(__file__).parent/'fixtures/fixture-import-cmd-56dqhix6.json').read_text())


def container():
    return {'Id':'a'*64,'Image':F['observedImage']['Id'],'State':{'Running':True},
        'Config':{'User':'10001:10001','Labels':{'cloudsentinel.owner':F['owner'],'cloudsentinel.role':'active-fixture-validation'}},
        'HostConfig':{'NetworkMode':'none','ReadonlyRootfs':True,'Privileged':False,'CapDrop':['ALL'],
        'SecurityOpt':['no-new-privileges:true'],'Memory':268435456,'NanoCpus':1000000000,'PidsLimit':64,
        'PublishAllPorts':False,'Tmpfs':{'/tmp':'rw,noexec,nosuid,nodev,size=16m,uid=10001,gid=10001,mode=0700'}},
        'NetworkSettings':{'Networks':{'none':{}},'Ports':{}},'Mounts':[]}


def probe():
    bodies=['fixture-ready','fixture-ready','[["demo-one"]]','[["demo-two"]]','[["demo-one"],["demo-two"]]',p.CASES['reflection']['query']['q'],'not found']
    return {'targetOrigin':p.ORIGIN,'runtime':{'uid':10001,'gid':10001,'rootFilesystemReadOnly':True,
        'networkInterfaces':['lo'],'appSha256':F['appSha256'],'appDirectoryFiles':['app.py'],
        'appUid':10001,'appGid':10001,'appMode':'0444','effectiveCapabilities':0,'noNewPrivileges':True,
        'tmp':{'capacityBytes':16777216,'uid':10001,'gid':10001,'mode':'0700'},
        'cgroupLimits':{'memoryMax':'268435456','pidsMax':'64','cpuMax':'100000 100000'}},
        'listeners':{'ipv4':[{'address':'0.0.0.0','port':18080,'nativeAddress':'00000000'}],'ipv6':[]},
        'observations':[dict(name=n,**c,body=b,truncated=False,sqliteResidualFiles=[]) for (n,c),b in zip(p.CASES.items(),bodies)]}


class DiagnosticTests(unittest.TestCase):
    def replay(self, **overrides):
        args=dict(imported=copy.deepcopy(F['observedImage']),expected=F['expectedConfig'],layers=F['expectedLayers'],owner=F['owner'],source_hash=F['appSha256'],start=Mock(return_value='a'*64),inspect=Mock(return_value=container()),probe=Mock(return_value=probe()),cleanup=Mock(return_value=True))
        args.update(overrides)
        result=d.replay_validation(**args)
        args['cleanup'].assert_called_once()
        return result

    def test_genuine_import_replay(self):
        original=copy.deepcopy(F)
        self.assertNotIn('Cmd',F['observedImage']['Config'])
        self.assertIsNone(F['expectedConfig']['Cmd'])
        self.assertEqual(self.replay()['status'],'PASS')
        self.assertEqual(F,original)
        self.assertEqual(F['historicalStatus'],'FAIL')

    def test_cmd_only_equivalence(self):
        for a,b in [({}, {'Cmd':None}),({'Cmd':None}, {})]:
            self.assertTrue(d.compare_config(a,b))
        for a,b in [({}, {'Cmd':['real']}),({'Cmd':None},{'Cmd':[]}),({'Cmd':['a']},{'Cmd':['b']}),({}, {'Cmd':''})]:
            with self.subTest(a=a,b=b),self.assertRaises(d.FixtureDiagnosticError):d.compare_config(a,b)

    def test_other_fields_strict(self):
        for field in ['Entrypoint','User','Env','WorkingDir','Labels']:
            changed=copy.deepcopy(F['observedImage']);changed['Config'][field]='changed'
            self.assertEqual(self.replay(imported=changed)['status'],'FAIL')
        with self.assertRaises(d.FixtureDiagnosticError):d.compare_config({}, {'User':None})
        for field,value in [('Architecture','arm64'),('RootFS',{'Layers':[]})]:
            changed=copy.deepcopy(F['observedImage']);changed[field]=value
            self.assertEqual(self.replay(imported=changed)['exitCode'],1)

    def test_security_assertions(self):
        for field,value in [('NetworkMode','bridge'),('ReadonlyRootfs',False),('Memory',1),('NanoCpus',1),('PidsLimit',1),('CapDrop',[]),('SecurityOpt',[]),('Binds',['/host:/tmp']),('Tmpfs',{})]:
            c=container();c['HostConfig'][field]=value
            with self.subTest(field=field):self.assertEqual(self.replay(inspect=Mock(return_value=c))['status'],'FAIL')
        c=container();c['Config']['User']='0:0'
        self.assertEqual(self.replay(inspect=Mock(return_value=c))['status'],'FAIL')

    def test_independent_functional_failures(self):
        for i in range(7):
            value=probe();value['observations'][i]['errorType']='TimeoutError'
            result=self.replay(probe=Mock(return_value=value))
            self.assertEqual(result['status'],'FAIL')
            self.assertNotIn('NOT_RUN', [result['checks'][k] for k in d.CHECKS])
        for key,value in [('uid',0),('networkInterfaces',['lo','eth0']),('appSha256','wrong')]:
            data=probe();data['runtime'][key]=value
            self.assertEqual(self.replay(probe=Mock(return_value=data))['exitCode'],1)
        data=probe();data['listeners']['ipv6']=[{'address':'::','port':18080}]
        self.assertEqual(self.replay(probe=Mock(return_value=data))['status'],'FAIL')
        data=probe();data['observations'][2]['sqliteResidualFiles']=['residual']
        self.assertEqual(self.replay(probe=Mock(return_value=data))['checks']['SQLiteCleanup'],'FAIL')

    def test_cleanup_every_failure(self):
        for stage in ['start','inspect','probe','cleanup']:
            result=self.replay(**{stage:Mock(side_effect=RuntimeError('mock failure'))})
            self.assertNotEqual(result['exitCode'],0)
        self.assertEqual(self.replay(cleanup=Mock(return_value=False))['cleanup'],'FAIL')
        self.assertEqual(d.finish({},True),('BLOCKED',3))
        result=self.replay()
        self.assertTrue(result['diagnosticOnly']);self.assertFalse(result['activeExecutionReady'])

    def test_observer_continues_after_timeout_without_network(self):
        client=Mock();client.open.side_effect=TimeoutError('private detail')
        with patch.object(p,'measure',return_value=probe()['runtime']),patch.object(p.glob,'glob',return_value=[]):
            result=p.collect(F['appSha256'],client)
        self.assertEqual(client.open.call_count,7)
        self.assertTrue(all(r['errorType']=='TimeoutError' for r in result['observations']))
        self.assertNotIn('private detail',json.dumps(result))
        for call in client.open.call_args_list:
            self.assertTrue(call.args[0].startswith(p.ORIGIN+'/'));self.assertEqual(call.kwargs['timeout'],2)

    def test_observer_preconditions_and_payload_compile(self):
        client=Mock()
        with patch.object(p,'measure',return_value={}):self.assertEqual(p.collect(F['appSha256'],client)['observations'],[])
        client.open.assert_not_called()
        compile(runner.native_payload(),'<native fixture payload>','exec')
        with patch.object(runner.subprocess,'run',side_effect=AssertionError('no execution')):
            self.assertTrue(callable(runner.main))

class WrapperTests(unittest.TestCase):
    def test_complete_wrapper_mocked_success_and_failures(self):
        for failure in (None, 'config', 'startup', 'probe', 'cleanup'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temp:
                directory=Path(temp);directory.chmod(0o700)
                state={'loaded':False,'created':False,'final':False}
                pre={'status':'PASS','owner':F['owner'],'sourceHashes':{},'buildTags':['offline:test1','offline:test2'],'finalTag':'offline:verified'}
                before={k:{'stdout':v} for k,v in {'containers':'original\n','networks':'network\n','images':'base\n','project17':'{"items":[]}'}.items()}
                archive=b'offline mock, not a Docker archive';(directory/'fixture-1.tar').write_bytes(archive)
                build={'archiveSha256':hashlib.sha256(archive).hexdigest(),'config':{'config':F['expectedConfig']},'layerDiffIds':F['expectedLayers'],'appSha256':F['appSha256']}
                for name,value in [('preflight',pre),('before',before),('build-1',build),('reproducibility',{'status':'PASS'}),('independent-archive-comparison',{'status':'PASS'})]:
                    (directory/(name+'.json')).write_text(json.dumps(value))
                def fake(args,**kwargs):
                    out='';err='';code=0
                    if args[:3]==['docker','image','load']:state['loaded']=True
                    elif args[:3]==['docker','image','inspect']:
                        if not state['loaded']:code=1;err='No such image'
                        else:
                            image=copy.deepcopy(F['observedImage']);image['RepoTags']=[pre['buildTags'][0]]+([pre['finalTag']] if state['final'] else [])
                            if failure=='config':image['Config']['User']='0'
                            out=json.dumps([image])
                    elif args[:3]==['docker','image','tag']:state['final']=True
                    elif args[:3]==['docker','image','rm']:
                        if not state['final']:state['loaded']=False
                    elif args[:3]==['docker','image','ls']:
                        if '--filter' in args:out=F['observedImage']['Id'] if state['loaded'] else ''
                        elif '--quiet' in args:out='base\n'+(F['observedImage']['Id'] if state['loaded'] else '')
                        else:out=''
                    elif args[:2]==['docker','run']:
                        state['created']=True;out='a'*64
                        if failure=='startup':code=1
                    elif args[:3]==['docker','container','inspect'] or args[:2]==['docker','inspect']:
                        if state['created']:
                            c=container();c['State']['Health']={'Status':'healthy'};out=json.dumps([c])
                        else:code=1;err='No such container'
                    elif args[:2]==['docker','exec']:
                        out=json.dumps(probe())
                        if failure=='probe':code=1
                    elif args[:2]==['docker','rm']:
                        if failure=='cleanup':code=1
                        else:state['created']=False
                    elif args[:2]==['docker','ps']:
                        if '--filter' in args:out='a'*64 if state['created'] else ''
                        elif '{{.Names}}' in args:out=''
                        else:out='original\n'+('a'*64 if state['created'] else '')
                    elif args[:3]==['docker','network','ls']:out='' if '--filter' in args else 'network\n'
                    elif args[:2]==['docker','info']:out='healthy'
                    elif args[0]=='kubectl':out='{"items":[]}'
                    elif args[0] in ('curl','pg_isready','minikube'):out='healthy'
                    else:raise AssertionError('Unmocked command '+repr(args))
                    return subprocess.CompletedProcess(args,code,out,err)
                oldmask=os.umask(0o077)
                try:
                    with patch.object(runner.subprocess,'run',side_effect=fake),contextlib.redirect_stdout(io.StringIO()):
                        code=runner.main(directory)
                finally:os.umask(oldmask)
                result=json.loads((directory/'result.json').read_text())
                self.assertEqual(code,0 if failure is None else 1)
                self.assertEqual(result['cleanup'],'FAIL' if failure=='cleanup' else 'PASS')
                self.assertEqual((directory/'result.json').stat().st_mode & 0o777,0o600)
                self.assertFalse(result['activeExecutionReady'])
                if failure is None:self.assertTrue(all(v=='PASS' for v in result['checks'].values()))

if __name__=='__main__':unittest.main()
