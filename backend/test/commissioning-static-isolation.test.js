'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('fs'),os=require('os'),path=require('path'),vm=require('vm');
const {createRequire}=require('module');
const checkout=require('../services/commissioningCheckout');
const context={projectId:11,executionId:101,userId:3};
function temporary(t){const root=fs.mkdtempSync(path.join(os.tmpdir(),'cs-checkout-test-'));t.after(()=>fs.rmSync(root,{recursive:true,force:true}));return root;}
test('concurrent commissioning checkouts are unique, private and cleaned without touching siblings',t=>{
 const root=temporary(t),a=checkout.create(root,context),b=checkout.create(root,{...context,executionId:102}),c=checkout.create(root,context);
 assert.equal(new Set([a.target,b.target,c.target]).size,3);
 fs.writeFileSync(path.join(root,'unrelated'),'keep');
 for(const r of [a,b,c]){assert.equal(fs.statSync(path.dirname(r.target)).mode&0o777,0o700);fs.mkdirSync(r.target);fs.writeFileSync(path.join(r.target,'partial'),'data');}
 a.cleanup();a.cleanup();assert(fs.existsSync(b.target));b.cleanup();c.cleanup();assert.equal(fs.readFileSync(path.join(root,'unrelated'),'utf8'),'keep');
});
test('checkout rejects invalid identity, traversal, symlink roots and unsafe ownership',t=>{
 const root=temporary(t);
 for(const c of [{...context,executionId:'../1'},{...context,projectId:17},{...context,userId:0}])assert.throws(()=>checkout.create(root,c));
 assert.throws(()=>checkout.create(root+'/../other',context));
 const link=path.join(root,'link');fs.symlinkSync(root,link);assert.throws(()=>checkout.create(link,context));
 const actual=fs.lstatSync;t.mock.method(fs,'lstatSync',p=>{const s=actual(p);if(p===root)return new Proxy(s,{get:(o,k)=>k==='uid'?process.getuid()+1:Reflect.get(o,k)});return s;});
 assert.throws(()=>checkout.create(root,context));
});
test('cleanup refuses substituted directory and never follows repository symlinks',t=>{
 const root=temporary(t),r=checkout.create(root,context),dir=path.dirname(r.target),outside=path.join(root,'outside');fs.mkdirSync(outside);fs.writeFileSync(path.join(outside,'keep'),'safe');
 fs.mkdirSync(r.target);fs.symlinkSync(outside,path.join(r.target,'link'));r.cleanup();assert(fs.existsSync(path.join(outside,'keep')));
 const replaced=checkout.create(root,context),original=path.dirname(replaced.target);fs.renameSync(original,original+'-saved');fs.symlinkSync(outside,original);assert.throws(()=>replaced.cleanup());assert(fs.existsSync(path.join(outside,'keep')));
});
function loadOrchestrator({commissioning,failStage,critical=false}){
 const filename=require.resolve('../services/orchestrator'),local=createRequire(filename),calls=[],queries=[],claims=[];let sleeps=0;
 const pool={async query(sql){queries.push(sql);if(sql.includes('FROM scan_history sh'))return {rows:[{critical:critical?1:0,high:0,medium:0,low:0,total_issues:critical?1:0,persisted_total:critical?1:0,distinct_total:critical?1:0,security_critical:critical?1:0,security_high:0,hotspots_pending:0,unknown_types:0,persisted_critical:critical?1:0,persisted_high:0,persisted_medium:0,persisted_low:0}]};if(sql.startsWith('SELECT critical'))return {rows:[{critical:0}]};return {rows:[],rowCount:1};}};
 const stubs={'axios':{async post(url){calls.push(url);if(url.includes('/'+failStage+'/'))throw Error('offline stage failure');return {data:{}};}},'jsonwebtoken':{sign(c){claims.push(c);return 'offline-token';}},'./activeDastCommissioning':{selection(){return commissioning?context:null;}},'./commissioningFixtureStage':{async prepare(){calls.push('fixture');return {fixtureOnly:true,stagingUrl:'http://fixture.test:18080'};},async verify(){},has(){return false;},release(){}},'./commissioningPhases':{async pause(){calls.push('pause');},async failSetup(){}},'./activeRuntimeRegistry':{async cancelPending(){return {cleaned:true};}},'./deployment':{},'../db':pool};
 const module={exports:{}};vm.runInNewContext(fs.readFileSync(filename,'utf8'),{module,exports:module.exports,require:id=>Object.hasOwn(stubs,id)?stubs[id]:local(id),process:{env:{JWT_SECRET:'offline',DAST_ACTIVE_ENABLED:'false'}},console:{log(){},error(){},warn(){}},setTimeout(fn){sleeps++;fn();}});
 return {run:()=>module.exports.runPipeline(context.executionId,context.projectId,context.userId),calls,queries,claims,sleeps:()=>sleeps};
}
for(const phase of ['PASSIVE_SETUP','ACTIVE_COMMISSIONING'])for(const stage of ['sast','dependencies','iac'])test(`${phase}: ${stage} failure is attempted once and stops remaining stages`,async()=>{
 const h=loadOrchestrator({commissioning:{...context,phase},failStage:stage});await h.run();assert.equal(h.calls.filter(u=>u.includes('/'+stage+'/')).length,1);assert.equal(h.sleeps(),0);assert(!h.calls.includes('fixture'));assert(h.claims.every(c=>c.commissioningStaticStage===true));assert(h.queries.some(s=>s.includes("status = 'ERROR'")));
});
test('ordinary pipeline keeps its two static-stage attempts and retry delay',async()=>{const h=loadOrchestrator({commissioning:false,failStage:'sast'});await h.run();assert.equal(h.calls.length,2);assert.equal(h.sleeps(),1);assert(h.claims.every(c=>!Object.hasOwn(c,'commissioningStaticStage')));});
test('commissioning keeps ordered static gates and pauses without Active execution',async()=>{const h=loadOrchestrator({commissioning:true});await h.run();assert.deepEqual(h.calls.map(x=>x.startsWith('http')?x.split('/api/')[1].split('/')[0]:x),['sast','dependencies','iac','fixture','pause']);});
test('critical SAST gate stops before dependency, IaC and fixture',async()=>{const h=loadOrchestrator({commissioning:true,critical:true});await h.run();assert.equal(h.calls.length,1);assert(h.queries.some(s=>s.includes("status = 'STAGE_FAILED'")));});
function loadSast(t,{failure,commissioning=true}){
 const filename=require.resolve('../routes/sast'),local=createRequire(filename),root=temporary(t);let handler,target;
 const selection=require('../services/activeDastCommissioning');t.mock.method(selection,'selection',()=>commissioning?context:null);
 const actualConfig=local('./config');
 const stubs={'express':{Router(){return {post(route,...args){handler=args.at(-1);},get(){}};}},'../../db':{async query(sql){if(sql.startsWith('SELECT * FROM projects'))return {rows:[{id:11,user_id:3,repo_url:'https://example.invalid/owned.git'}]};if(sql.startsWith('INSERT INTO scan_history'))return {rows:[{id:99}]};return {rows:[]};}},'../../services/pipelineExecutionContext':{async resolvePipelineExecutionId(){return context.executionId;}},'./config':{...actualConfig,async assertSonarReachable(){if(failure==='sonar')throw Error('offline sonar failure');},shouldKeepClone:()=>true},'./pipeline':{resolveCloneUrl:p=>p.repo_url,useShallowGitClone:()=>true,async gitCloneAsync(url,p){target=p;fs.mkdirSync(p);fs.writeFileSync(path.join(p,'file'),'partial');if(failure==='clone')throw Error('offline clone failure');},async buildGradleProjectIfPresent(){return false;},stripSonarProjectPropertiesFromClone(){},detectedGitBranch(){return 'main';},async runSonarScannerAsync(){}},'axios':{async get(url){return {data:url.includes('qualitygates')?{projectStatus:{status:'OK'}}:url.includes('hotspots/search')?{hotspots:[],paging:{total:0}}:url.includes('measures')?{component:{measures:[{metric:'ncloc',value:'1'},{metric:'files',value:'1'}]}}:{issues:[],total:0,paging:{pageIndex:1,pageSize:500,total:0}}};}},'../../services/sastEvidence':{async persistSastEvidence(){return {total:0};}}};
 const module={exports:{}};vm.runInNewContext(fs.readFileSync(filename,'utf8'),{module,exports:module.exports,require:id=>Object.hasOwn(stubs,id)?stubs[id]:local(id),process:{env:{CLONE_DIR:root}},console:{log(){},warn(){},error(){}}});
 return {root,target:()=>target,async run(){const res={headersSent:false,code:200,status(n){this.code=n;return this;},json(v){this.body=v;return this;}};await handler({params:{projectId:'11'},user:{id:3,pipelineOrchestrator:true,commissioningStaticStage:commissioning,pipelineExecutionId:101}},res);return res;}};
}
for(const failure of [null,'sonar','clone'])test(`SAST commissioning checkout cleanup after ${failure||'success'}, ignoring keep-clone`,async t=>{
 const h=loadSast(t,{failure});fs.mkdirSync(path.join(h.root,'11'));fs.writeFileSync(path.join(h.root,'11','keep'),'unrelated');const r=await h.run();assert.equal(r.code,failure?500:200);assert.deepEqual(fs.readdirSync(h.root),['11']);assert.equal(fs.readFileSync(path.join(h.root,'11','keep'),'utf8'),'unrelated');if(h.target())assert(h.target().includes('cs-p11-e101-u3-'));
});
test('ordinary SAST preserves existing checkout and keep-clone behavior',async t=>{const h=loadSast(t,{commissioning:false});const r=await h.run();assert.equal(r.code,200);assert.equal(h.target(),path.join(h.root,'11'));assert(fs.existsSync(h.target()));});
test('expired or unselected signed commissioning context fails before allocating a checkout',t=>{t.mock.method(require('../services/activeDastCommissioning'),'selection',()=>null);assert.throws(()=>checkout.required({pipelineOrchestrator:true,commissioningStaticStage:true},context));assert.equal(checkout.required({pipelineOrchestrator:true},context),false);});
test('SAST cleanup ownership failure fails the request and preserves unrelated files',async t=>{
 const h=loadSast(t,{failure:'clone'}),real=checkout.create;
 t.mock.method(checkout,'create',(...args)=>{const r=real(...args);return {target:r.target,cleanup(){throw Error('ownership changed');}};});
 fs.writeFileSync(path.join(h.root,'unrelated'),'keep');const r=await h.run();assert.equal(r.code,500);assert.equal(r.body.error,'COMMISSIONING_CHECKOUT_CLEANUP_FAILED');assert.equal(fs.readFileSync(path.join(h.root,'unrelated'),'utf8'),'keep');
});
test('cleanup refuses changed directory permissions and changed root identity',t=>{
 const root=temporary(t),r=checkout.create(root,context);fs.chmodSync(path.dirname(r.target),0o755);assert.throws(()=>r.cleanup());fs.chmodSync(path.dirname(r.target),0o700);
 const moved=root+'-moved';fs.renameSync(root,moved);t.after(()=>fs.rmSync(moved,{recursive:true,force:true}));fs.mkdirSync(root,{mode:0o700});fs.writeFileSync(path.join(root,'keep'),'safe');assert.throws(()=>r.cleanup());assert.equal(fs.readFileSync(path.join(root,'keep'),'utf8'),'safe');
});
