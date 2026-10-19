"use strict";
const express=require('express');
const pool=require('../db');
const auth=require('../middleware/auth');
const {sync}=require('../services/governance/store');
const {filters,positive,bad,assertProject,list}=require('../services/governance/query');
const {snapshot}=require('../services/governance/analytics');
const {STATUSES}=require('../services/governance/normalize');
const {csv,pdf}=require('../services/governance/report');
const router=express.Router();router.use(auth);
function wrap(fn){return async(req,res)=>{try{await fn(req,res);}catch(e){if(!e.status)console.error('[governance]',e.message);res.status(e.status||(e.code==='42P01'?503:500)).json({error:e.status?e.message:e.code==='42P01'?'Governance schema unavailable. Apply migrations 017 and 018.':'Governance request failed'});}};}
// Read transactions keep counts, charts and downloadable reports internally consistent.
async function read(req,fn) {const f=filters(req.query),db=await pool.connect();try{await db.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');await assertProject(db,req.user.id,f);const result=await fn(db,f);await db.query('COMMIT');return result;}catch(e){await db.query('ROLLBACK');throw e;}finally{db.release();}}
router.post('/sync',wrap(async(req,res)=>res.json(await sync(pool,req.user.id))));
router.get('/findings',wrap(async(req,res)=>res.json(await read(req,(db,f)=>list(db,req.user.id,f)))));
router.get('/summary',wrap(async(req,res)=>{const s=await read(req,(db,f)=>snapshot(db,req.user.id,f));delete s.findings;res.json(s);}));
router.get('/compliance',wrap(async(req,res)=>res.json(await read(req,async(db,f)=>(await snapshot(db,req.user.id,f)).compliance))));
router.get('/compliance/controls/:controlId',wrap(async(req,res)=>{
 const {cis,docker}=require('../services/governance/registry');
 const control=cis.find(c=>c.id===req.params.controlId);if(!control)throw bad('Unsupported control');
 const result=await read(req,async(db,f)=>{
  const {scope}=require('../services/governance/query');const s=scope(req.user.id,f);
  const conditions=`${s.where} AND g.source='IAC' AND a.benchmark_id=$${s.params.length+1} AND a.control_id=$${s.params.length+2}`;
  const parameters=[...s.params,docker.id,control.id];
  const from=`FROM governance_control_assessments a JOIN governance_configuration_targets t ON t.id=a.target_id JOIN governance_scans g ON g.id=t.governance_scan_id JOIN projects p ON p.id=g.project_id WHERE ${conditions}`;
  const total=Number((await db.query(`SELECT COUNT(*) AS total ${from}`,parameters)).rows[0].total);
  const history=(await db.query(`SELECT a.*,t.resource,g.project_id,p.name AS project_name,g.scan_id,g.scanned_at ${from} ORDER BY g.scanned_at DESC,a.id DESC LIMIT $${parameters.length+1} OFFSET $${parameters.length+2}`,[...parameters,f.pageSize,(f.page-1)*f.pageSize])).rows;
  const current=(await snapshot(db,req.user.id,f)).compliance;
  return {control,current:current.projectControls.filter(c=>c.id===control.id),history,total,page:f.page,pageSize:f.pageSize};
 });res.json(result);
}));
router.get('/findings/:id',wrap(async(req,res)=>{
 const id=positive(req.params.id,'finding id');
 const finding=(await pool.query('SELECT f.*,p.name AS project_name FROM governance_findings f JOIN projects p ON p.id=f.project_id WHERE f.id=$1 AND p.user_id=$2',[id,req.user.id])).rows[0];
 if(!finding)return res.status(404).json({error:'Finding not found'});
 const observations=(await pool.query(`SELECT o.source_record_id,o.observed_at,o.evidence,g.source,g.scan_id,g.details_complete FROM governance_observations o JOIN governance_scans g ON g.id=o.governance_scan_id JOIN projects p ON p.id=g.project_id WHERE o.finding_id=$1 AND p.user_id=$2 ORDER BY o.observed_at DESC`,[id,req.user.id])).rows;
 const history=(await pool.query(`SELECT h.old_status,h.new_status,h.reason,h.changed_at FROM governance_status_history h JOIN governance_findings f ON f.id=h.finding_id JOIN projects p ON p.id=f.project_id WHERE f.id=$1 AND p.user_id=$2 ORDER BY h.id DESC`,[id,req.user.id])).rows;
 res.json({finding,observations,history});
}));
router.patch('/findings/:id/status',wrap(async(req,res)=>{
 const id=positive(req.params.id,'finding id'),status=req.body.status,reason=req.body.reason;
 if(!STATUSES.includes(status)||typeof reason!=='string'||reason.trim().length<3||reason.length>1000)throw bad('Valid status and a review reason (3-1000 characters) required');
 const db=await pool.connect();try{
  await db.query('BEGIN');
  const found=(await db.query('SELECT f.id,f.status FROM governance_findings f JOIN projects p ON p.id=f.project_id WHERE f.id=$1 AND p.user_id=$2 FOR UPDATE OF f',[id,req.user.id])).rows[0];
  if(!found)throw Object.assign(Error('Finding not found'),{status:404});
  await db.query('UPDATE governance_findings SET status=$1 WHERE id=$2',[status,id]);
  await db.query('INSERT INTO governance_status_history(finding_id,user_id,old_status,new_status,reason) VALUES($1,$2,$3,$4,$5)',[id,req.user.id,found.status,status,require('../services/governance/normalize').clean(reason.trim())]);
  await db.query('COMMIT');res.json({id,status});
 }catch(e){await db.query('ROLLBACK');throw e;}finally{db.release();}
}));
router.get('/export/:kind',wrap(async(req,res)=>{
 const kind=req.params.kind;if(!['security','compliance','csv','compliance-csv'].includes(kind))throw bad('Invalid report kind');
 const data=await read(req,(db,f)=>snapshot(db,req.user.id,f));
 res.set('Cache-Control','no-store');
 res.set('Content-Disposition',`attachment; filename="cloudsentinel-${kind}.${kind.endsWith('csv')?'csv':'pdf'}"`);
 if(kind==='csv')res.type('text/csv').send(csv(data.findings));else if(kind==='compliance-csv')res.type('text/csv').send(require('../services/governance/report').complianceCsv(data));else res.type('application/pdf').send(await pdf(data,kind));
}));
module.exports=router;
