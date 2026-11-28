'use strict';
const router=require('express').Router(),pool=require('../db'),auth=require('../middleware/auth');
const {Planner,publicRecord,ownedProject}=require('../services/infrastructurePlanning');
const {runPlan,enabled}=require('../services/terraformPlanRunner');
const admission=new (require('../services/signedNetworkAdmission').Admission)();
const reservations=new (require('../services/cidrReservations').Reservations)();
const planner=new Planner({runner:enabled()?runPlan:null});router.use(auth);
async function handle(req,res,operation){
 res.set('Cache-Control','no-store');
 try{
  const project=await ownedProject(pool,req.user.id,req.params.projectId);
  res.json(publicRecord(await operation(project)));
 }catch(e){res.status(e.safe?e.status:503).json({error:e.safe?e.message:'Infrastructure operation unavailable; no infrastructure applied'});}
}
async function adminReview(req,res,operation){res.set('Cache-Control','no-store');try{await admission.administrator(req.user.id);const id=Number(req.params.projectId);if(!Number.isSafeInteger(id)||id<1)throw Object.assign(Error('Invalid project'),{safe:true,status:400});const {rows}=await pool.query('SELECT id,user_id FROM projects WHERE id=$1',[id]);if(!rows.length)return res.status(404).json({error:'Project not found'});res.json(await operation(rows[0]));}catch(e){res.status(e.safe?e.status:503).json({error:e.safe?e.message:'Administrator review unavailable'});}}
router.post('/admin/network-reviews/:projectId/challenge',(req,res)=>adminReview(req,res,p=>admission.challenge(req.user.id,p)));
router.post('/admin/network-reviews/:projectId/admit',(req,res)=>adminReview(req,res,p=>admission.admit(req.user.id,p,req.body)));
router.post('/admin/network-reviews/:projectId/revoke',(req,res)=>adminReview(req,res,p=>admission.revoke(req.user.id,p.id,req.body.reviewId)));
router.get('/:projectId/review-status',(req,res)=>handle(req,res,p=>admission.status(p.id,req.user.id)));
router.get('/:projectId/deployment-eligibility',async(req,res)=>{
 res.set('Cache-Control','no-store');
 try{
  const p=await ownedProject(pool,req.user.id,req.params.projectId);
  const r=await pool.query('SELECT pipeline_execution_id AS "executionId",decision,evidence,created_at AS "createdAt",expires_at AS "expiresAt" FROM deployment_eligibility WHERE project_id=$1 ORDER BY id DESC LIMIT 1',[p.id]);
  if(!r.rows.length)return res.json({decision:'PENDING_EVIDENCE',reasons:['No deployment eligibility evidence recorded'],awsDeployment:'NOT_STARTED'});
  return res.json(require('../services/eligibilityView').view(r.rows[0]));
 }catch(e){res.status(e.safe?e.status:503).json({error:e.safe?e.message:'Deployment eligibility evidence unavailable; deployment blocked'});}
});
router.get('/:projectId', (req,res)=>handle(req,res,p=>planner.get(p.id)));
router.post('/:projectId/analyze',(req,res)=>handle(req,res,p=>planner.analysis(p)));
router.post('/:projectId/cidr-check',(req,res)=>handle(req,res,async()=>require('../services/infrastructureCidr').checkCidr(req.body.cidr)));
router.get('/:projectId/cidrs',(req,res)=>handle(req,res,p=>reservations.proposals(p.id)));
router.post('/:projectId/cidrs/reserve',(req,res)=>handle(req,res,p=>reservations.reserve(p.id,req.user.id,req.body.cidr)));
router.post('/:projectId/cidrs/release',(req,res)=>handle(req,res,p=>reservations.release(p.id,req.user.id,req.body.reservationId)));
router.post('/:projectId/plan',(req,res)=>handle(req,res,p=>planner.plan(p,req.body)));
router.post('/:projectId/approve',(req,res)=>handle(req,res,p=>planner.approve(p,req.user.id,req.body)));
// ---- EKS container workload (Module 8): analyze -> confirm -> plan -> approve -> apply -> destroy-plan -> destroy.
// Apply is real but gated: INFRA_APPLY_ENABLED=true, kill switch off, project not protected, single-use approval of
// the exact plan SHA-256, plan allowlist passed, AWS account 229032674007 / ap-south-1 (services/eksWorkloadEngine.js).
const {WorkloadInfrastructure}=require('../services/eksWorkloadEngine');
const {repositoryFiles}=require('../services/infrastructurePlanning');
const workload=new WorkloadInfrastructure({source:p=>repositoryFiles(p,{withCode:true})});
async function workloadHandle(req,res,operation){
 res.set('Cache-Control','no-store');
 try{const project=await ownedProject(pool,req.user.id,req.params.projectId);res.json(workload.publicRecord(await operation(project)));}
 catch(e){res.status(e.safe?e.status:503).json({error:e.safe?e.message:'Infrastructure operation unavailable; no infrastructure applied'});}
}
router.get('/:projectId/workload',(req,res)=>workloadHandle(req,res,p=>workload.get(p.id)));
router.post('/:projectId/workload/analyze',(req,res)=>workloadHandle(req,res,p=>workload.analyze(p,req.user.id)));
router.post('/:projectId/workload/confirm',(req,res)=>workloadHandle(req,res,p=>workload.confirm(p,req.user.id,req.body)));
router.post('/:projectId/workload/plan',(req,res)=>workloadHandle(req,res,p=>workload.plan(p,req.user.id)));
router.post('/:projectId/workload/approve',(req,res)=>workloadHandle(req,res,p=>workload.approve(p,req.user.id,{hash:req.body?.hash,kind:req.body?.kind==='destroy'?'destroy':'apply'})));
router.post('/:projectId/workload/destroy-plan',(req,res)=>workloadHandle(req,res,p=>workload.destroyPlan(p,req.user.id)));
router.post('/:projectId/workload/destroy',(req,res)=>workloadHandle(req,res,p=>workload.destroy(p,req.user.id)));
// Network-only plans are still never applied. /apply applies the approved EKS workload plan and fails closed with
// "Real apply is disabled: <reasons>" while any gate is closed.
router.post('/:projectId/workload/apply',(req,res)=>workloadHandle(req,res,p=>workload.apply(p,req.user.id)));
router.post('/:projectId/apply',(req,res)=>workloadHandle(req,res,p=>workload.apply(p,req.user.id)));
// ---- Promote to EKS stage settings (services/promoteStage.js): promote_target none|eks, approval manual|auto_after_gates.
async function promoteSettings(req,res,update){
 res.set('Cache-Control','no-store');
 try{
  const p=await ownedProject(pool,req.user.id,req.params.projectId);
  if(update){
   const target=req.body?.promote_target,approval=req.body?.promote_approval??'manual';
   if(!['none','eks'].includes(target)||!['manual','auto_after_gates'].includes(approval))return res.status(400).json({error:'promote_target must be none|eks and promote_approval manual|auto_after_gates'});
   await pool.query('UPDATE projects SET promote_target=$1,promote_approval=$2 WHERE id=$3 AND user_id=$4',[target,approval,p.id,req.user.id]);
  }
  res.json(await require('../services/promoteStage').loadSettings(pool,p.id));
 }catch(e){res.status(e.safe?e.status:503).json({error:e.safe?e.message:e.code==='42703'?'Promote settings need migration 024':'Promote settings unavailable'});}
}
router.get('/:projectId/promote-settings',(req,res)=>promoteSettings(req,res,false));
router.put('/:projectId/promote-settings',(req,res)=>promoteSettings(req,res,true));
module.exports=router;
