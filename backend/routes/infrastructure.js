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
  const row=r.rows[0],expiry=Date.parse(row.expiresAt),expired=!Number.isFinite(expiry)||expiry<=Date.now();
  return res.json({executionId:row.executionId,decision:expired?'BLOCKED':row.decision,reasons:expired?['Eligibility expired']:row.evidence.reasons,createdAt:row.createdAt,expiresAt:row.expiresAt,awsDeployment:'NOT_STARTED'});
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
router.post('/:projectId/apply',(req,res)=>handle(req,res,async()=>{const e=new Error('Real apply is disabled');e.safe=true;e.status=409;throw e}));
module.exports=router;
