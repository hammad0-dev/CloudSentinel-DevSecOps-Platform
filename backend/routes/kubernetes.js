const router=require('express').Router();
const auth=require('../middleware/auth');
const pool=require('../db');
const {projectInventory}=require('../services/kubernetesInventory');
const {projectRbac}=require('../services/kubernetesRbac');
const {projectPolicies}=require('../services/kubernetesPolicy');
const {projectUsage}=require('../services/kubernetesUsage');
router.use(auth);
const handler=(load,unavailable)=>async(req,res)=>{
 res.set('Cache-Control','no-store');
 try{const r=await load(pool,req.user.id,req.params.projectId||req.query.projectId);res.status(r.code).json(r.body);}
 catch{res.status(503).json({error:unavailable});}
};
const read=handler(projectInventory,'Kubernetes inventory unavailable');
router.get('/projects/:projectId/inventory',read);
router.get('/summary',read);
// Module 10 FE-3: namespace Roles/RoleBindings with wildcard and cluster-admin flags.
router.get('/projects/:projectId/rbac',handler(projectRbac,'Kubernetes RBAC unavailable'));
// Module 10: Kyverno ClusterPolicies, PolicyReport results and blocked admissions.
router.get('/projects/:projectId/policies',handler(projectPolicies,'Kubernetes policy reports unavailable'));
// SRS FR-16.2: CPU and memory from metrics-server (cluster nodes and the project's pods), or an honest unavailable state.
router.get('/projects/:projectId/usage',handler((pool,userId,id)=>projectUsage(pool,userId,id),'Kubernetes usage unavailable'));
// Legacy demo scan wrote fabricated compliance records. Inventory is read-only.
router.post('/scan',(req,res)=>res.status(410).json({error:'Use project-scoped read-only inventory; security scan is not configured'}));
module.exports=router;
