const router=require('express').Router();
const auth=require('../middleware/auth');
const pool=require('../db');
const {projectInventory}=require('../services/kubernetesInventory');
router.use(auth);
async function read(req,res){
 res.set('Cache-Control','no-store');
 try{const r=await projectInventory(pool,req.user.id,req.params.projectId||req.query.projectId);res.status(r.code).json(r.body);}
 catch{res.status(503).json({error:'Kubernetes inventory unavailable'});}
}
router.get('/projects/:projectId/inventory',read);
router.get('/summary',read);
// Legacy demo scan wrote fabricated compliance records. Inventory is read-only.
router.post('/scan',(req,res)=>res.status(410).json({error:'Use project-scoped read-only inventory; security scan is not configured'}));
module.exports=router;
