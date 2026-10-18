const router=require('express').Router();
const auth=require('../middleware/auth');
const pool=require('../db');
const {projectNetwork}=require('../services/cloudNetwork');
router.use(auth);
router.get('/projects/:projectId/network',async(req,res)=>{
 res.set('Cache-Control','no-store');
 try{const result=await projectNetwork(pool,req.user.id,req.params.projectId);res.status(result.code).json(result.body);}
 catch{res.status(503).json({error:'Cloud inventory unavailable'});}
});
module.exports=router;
