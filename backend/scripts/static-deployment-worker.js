'use strict';
// Explicit opt-in process. Not invoked by server.js, npm dev, registration or webhooks.
require('dotenv').config({path:process.env.BACKEND_ENV_FILE||require('node:path').join(__dirname,'../.env'),quiet:true});
const {enabled}=require('../services/staticDeploymentEngine');
if(!enabled()){console.error('AWS deployment worker disabled; no work started');process.exitCode=1;}
else{
 const pool=require('../db');
 try{require('../services/staticAwsAdapter').configured();const stop=require('../services/staticDeploymentWorker').start(pool);let closing=false;const shutdown=async()=>{if(closing)return;closing=true;stop();await pool.end();};process.on('SIGINT',shutdown);process.on('SIGTERM',shutdown);}
 catch{console.error('AWS deployment worker configuration invalid; no work started');pool.end();process.exitCode=1;}
}
