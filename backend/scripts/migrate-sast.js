// Apply only the additive SAST classification migration; never runs scanners.
const path=require('path');
require('dotenv').config({path:process.env.BACKEND_ENV_FILE||path.join(__dirname,'../.env')});
const pool=require('../db');
(async()=>{const client=await pool.connect();try{await client.query('BEGIN');await client.query(require('fs').readFileSync(path.join(__dirname,'../migrations/016_sast_issue_classification.sql'),'utf8'));await client.query('COMMIT');console.log('SAST migration 016 applied: issue_type and hotspot_review are available.');}catch(error){await client.query('ROLLBACK');throw error;}finally{client.release();await pool.end();}})().catch(error=>{console.error('SAST migration failed:',error.message);process.exitCode=1;});
