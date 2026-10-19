// Additive Module 12 migration only; never runs scanner/deployment code.
const path=require('path');
require('dotenv').config({path:process.env.BACKEND_ENV_FILE||path.join(__dirname,'../.env')});
const pool=require('../db');
async function main(){const db=await pool.connect();try{await db.query('BEGIN');for(const name of (process.argv.includes('--compliance-only')?['018_compliance_assessments.sql']:['017_governance.sql','018_compliance_assessments.sql']))await db.query(require('fs').readFileSync(path.join(__dirname,'../migrations',name),'utf8'));await db.query('COMMIT');console.log('Governance migrations applied (including compliance 018).');}catch(e){await db.query('ROLLBACK');throw e;}finally{db.release();await pool.end();}}
main().catch(e=>{console.error('Migration failed:',e.message);process.exitCode=1;});
