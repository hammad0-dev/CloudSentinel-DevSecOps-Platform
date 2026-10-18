'use strict';
const {randomUUID}=require('node:crypto');
// No worker is started or registered. These lease primitives have no AWS/Terraform capability.
async function claim(pool,{enabled=false,policyDigest,leaseSeconds=30}={}){
 if(enabled!==true)throw Error('Deployment outbox consumer disabled');
 if(!/^[a-f0-9]{64}$/.test(policyDigest||'')||!Number.isSafeInteger(leaseSeconds)||leaseSeconds<1||leaseSeconds>60)throw Error('Invalid outbox admission');
 const c=await pool.connect();try{
  await c.query('BEGIN');
  await c.query("UPDATE deployment_outbox o SET status='blocked',claim_token=NULL,claim_until=NULL FROM deployment_eligibility d,pipeline_executions e WHERE o.decision_id=d.id AND e.id=d.pipeline_execution_id AND o.status IN ('pending','claimed') AND (d.expires_at<=NOW() OR d.evidence->>'policyDigest'<>$1 OR e.status<>'COMPLETED')",[policyDigest]);
  const r=await c.query("SELECT o.id FROM deployment_outbox o JOIN deployment_eligibility d ON d.id=o.decision_id WHERE d.decision='ELIGIBLE' AND d.expires_at>NOW()+$1*INTERVAL '1 second' AND d.evidence->>'policyDigest'=$2 AND (o.status='pending' OR (o.status='claimed' AND o.claim_until<=NOW())) ORDER BY o.id FOR UPDATE OF o SKIP LOCKED LIMIT 1",[leaseSeconds,policyDigest]);
  let event=null;if(r.rows.length){const token=randomUUID();event=(await c.query("UPDATE deployment_outbox SET status='claimed',claim_token=$2,claim_until=NOW()+$3*INTERVAL '1 second',attempts=attempts+1 WHERE id=$1 RETURNING id,decision_id,claim_token,claim_until,attempts",[r.rows[0].id,token,leaseSeconds])).rows[0];}
  await c.query('COMMIT');return event;
 }catch(e){await c.query('ROLLBACK').catch(()=>{});throw e}finally{c.release()}
}
async function abandon(pool,id,token,status='failed'){
 if(!['failed','blocked','pending'].includes(status))throw Error('Processing success is not supported in this phase');
 const r=await pool.query("UPDATE deployment_outbox SET status=$3,claim_token=NULL,claim_until=NULL WHERE id=$1 AND claim_token=$2 AND status='claimed' AND claim_until>NOW() RETURNING id",[id,token,status]);
 if(r.rows.length!==1)throw Error('Stale or invalid outbox claim');
}
module.exports={claim,abandon};
