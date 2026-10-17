'use strict';
const {randomUUID}=require('crypto');
const budget=require('./commissioningBudget');
const fail=code=>Object.assign(new Error(code),{code,status:403,nonRetryable:true});

// A lease is created only after the phase is genuinely resumable. Its expiry is
// bounded by every already-authorized deadline and the fixed 165s warm reserve.
async function issue(pool,context,phaseExpiry,overallDeadline,now=Date.now()) {
  if(!Number.isSafeInteger(phaseExpiry)||!Number.isSafeInteger(overallDeadline))throw fail('COMMISSIONING_PHASE_LEASE_BLOCKED');
  const expires=Math.min(phaseExpiry,overallDeadline);
  budget.requireTime(expires,budget.reuseMinimumMs,now);
  const id=randomUUID();
  const result=await pool.query(`UPDATE active_dast_commissioning_phases
    SET active_lease_id=$4, active_lease_expires_at=to_timestamp($5/1000.0),
        overall_deadline=to_timestamp($6/1000.0), updated_at=NOW()
    WHERE project_id=$1 AND pipeline_execution_id=$2 AND operator_id=$3
      AND phase='AWAITING_ACTIVE_AUTHORIZATION' AND runtime_retained
      AND expires_at>NOW() AND active_lease_id IS NULL
    RETURNING active_lease_id,active_lease_expires_at`,[context.projectId,context.executionId,context.userId,id,expires,overallDeadline]);
  if(result.rows.length!==1)throw fail('COMMISSIONING_PHASE_LEASE_BLOCKED');
  return {leaseId:id,expiresAt:expires,overallDeadline};
}

async function consume(pool,context,leaseId,now=Date.now()) {
  if(!/^[0-9a-f-]{36}$/.test(leaseId||''))throw fail('COMMISSIONING_PHASE_LEASE_BLOCKED');
  const result=await pool.query(`UPDATE active_dast_commissioning_phases
    SET active_lease_consumed_at=NOW(),updated_at=NOW()
    WHERE project_id=$1 AND pipeline_execution_id=$2 AND operator_id=$3
      AND phase='AWAITING_ACTIVE_AUTHORIZATION' AND runtime_retained
      AND active_lease_id=$4 AND active_lease_consumed_at IS NULL
      AND active_lease_expires_at>NOW() AND expires_at>NOW()
    RETURNING active_lease_expires_at,overall_deadline`,[context.projectId,context.executionId,context.userId,leaseId]);
  if(result.rows.length!==1)throw fail('COMMISSIONING_PHASE_LEASE_BLOCKED');
  const row=result.rows[0];
  const deadline=Math.min(new Date(row.active_lease_expires_at).getTime(),new Date(row.overall_deadline||row.active_lease_expires_at).getTime());
  budget.requireTime(deadline,budget.reuseMinimumMs,now);
  return {expiresAt:deadline};
}
module.exports={issue,consume};
