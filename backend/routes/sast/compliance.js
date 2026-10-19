"use strict";
// Compatibility endpoint adapter. Compliance rules live in governance, never here.
const {filters,assertProject}=require('../../services/governance/query');
const {snapshot}=require('../../services/governance/analytics');
async function projectSnapshot(pool,userId,query) {
 const f=filters(query),db=await pool.connect();
 try {await db.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');await assertProject(db,userId,f);const result=await snapshot(db,userId,f);await db.query('COMMIT');return result;}
 catch(e){await db.query('ROLLBACK');throw e;}finally{db.release();}
}
module.exports={projectSnapshot};
