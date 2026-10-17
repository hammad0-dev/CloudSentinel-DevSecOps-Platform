'use strict';
// Read-only batches must settle before failure cleanup starts. Promise.all can
// reject while another Docker inspection is still using a soon-removed resource.
async function verifiedReads(operations){
 const results=await Promise.allSettled(operations.map(operation=>Promise.resolve().then(operation)));
 for(const result of results)if(result.status==='rejected')throw result.reason;
 return results.map(result=>result.value);
}
module.exports=verifiedReads;
