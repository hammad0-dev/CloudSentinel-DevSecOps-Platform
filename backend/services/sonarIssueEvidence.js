'use strict';
const fail=reason=>Object.assign(Error(reason),{code:reason});
async function collect({get,host,projectKey,options}){
 if(!/^cloudsentinel_[1-9][0-9]*$/.test(projectKey))throw fail('SAST_ISSUE_SCOPE_INVALID');
 const collected=[],keys=new Set();let total;
 for(let page=1;page<=20;page++){
  const data=(await get(`${host}/api/issues/search?components=${encodeURIComponent(projectKey)}&ps=500&p=${page}`,options)).data;
  const paging=data?.paging;
  if(!Array.isArray(data?.issues)||!paging||!Number.isSafeInteger(paging.total)||paging.total<0||paging.total>10000||paging.pageIndex!==page||paging.pageSize!==500||(data.total!==undefined&&data.total!==paging.total))throw fail('SAST_ISSUE_EVIDENCE_INCOMPLETE');
  if(total!==undefined&&total!==paging.total)throw fail('SAST_ISSUE_EVIDENCE_INCOMPLETE');total=paging.total;
  if(data.issues.length!==Math.min(500,total-collected.length))throw fail('SAST_ISSUE_EVIDENCE_INCOMPLETE');
  for(const issue of data.issues){
   if(!issue||typeof issue.key!=='string'||!issue.key||keys.has(issue.key))throw fail('SAST_ISSUE_EVIDENCE_INCONSISTENT');
   if(typeof issue.component!=='string'||!(issue.component===projectKey||issue.component.startsWith(projectKey+':'))||(issue.project!==undefined&&issue.project!==projectKey))throw fail('SAST_ISSUE_SCOPE_INVALID');
   keys.add(issue.key);collected.push(issue);
  }
  if(collected.length===total)return collected;
 }
 throw fail('SAST_ISSUE_EVIDENCE_INCOMPLETE');
}
module.exports={collect};
