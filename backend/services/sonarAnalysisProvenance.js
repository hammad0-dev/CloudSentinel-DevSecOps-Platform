'use strict';
const fs=require('node:fs'),path=require('node:path');
async function verify({cwd,host,projectKey,commit,get,options,startedAt=0,wait=ms=>new Promise(r=>setTimeout(r,ms)),now=Date.now}){
 const file=path.join(cwd,'.scannerwork','report-task.txt'),st=fs.lstatSync(file);if(!st.isFile()||st.isSymbolicLink()||st.size>16384||st.mtimeMs<startedAt-1000)throw Error('SONAR_TASK_EVIDENCE_UNVERIFIED');
 const lines=Object.fromEntries(fs.readFileSync(file,'utf8').trim().split(/\r?\n/).map(line=>{const i=line.indexOf('=');return [line.slice(0,i),line.slice(i+1)]}));
 if(lines.projectKey!==projectKey||!lines.ceTaskId?.match(/^[A-Za-z0-9_-]{1,100}$/))throw Error('SONAR_TASK_IDENTITY_MISMATCH');
 const deadline=now()+90000;let task;
 do{task=(await get(`${host}/api/ce/task?id=${encodeURIComponent(lines.ceTaskId)}`,options)).data?.task;if(task?.status==='SUCCESS')break;if(!['PENDING','IN_PROGRESS'].includes(task?.status))throw Error('SONAR_TASK_FAILED');await wait(1000)}while(now()<deadline);
 if(task?.status!=='SUCCESS'||task.id!==lines.ceTaskId||task.componentKey!==projectKey||!task.analysisId?.match(/^[A-Za-z0-9_-]{1,100}$/))throw Error('SONAR_ANALYSIS_UNVERIFIED');
 const analyses=(await get(`${host}/api/project_analyses/search?project=${encodeURIComponent(projectKey)}&ps=1`,options)).data?.analyses;
 if(analyses?.[0]?.key!==task.analysisId||analyses[0].revision!==commit)throw Error('SONAR_ANALYSIS_REVISION_MISMATCH');
 return task.analysisId;
}
module.exports={verify};
