"use strict";
const {SEVERITIES,STATUSES}=require('./normalize');
const {owasp,cis,OWASP_VERSION}=require('./registry');
const {selection,scope}=require('./query');
const CORE=['SAST','DEPENDENCY','IAC','IMAGE','DAST'];
const WEIGHTS={CRITICAL:10,HIGH:5,MEDIUM:2,LOW:1,INFO:0,UNKNOWN:10};
const methodology='Filtered posture indicator: W = sum of unresolved unique finding weights (Critical 10, High 5, Medium 2, Low 1, Info 0, Unknown 10). Open and accepted risk count; resolved and false positives do not. C = complete latest project/scanner assessments / (selected projects x 5 core sources). Score = round(95 x C / (1 + W / (10 x selected projects))). No complete assessments = Not assessed. Maximum 95; this is not CVSS, a certification, or proof of security. Status is current; date filters select observations, not historical status snapshots.';
function group(rows,key,label) {const map=new Map();for(const r of rows){const k=String(r[key]);if(!map.has(k))map.set(k,{name:label?r[label]:k,value:0,id:k});map.get(k).value++;}return [...map.values()].sort((a,b)=>b.value-a.value);}
function score(findings,scans,projects) {
 const slots=projects.length*CORE.length;
 const assessed=scans.filter(s=>CORE.includes(s.source)&&s.details_complete).length;
 const weight=findings.filter(f=>['OPEN','ACCEPTED_RISK'].includes(f.status)).reduce((n,f)=>n+WEIGHTS[f.severity],0);
 const coverage=slots?Math.min(1,assessed/slots):0;
 return {value:assessed&&projects.length?Math.round(95*coverage/(1+weight/(10*projects.length))):null,weightedUnresolved:weight,assessedSlots:assessed,totalSlots:slots,coverage,methodology};
}
function compliance(findings) {
 return require('./assessments').buildCompliance(findings);
}
async function snapshot(db,userId,f) {
 const q=selection(userId,f), s=scope(userId,f);
 const projects=(await db.query('SELECT id,name FROM projects WHERE user_id=$1'+(f.project?' AND id=$2':''),f.project?[userId,f.project]:[userId])).rows;
 const findings=(await db.query(q.sql,q.params)).rows;
 const scans=(await db.query(`SELECT DISTINCT ON (g.project_id,g.source) g.*,p.name AS project_name FROM governance_scans g JOIN projects p ON p.id=g.project_id WHERE ${s.where} ORDER BY g.project_id,g.source,g.scanned_at DESC,g.id DESC`,s.params)).rows;
 const scanDateRange=(await db.query(`SELECT MIN(g.scanned_at) AS earliest,MAX(g.scanned_at) AS latest FROM governance_scans g JOIN projects p ON p.id=g.project_id WHERE ${s.where}`,s.params)).rows[0];
 const trend=(await db.query(`WITH selected AS (${q.sql}) SELECT to_char(o.observed_at AT TIME ZONE 'UTC','YYYY-MM-DD') AS day,COUNT(DISTINCT o.finding_id)::int AS value
 FROM governance_observations o JOIN governance_scans g ON g.id=o.governance_scan_id JOIN projects p ON p.id=g.project_id JOIN selected f ON f.id=o.finding_id
 WHERE ${s.where} GROUP BY 1 ORDER BY 1`,q.params)).rows;
 // Selection and scope share initial parameter positions; selection's additional
 // predicates are used inside its CTE, not accidentally interpolated into scope.
 const bySeverity=SEVERITIES.map(name=>({name,value:findings.filter(r=>r.severity===name).length}));
 const byStatus=STATUSES.map(name=>({name,value:findings.filter(r=>r.status===name).length}));
 const posture=score(findings,scans,projects),mapped=await require('./assessments').loadCompliance(db,userId,findings,projects,f);
 const priority=findings.filter(r=>['OPEN','ACCEPTED_RISK'].includes(r.status)).sort((a,b)=>WEIGHTS[b.severity]-WEIGHTS[a.severity]||new Date(b.last_seen)-new Date(a.last_seen)).slice(0,10);
 return {generatedAt:new Date().toISOString(),scanDateRange,filters:f,projects,total:findings.length,bySeverity,byStatus,byProject:group(findings,'project_id','project_name'),bySource:group(findings,'source'),trend,trendLabel:'Unique findings observed per UTC day (not historical open balance)',score:posture,compliance:mapped,recentScans:scans.slice().sort((a,b)=>new Date(b.scanned_at)-new Date(a.scanned_at)),priority,findings};
}
module.exports={snapshot,score,compliance,methodology,WEIGHTS};
