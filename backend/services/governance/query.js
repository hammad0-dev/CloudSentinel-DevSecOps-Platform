"use strict";
const {SOURCES,SEVERITIES,STATUSES}=require('./normalize');
function bad(message){return Object.assign(Error(message),{status:400});}
function positive(value,name,max=2147483647){if(!['string','number'].includes(typeof value)||!/^\d+$/.test(String(value))||!Number.isSafeInteger(Number(value))||Number(value)<1||Number(value)>max)throw bad(`${name} must be a positive integer (maximum ${max})`);return Number(value);}
function filters(q={}) {
 const out={page:q.page===undefined?1:positive(q.page,'page',1000000),pageSize:q.pageSize===undefined?25:positive(q.pageSize,'pageSize',100)};
 out.owaspVersion=q.owaspVersion||'2021';
 if(!require('./registry').OWASP_VERSIONS.includes(out.owaspVersion))throw bad('Unsupported OWASP version');
 if(q.benchmark){if(q.benchmark!==require('./registry').docker.id)throw bad('Unsupported benchmark');out.benchmark=q.benchmark;}
 if(q.assessment){if(!['PASS','FAIL','NOT_ASSESSED','NOT_APPLICABLE','ERROR'].includes(q.assessment))throw bad('Invalid assessment state');out.assessment=q.assessment;}
 if(q.project)out.project=positive(q.project,'project');
 for(const [key,allowed] of [['severity',SEVERITIES],['source',SOURCES],['status',STATUSES]])if(q[key]){if(!allowed.includes(q[key]))throw bad(`Invalid ${key}`);out[key]=q[key];}
 for(const key of ['from','to'])if(q[key]){if(typeof q[key]!=='string'||!/^\d{4}-\d{2}-\d{2}$/.test(q[key])||!Number.isFinite(Date.parse(q[key]))||new Date(q[key]).toISOString().slice(0,10)!==q[key])throw bad(`Invalid ${key} date`);out[key]=q[key];}
 if(out.from&&out.to&&out.from>out.to)throw bad('from must be before to');
 if(q.search){if(typeof q.search!=='string'||q.search.length>200)throw bad('Search must contain at most 200 characters');out.search=q.search;}
 if(q.mapping){if(typeof q.mapping!=='string'||q.mapping.length>80)throw bad('Invalid mapping');out.mapping=q.mapping;const category=/^A\d{2}:(\d{4})$/.exec(q.mapping);if(category&&(category[1]!==out.owaspVersion||!require('./registry').categories.some(c=>c.id===q.mapping)))throw bad('Mapping category must match the selected OWASP version');}
 out.sort=q.sort||'severity';if(!['severity','newest','oldest'].includes(out.sort))throw bad('Invalid sort');
 return out;
}
function scope(userId,f) {
 const params=[userId];const parts=['p.user_id=$1'];
 const add=(sql,value)=>{params.push(value);parts.push(sql.replace('?',`$${params.length}`));};
 if(f.project)add('p.id=?',f.project);
 if(f.source)add('g.source=?',f.source);
 if(f.from)add("g.scanned_at >= (?::date::timestamp AT TIME ZONE 'UTC')",f.from);
 if(f.to)add("g.scanned_at < ((?::date + INTERVAL '1 day') AT TIME ZONE 'UTC')",f.to);
 return {params,where:parts.join(' AND ')};
}
function selection(userId,f) {
 const s=scope(userId,f);const parts=[];
 const add=(sql,value)=>{s.params.push(value);parts.push(sql.replace('?',`$${s.params.length}`));};
 for(const key of ['severity','status'])if(f[key])add(`f.${key}=?`,f[key]);
 if(f.search)add("(f.title || ' ' || f.identity || ' ' || f.references_json::text) ILIKE ?",`%${f.search.replace(/[\\%_]/g,'\\$&')}%`);
 if(f.mapping==='UNMAPPED')add("NOT EXISTS (SELECT 1 FROM jsonb_array_elements(f.mappings) m WHERE m->>'framework'=?)",`OWASP Top 10:${f.owaspVersion}`);
 else if(f.mapping)add("EXISTS (SELECT 1 FROM jsonb_array_elements(f.mappings) m WHERE m->>'id'=?)",f.mapping);
 const sql=`WITH observed AS (
 SELECT DISTINCT ON (o.finding_id) o.finding_id,g.scan_id,g.source_status,g.details_complete,o.observed_at,g.id AS observation_scan
 FROM governance_observations o JOIN governance_scans g ON g.id=o.governance_scan_id JOIN projects p ON p.id=g.project_id
 WHERE ${s.where} ORDER BY o.finding_id,o.observed_at DESC,o.id DESC)
 SELECT f.*,p.name AS project_name,observed.scan_id,observed.observed_at,observed.details_complete
 FROM governance_findings f JOIN observed ON observed.finding_id=f.id JOIN projects p ON p.id=f.project_id
 WHERE p.user_id=$1 ${parts.length?'AND '+parts.join(' AND '):''}`;
 return {sql,params:s.params};
}
const ordering={severity:"CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 WHEN 'INFO' THEN 4 ELSE 5 END, last_seen DESC,id DESC",newest:'last_seen DESC,id DESC',oldest:'first_seen ASC,id ASC'};
async function assertProject(db,userId,f){if(f.project&&!(await db.query('SELECT id FROM projects WHERE id=$1 AND user_id=$2',[f.project,userId])).rows.length)throw Object.assign(Error('Project not found'),{status:404});}
async function list(db,userId,f){const q=selection(userId,f);const total=Number((await db.query(`SELECT COUNT(*) AS total FROM (${q.sql}) selected`,q.params)).rows[0].total);const rows=(await db.query(`${q.sql} ORDER BY ${ordering[f.sort]} LIMIT $${q.params.length+1} OFFSET $${q.params.length+2}`,[...q.params,f.pageSize,(f.page-1)*f.pageSize])).rows;return {findings:rows,total,page:f.page,pageSize:f.pageSize};}
module.exports={filters,positive,bad,scope,selection,ordering,assertProject,list};
