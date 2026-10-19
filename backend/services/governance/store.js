"use strict";
const {normalize}=require('./normalize');
const adapters=[
 {source:'SAST',table:'scan_history',detail:'scan_results',link:'scan_history_id',count:'total_issues',where:"AND s.scan_type='SAST'",statuses:['COMPLETED']},
 {source:'DEPENDENCY',table:'dependency_scans',detail:'sbom_components',link:'scan_id',count:'total_packages',statuses:['COMPLETED']},
 {source:'IAC',table:'iac_scans',detail:'iac_findings',link:'scan_id',count:'total_findings',statuses:['COMPLETED']},
 {source:'IMAGE',table:'image_scans',detail:'image_vulnerabilities',link:'image_scan_id',count:'total_vulnerabilities',statuses:['COMPLETED','BLOCKED']},
 {source:'DAST',table:'dast_scans',detail:'dast_findings',link:'scan_id',count:'total_findings',statuses:['COMPLETED']},
 {source:'ACTIVE_DAST',table:'active_dast_executions',statuses:['COMPLETED_WITH_FINDINGS','COMPLETED_NO_FINDINGS']},
];
async function sync(pool,userId) {
 const client=await pool.connect();const sources=[];let imported=0;
 try {
  await client.query('BEGIN');
  // Shared user refreshes serialize; row upserts also protect project/source identity.
  await client.query('SELECT pg_advisory_xact_lock(120017,$1::int)',[userId]);
  for(const a of adapters) {
   const available=await client.query('SELECT to_regclass($1) AS scans,to_regclass($2) AS details',[a.table,a.detail||a.table]);
   if(!available.rows[0].scans||!available.rows[0].details){sources.push({source:a.source,state:'UNAVAILABLE',reason:'Source schema not installed'});continue;}
   const scans=(await client.query(`SELECT to_jsonb(s) AS record FROM ${a.table} s JOIN projects p ON p.id=s.project_id
    LEFT JOIN governance_scans g ON g.project_id=s.project_id AND g.source=$2 AND g.scan_id=s.id::text
    WHERE p.user_id=$1 AND s.status=ANY($3::text[]) ${a.where||''} AND (g.id IS NULL OR NOT g.details_complete ${a.source==='SAST'?"OR (to_jsonb(s)->>'sast_details_linked'='false' AND g.details_complete)":''})
    ORDER BY s.id`,[userId,a.source,a.statuses])).rows;
   for(const {record:s} of scans) {
    const active=a.source==='ACTIVE_DAST';
    const rows=active?(Array.isArray(s.result?.findings)?s.result.findings:[]):(await client.query(`SELECT to_jsonb(f) AS record FROM ${a.detail} f WHERE f.project_id=$1 AND f.${a.link}=$2`,[s.project_id,s.id])).rows.map(r=>r.record);
    const expected=active?rows.length:Number(s[a.count]);
    const complete=Number.isFinite(expected)&&expected===rows.length&&(a.source!=='SAST'||s.sast_details_linked!==false)&&(!active||Array.isArray(s.result?.findings));
    const at=s.completed_at||s.created_at||s.started_at;
    if(!at)throw Error('Source scan has no observation timestamp');
    const scan=(await client.query(`INSERT INTO governance_scans(project_id,source,scan_id,scanned_at,source_status,details_complete,raw_count)
     VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(project_id,source,scan_id) DO UPDATE SET details_complete=EXCLUDED.details_complete,raw_count=EXCLUDED.raw_count RETURNING id`,[s.project_id,a.source,String(s.id),at,s.status,complete,rows.length])).rows[0];
    let normalized=0;
    for(const row of rows) {
     const f=normalize(a.source,row,{project_id:s.project_id,scan_id:s.id,resource:s.image_tag,mode:s.scan_mode,detailTable:a.detail||a.table});
     if(!f)continue;
     const stored=(await client.query(`INSERT INTO governance_findings(project_id,source,fingerprint,identity,title,description,severity,location,references_json,remediation,mappings,classification,first_seen,last_seen)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10,$11::jsonb,$12,$13,$13)
      ON CONFLICT(project_id,source,fingerprint) DO UPDATE SET
      title=CASE WHEN EXCLUDED.last_seen>=governance_findings.last_seen THEN EXCLUDED.title ELSE governance_findings.title END,
      description=CASE WHEN EXCLUDED.last_seen>=governance_findings.last_seen THEN EXCLUDED.description ELSE governance_findings.description END,
      severity=CASE WHEN EXCLUDED.last_seen>=governance_findings.last_seen THEN EXCLUDED.severity ELSE governance_findings.severity END,
      remediation=CASE WHEN EXCLUDED.last_seen>=governance_findings.last_seen THEN EXCLUDED.remediation ELSE governance_findings.remediation END,
      mappings=EXCLUDED.mappings, first_seen=LEAST(governance_findings.first_seen,EXCLUDED.first_seen),last_seen=GREATEST(governance_findings.last_seen,EXCLUDED.last_seen)
      RETURNING id`,[s.project_id,a.source,f.fingerprint,f.identity,f.title,f.description,f.severity,f.location,JSON.stringify(f.references),f.remediation,JSON.stringify(f.mappings),f.classification,at])).rows[0];
     const observed=await client.query(`INSERT INTO governance_observations(finding_id,governance_scan_id,source_record_id,observed_at,evidence)
      VALUES($1,$2,$3,$4,$5::jsonb) ON CONFLICT(finding_id,governance_scan_id) DO NOTHING`,[stored.id,scan.id,f.evidence.sourceRecordId,at,JSON.stringify(f.evidence)]);
     imported+=observed.rowCount;normalized++;
    }
    await client.query('UPDATE governance_scans SET imported_count=$1 WHERE id=$2',[normalized,scan.id]);
   }
   sources.push({source:a.source,state:'AVAILABLE',processedScans:scans.length});
  }
  const {refreshMappings,importAssessments}=require('./assessments');
  const updatedMappings=await refreshMappings(client,userId);
  const importedAssessments=await importAssessments(client,userId);
  await client.query('COMMIT');
  return {importedObservations:imported,updatedMappings,importedAssessments,sources,limitations:['Kubernetes audit excluded: stored records lack project/owner identity.','Earlier dependency/IaC details deleted by upstream scans cannot be recovered.','Findings never resolve automatically; status changes require owner review.']};
 } catch(e){await client.query('ROLLBACK');throw e;}finally{client.release();}
}
module.exports={sync,adapters};
