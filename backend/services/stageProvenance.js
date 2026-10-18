'use strict';
const {revision,pin}=require('./pipelineProvenance'),artifact=require('./staticArtifact'),{digest,policyFromEnvironment}=require('./deploymentEligibility');
const TABLES={SAST:'scan_history',Dependency:'dependency_scans',IaC:'iac_scans',Deploy:'deployment_history',DAST:'dast_scans'};
async function prepare(pool,context,cwd){
 const r=await pin(pool,context,cwd);if(!r||r.profile!=='STATIC_HTML')return r;
 const p=policyFromEnvironment();if(!p||digest(p)!==r.policy_digest||Date.parse(p.expiresAt)<=Date.now())throw Error('EXECUTION_DEPLOYMENT_POLICY_STALE');
 const detected=require('./staticDeploymentEngine').detect(cwd,r.commit_sha);if(detected.profile!=='STATIC_HTML')throw Error('UNSUPPORTED_ARCHITECTURE');
 const old=await pool.query('SELECT * FROM deployment_revision_bindings WHERE pipeline_execution_id=$1 AND project_id=$2',[context.executionId,context.projectId]);
 let ref;
 if(old.rows.length){const b=old.rows[0];ref={...context,commit:r.commit_sha,sha256:b.artifact_sha256};artifact.verify(ref);if(artifact.hash(Buffer.from(JSON.stringify(artifact.collect(cwd,r.commit_sha))))!==ref.sha256)throw Error('Checkout artifact changed');}
 else{ref=artifact.create(cwd,{...context,commit:r.commit_sha});await pool.query("INSERT INTO deployment_revision_bindings(pipeline_execution_id,project_id,owner_id,repository_id,repository_identity,branch,commit_sha,profile,artifact_sha256,policy_digest,evidence) VALUES($1,$2,$3,$4,$5,$6,$7,'STATIC_HTML',$8,$9,$10)",[context.executionId,context.projectId,context.userId,r.repository_id,r.repository_identity,r.branch,r.commit_sha,ref.sha256,r.policy_digest,detected]);}
 return {...r,artifact:ref};
}
async function binding(pool,context){const r=await revision(pool,context);if(!r||r.profile!=='STATIC_HTML')return null;const result=await pool.query('SELECT * FROM deployment_revision_bindings WHERE pipeline_execution_id=$1 AND project_id=$2',[context.executionId,context.projectId]);if(result.rows.length!==1)throw Error('ARTIFACT_BINDING_MISSING');const b=result.rows[0];if(b.commit_sha!==r.commit_sha||b.policy_digest!==r.policy_digest||b.owner_id!==r.owner_id||b.repository_identity!==r.repository_identity)throw Error('SOURCE_ARTIFACT_BINDING_MISMATCH');artifact.verify({projectId:context.projectId,executionId:context.executionId,commit:b.commit_sha,sha256:b.artifact_sha256});return b;}
function counts(s){return {CRITICAL:Number(s.critical||0),HIGH:Number(s.high||0),MEDIUM:Number(s.medium||0),LOW:Number(s.low||0),INFORMATIONAL:Number(s.informational||0)}}
async function attest(pool,context,stage,id,facts){
 if(!TABLES[stage])throw Error('Unsupported attestation stage');
 const b=await binding(pool,context);if(!b)return;
 if(facts.commit!==b.commit_sha||!facts.reportHash?.match(/^[a-f0-9]{64}$/)||typeof facts.tool!=='string'||!facts.tool||facts.tool.length>500)throw Error('INCOMPLETE_TOOL_OR_REPORT_PROVENANCE');
 const r=await pool.query(`SELECT to_jsonb(t) AS record FROM ${TABLES[stage]} t WHERE id=$1 AND project_id=$2 AND pipeline_execution_id=$3`,[id,context.projectId,context.executionId]);
 if(r.rows.length!==1)throw Error('STAGE_RECORD_MISSING');const row=r.rows[0].record;
 if(row.status!==(stage==='Deploy'?'SUCCESS':'COMPLETED'))throw Error('STAGE_RECORD_NOT_COMPLETED');
 const snapshot={id,status:row.status,completedAt:new Date(row.completed_at||row.deployed_at).toISOString(),counts:counts(row),url:row.staging_url||row.target_url||null,mode:row.scan_mode||null,consistent:true,reviewsResolved:true,recordDigest:digest(row),tool:facts.tool,reportHash:facts.reportHash,commit:b.commit_sha,artifact:b.artifact_sha256};
 const details=await detailRecords(pool,context,stage,id);snapshot.detailsDigest=digest(details);
 if(Number(row.unknown||0)>0)throw Error('UNCLASSIFIED_SCAN_FINDINGS');
 if(stage==='SAST'){
  const issues=(await pool.query('SELECT issue_type,hotspot_review,severity FROM scan_results WHERE scan_history_id=$1 AND project_id=$2 ORDER BY id',[id,context.projectId])).rows;
  if(issues.length!==Number(row.total_issues)||!row.sast_details_linked)throw Error('SAST_PERSISTENCE_INCOMPLETE');
  snapshot.classificationVerified=issues.every(i=>['CODE_SMELL','BUG','VULNERABILITY','SECURITY_HOTSPOT'].includes(i.issue_type));snapshot.reviewsResolved=issues.every(i=>i.issue_type!=='SECURITY_HOTSPOT'||['SAFE','FIXED'].includes(i.hotspot_review));snapshot.counts=counts({});
  for(const i of issues.filter(i=>i.issue_type==='VULNERABILITY')){const severity=({BLOCKER:'CRITICAL',MAJOR:'HIGH',MINOR:'MEDIUM',INFO:'INFORMATIONAL'})[i.severity]||i.severity;if(!(severity in snapshot.counts))throw Error('UNKNOWN_SECURITY_SEVERITY');snapshot.counts[severity]++;}
  snapshot.qualityGate=facts.qualityGate;snapshot.analysisId=facts.analysisId;if(!facts.analysisId||facts.qualityGate!=='OK'||facts.sourceCoverageVerified!==true)throw Error('SAST_ANALYSIS_UNVERIFIED');
 }
 if(stage==='Dependency'){snapshot.sbomVerified=facts.sbomVerified===true;snapshot.coverageVerified=['INVENTORY_PRESENT','NO_SUPPORTED_MANIFESTS_OBSERVED'].includes(facts.coverage?.status);snapshot.coverage=facts.coverage;const bom=typeof row.sbom_json==='string'?JSON.parse(row.sbom_json):row.sbom_json;if(bom?.bomFormat!=='CycloneDX'||!Array.isArray(bom.components))throw Error('INVALID_PERSISTED_SBOM');if(!snapshot.sbomVerified||!snapshot.coverageVerified||!row.sbom_json)throw Error('SBOM_COVERAGE_UNVERIFIED');}
 if(stage==='DAST'){snapshot.reportVerified=true;const deployment=await pool.query("SELECT staging_url FROM deployment_history WHERE project_id=$1 AND pipeline_execution_id=$2 AND status='SUCCESS' ORDER BY id DESC LIMIT 1",[context.projectId,context.executionId]);if(row.scan_mode!=='BASELINE'||deployment.rows[0]?.staging_url!==row.target_url)throw Error('PASSIVE_TARGET_MISMATCH');}
 if(stage!=='SAST'&&stage!=='Deploy'){if(!facts.counts||Object.keys(snapshot.counts).some(k=>facts.counts[k]!==snapshot.counts[k]))throw Error('SCAN_REPORT_COUNT_MISMATCH');const total=Number(stage==='Dependency'?row.total_packages:row.total_findings);if(Number.isFinite(total)&&stage!=='Dependency'&&details.length!==total)throw Error('SCAN_DETAILS_INCOMPLETE');}
 const reports=require('./securityReports');snapshot.reports=reports.store({projectId:context.projectId,executionId:context.executionId,stage,recordId:id,commit:b.commit_sha,artifact:b.artifact_sha256},facts.reports);snapshot.reportHash=snapshot.reports.manifestSha256;reports.verify(snapshot.reports);
 await pool.query('INSERT INTO deployment_stage_attestations(pipeline_execution_id,project_id,stage,record_id,commit_sha,artifact_sha256,snapshot,fingerprint) VALUES($1,$2,$3,$4,$5,$6,$7,$8)',[context.executionId,context.projectId,stage,id,b.commit_sha,b.artifact_sha256,snapshot,digest(snapshot)]);
}
async function detailRecords(pool,context,stage,id){const spec={SAST:['scan_results','scan_history_id'],Dependency:['sbom_components','scan_id'],IaC:['iac_findings','scan_id'],DAST:['dast_findings','scan_id']}[stage];if(!spec)return [];return (await pool.query(`SELECT to_jsonb(t) AS record FROM ${spec[0]} t WHERE ${spec[1]}=$1 AND project_id=$2 ORDER BY id`,[id,context.projectId])).rows.map(r=>r.record);}
async function toolVersion(command,name='Trivy'){const stdout=await require('./boundedCommand').run(command,['--version'],{timeout:15000,maxBuffer:65536});const m=/\b(\d+\.\d+\.\d+[\w.-]*)\b/.exec(stdout);if(!m)throw Error('TOOL_VERSION_UNVERIFIED');return `${name} ${m[1]}`;}
module.exports={prepare,binding,attest,TABLES,counts,toolVersion,detailRecords};
