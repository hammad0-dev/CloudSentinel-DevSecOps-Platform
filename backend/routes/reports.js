const express = require("express");
const pool = require("../db");
const auth = require("../middleware/auth");
const router = express.Router();
const severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL", "UNKNOWN"];
const normalize = (value) => ({ MAJOR: "HIGH", MINOR: "MEDIUM" }[String(value || "").toUpperCase()] || (severities.includes(String(value || "").toUpperCase()) ? String(value).toUpperCase() : "UNKNOWN"));
const count = (groups) => groups.flat().reduce((out, finding) => { const severity = normalize(finding.severity); out.total++; out.bySeverity[severity]++; return out; }, { total: 0, bySeverity: Object.fromEntries(severities.map((key) => [key, 0])) });
const validId = (value) => Number.isInteger(Number(value)) && Number(value) > 0 ? Number(value) : null;
router.get("/projects/:projectId/executions/:executionId", auth, async (req, res) => {
  const projectId = validId(req.params.projectId), executionId = validId(req.params.executionId);
  if (!projectId || !executionId) return res.status(400).json({ error: "Project and execution IDs must be positive integers" });
  try {
    const execution = await pool.query("SELECT e.id,e.project_id,e.status,e.triggered_by,e.stages_completed,e.failure_reason,e.started_at,e.completed_at,p.name,p.repo_url FROM pipeline_executions e JOIN projects p ON p.id=e.project_id WHERE e.id=$1 AND e.project_id=$2 AND p.user_id=$3", [executionId, projectId, req.user.id]);
    if (!execution.rows.length) return res.status(404).json({ error: "Pipeline execution not found for this project" });
    const q = (sql) => pool.query(sql, [projectId, executionId]);
    const [sast, dependency, iac, image, dast, deployment] = await Promise.all([
      q("SELECT id,status,total_issues,critical,high,medium,low,started_at,completed_at FROM scan_history WHERE project_id=$1 AND pipeline_execution_id=$2 AND scan_type='SAST' ORDER BY id DESC LIMIT 1"),
      q("SELECT id,status,total_packages,critical,high,medium,low,unknown,started_at,completed_at FROM dependency_scans WHERE project_id=$1 AND pipeline_execution_id=$2 ORDER BY id DESC LIMIT 1"),
      q("SELECT id,status,total_findings,critical,high,medium,low,unknown,started_at,completed_at FROM iac_scans WHERE project_id=$1 AND pipeline_execution_id=$2 ORDER BY id DESC LIMIT 1"),
      q("SELECT id,status,image_tag,total_vulnerabilities,critical,high,medium,low,unknown,failure_reason,started_at,completed_at FROM image_scans WHERE project_id=$1 AND pipeline_execution_id=$2 ORDER BY id DESC LIMIT 1"),
      q("SELECT id,status,target_url,total_findings,high,medium,low,informational,scan_mode,policy_name,policy_version,started_at,completed_at FROM dast_scans WHERE project_id=$1 AND pipeline_execution_id=$2 ORDER BY id DESC LIMIT 1"),
      q("SELECT id,status,deployment_attempt,deployed_at,staging_url,app_name,image_tag,failure_reason FROM deployment_history WHERE project_id=$1 AND pipeline_execution_id=$2 ORDER BY id DESC LIMIT 1")
    ]);
    const scans = { sast:sast.rows[0]||null, dependency:dependency.rows[0]||null, iac:iac.rows[0]||null, image:image.rows[0]||null, dast:dast.rows[0]||null };
    let activeResult=null,activeUnavailable=false;
    try {activeResult=(await q('SELECT status,duration_ms,result,created_at FROM active_dast_executions WHERE project_id=$1 AND pipeline_execution_id=$2')).rows[0]||null;}
    catch (_) {activeUnavailable=true;}
    scans.activeDast=activeResult;
    const detail = async (scan, table, idColumn, columns) => scan ? (await pool.query(`SELECT ${columns} FROM ${table} WHERE project_id=$1 AND ${idColumn}=$2`, [projectId, scan.id])).rows : [];
    const [sastFindings, dependencyFindings, iacFindings, imageFindings, dastFindings] = await Promise.all([
      detail(scans.sast,"scan_results","scan_history_id","rule,severity,message,file_path,line_number,status"), detail(scans.dependency,"sbom_components","scan_id","pkg_name,pkg_version,cve_id,severity,cvss_score,fixed_version,description"), detail(scans.iac,"iac_findings","scan_id","config_file,misconfig_id,severity,description,resolution,start_line"), detail(scans.image,"image_vulnerabilities","image_scan_id","vulnerability_id,severity,package_name,installed_version,fixed_version,title"), detail(scans.dast,"dast_findings","scan_id","alert,attack_type,severity,endpoint,method,param,cwe_id,solution")
    ]);
    const findings = { sast:sastFindings, dependency:dependencyFindings, iac:iacFindings, image:imageFindings, dast:dastFindings };
    findings.activeDast=activeResult?.result?.findings||[];
    // Keep passive and active records distinguishable, with stable finding IDs
    // supplied by each scan's normalizer rather than merging scan statuses.
    if(activeUnavailable) scans.activeDast={status:'UNAVAILABLE',reason:'Active reporting schema not available'};
    return res.json({ execution:execution.rows[0], deployment:deployment.rows[0]||null, scans, findings, counts:count([sastFindings,dependencyFindings,iacFindings,imageFindings,dastFindings,findings.activeDast]), limitations:{sastDetails:scans.sast&&!sastFindings.length?"No execution-linked SAST details are available; legacy scan_results are intentionally excluded.":null}, gates:{staticPassed:![scans.sast,scans.dependency,scans.iac].some(s=>Number(s?.critical||0)>0),imagePassed:scans.image?scans.image.status==="COMPLETED"&&Number(scans.image.critical||0)===0:null,deploymentSucceeded:deployment.rows[0]?.status==="SUCCESS",dastCompleted:scans.dast?.status==="COMPLETED"} });
  } catch (error) { console.error("[reports] execution report failed:", error.message); return res.status(500).json({ error:"Failed to generate execution report" }); }
});
module.exports = router;
