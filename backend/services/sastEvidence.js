"use strict";

function summarizeIssues(issues) {
  return issues.reduce(
    (acc, item) => {
      const severity = (item.severity || "INFO").toUpperCase();
      if (["CRITICAL","BLOCKER"].includes(severity)) acc.critical += 1;
      else if (severity === "MAJOR" || severity === "HIGH") acc.high += 1;
      else if (severity === "MINOR" || severity === "MEDIUM" || severity === "LOW") acc.medium += 1;
      else acc.low += 1;
      acc.total += 1;
      return acc;
    },
    { critical: 0, high: 0, medium: 0, low: 0, total: 0 }
  );
}

function sameSummary(expected, actual) {
  return ["total", "critical", "high", "medium", "low"].every((key) => Number(expected[key]) === Number(actual[key]));
}

async function persistSastEvidence(pool, { projectId, scanHistoryId, issues, coerceIssueRow }) {
  const summary = summarizeIssues(issues);
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query("DELETE FROM scan_results WHERE scan_history_id = $1 AND project_id = $2", [scanHistoryId, projectId]);
    for (const issue of issues) {
      const row = coerceIssueRow(issue, projectId);
      await client.query(
        "INSERT INTO scan_results (project_id, scan_history_id, rule, severity, message, file_path, line_number, status, issue_type, hotspot_review) VALUES ($1,$2,$3,$4,$5,$6,$7,'OPEN',$8,$9)",
        [projectId, scanHistoryId, ...row.slice(1), require("./sastClassification").classify(issue).type, require("./sastClassification").classify(issue).review]
      );
    }
    const verification = await client.query(
      `SELECT COUNT(*)::int AS total,
        COUNT(DISTINCT (rule, severity, message, file_path, line_number))::int AS distinct_total,
        COUNT(*) FILTER (WHERE UPPER(severity) IN ('CRITICAL','BLOCKER'))::int AS critical,
        COUNT(*) FILTER (WHERE UPPER(severity) IN ('MAJOR', 'HIGH'))::int AS high,
        COUNT(*) FILTER (WHERE UPPER(severity) IN ('MINOR', 'MEDIUM', 'LOW'))::int AS medium,
        COUNT(*) FILTER (WHERE UPPER(severity) NOT IN ('CRITICAL', 'BLOCKER', 'MAJOR', 'HIGH', 'MINOR', 'MEDIUM', 'LOW'))::int AS low
       FROM scan_results WHERE project_id = $1 AND scan_history_id = $2`,
      [projectId, scanHistoryId]
    );
    const actual = verification.rows[0] || {};
    if (!sameSummary(summary, actual) || Number(actual.distinct_total) !== summary.total) {
      throw new Error("SAST finding persistence verification failed");
    }
    const completed = await client.query(
      `UPDATE scan_history SET status = 'COMPLETED', sast_details_linked = TRUE,
        total_issues = $1, critical = $2, high = $3, medium = $4, low = $5, completed_at = NOW()
       WHERE id = $6 AND project_id = $7 AND status = 'RUNNING' RETURNING id`,
      [summary.total, summary.critical, summary.high, summary.medium, summary.low, scanHistoryId, projectId]
    );
    if (!completed.rows.length) throw new Error("SAST scan completion update was not applied");
    await client.query("COMMIT");
    return summary;
  } catch (error) {
    try { await client.query("ROLLBACK"); } catch { /* preserve original error */ }
    throw error;
  } finally {
    client.release();
  }
}

module.exports = { persistSastEvidence, summarizeIssues };
