"use strict";

const axios = require("axios");
const { sonarBaseUrl, sonarAuthAxiosConfig } = require("./config");

async function fetchSonarMetrics(projectId) {
  const sonarHost = sonarBaseUrl();
  const projectKey = `cloudsentinel_${projectId}`;
  const metricKeys = [
    "bugs",
    "vulnerabilities",
    "security_hotspots",
    "code_smells",
    "coverage",
    "duplicated_lines_density",
    "ncloc",
  ].join(",");

  // First verify the project key actually exists in SonarQube for this projectId.
  // This prevents returning stale metrics from a different project's last scan.
  try {
    await axios.get(
      `${sonarHost}/api/projects/search?projects=${encodeURIComponent(projectKey)}`,
      sonarAuthAxiosConfig()
    );
  } catch (e) {
    return null;
  }

  const res = await axios.get(
    `${sonarHost}/api/measures/component?component=${encodeURIComponent(projectKey)}&metricKeys=${metricKeys}`,
    sonarAuthAxiosConfig()
  );

  // If SonarQube returns no component (project key doesn't exist), return null
  if (!res.data?.component) return null;

  const measures = res.data.component.measures || [];
  const byMetric = Object.fromEntries(measures.map((m) => [m.metric, m.value]));
  return {
    bugs: Number(byMetric.bugs || 0),
    vulnerabilities: Number(byMetric.vulnerabilities || 0),
    hotspots: Number(byMetric.security_hotspots || 0),
    codeSmells: Number(byMetric.code_smells || 0),
    coverage: Number(byMetric.coverage || 0),
    duplications: Number(byMetric.duplicated_lines_density || 0),
    ncloc: Number(byMetric.ncloc || 0),
  };
}

module.exports = { fetchSonarMetrics };
