/**
 * backend/services/gitHelper.js
 * Shared git clone utilities - single canonical implementation for the whole backend.
 */
const { spawn } = require("child_process");

const GIT_CLONE_TIMEOUT_MS = Number.parseInt(
  process.env.GIT_CLONE_TIMEOUT_MS || String(10 * 60 * 1000), 10
);

const isUsableGithubToken = (token) => {
  if (!token || typeof token !== "string") return false;
  const t = token.trim();
  if (!t || t.includes("your_github_pat_token_here") || t.startsWith("ghp_your_")) return false;
  return true;
};

function githubHttpsCloneUrl(repoUrl, token) {
  if (!token) return repoUrl;
  try {
    const u = new URL(repoUrl);
    if (!/^github\.com$/i.test(u.hostname.replace(/^www\./, ""))) return repoUrl;
    u.username = "x-access-token";
    u.password = token;
    return u.href;
  } catch { return repoUrl; }
}

function resolveCloneUrl(project) {
  const raw = project.repo_url?.trim?.() || "";
  const token = isUsableGithubToken(project.github_token) ? project.github_token.trim()
    : isUsableGithubToken(process.env.GITHUB_TOKEN) ? process.env.GITHUB_TOKEN.trim() : null;
  if (/^https:\/\/(www\.)?github\.com\//i.test(raw) && token) return githubHttpsCloneUrl(raw, token);
  return raw;
}

const gitEnv = () => ({
  ...process.env,
  GIT_TERMINAL_PROMPT: "0",
  ...(process.platform !== "win32" ? { GIT_ASKPASS: "/bin/false" } : {}),
});

function gitCloneArgs(repoUrl, targetDir) {
  const branch = process.env.GIT_CLONE_BRANCH?.trim();
  const shallow = !/^false$/i.test(String(process.env.SAST_SHALLOW_CLONE ?? "true").trim());
  const depthArgs = shallow ? ["--depth", "1"] : [];
  if (branch) {
    return shallow
      ? ["clone", ...depthArgs, "-b", branch, "--single-branch", repoUrl, targetDir]
      : ["clone", "-b", branch, "--single-branch", repoUrl, targetDir];
  }
  return shallow ? ["clone", ...depthArgs, repoUrl, targetDir] : ["clone", repoUrl, targetDir];
}

function gitCloneAsync(repoUrl, targetDir) {
  return new Promise((resolve, reject) => {
    const args = gitCloneArgs(repoUrl, targetDir);
    const proc = spawn("git", args, { env: gitEnv(), stdio: ["ignore", "pipe", "pipe"] });
    const timer = setTimeout(() => { proc.kill(); reject(new Error("git clone timed out")); }, GIT_CLONE_TIMEOUT_MS);
    let stderr = "";
    proc.stderr.on("data", d => { stderr += d.toString(); });
    proc.on("close", code => {
      clearTimeout(timer);
      if (code === 0) resolve();
      else reject(new Error(stderr.trim() || "git clone failed"));
    });
  });
}

module.exports = { resolveCloneUrl, gitCloneAsync, gitCloneArgs, gitEnv, isUsableGithubToken };
