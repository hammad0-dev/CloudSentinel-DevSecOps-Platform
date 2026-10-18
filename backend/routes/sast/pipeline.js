"use strict";

const fs = require("fs");
const path = require("path");
const { spawn, spawnSync } = require("child_process");
const {
  GIT_CLONE_TIMEOUT_MS,
  MAVEN_TIMEOUT_MS,
  GRADLE_TIMEOUT_MS,
  SONAR_SCANNER_TIMEOUT_MS,
  sanitizeScanError,
  shouldUseSonarBranchAnalysis,
} = require("./config");

function spawnWithTimeout(label, command, args, spawnOptions, timeoutMs) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, spawnOptions);
    let stderr = "";
    let stdout = "";
    let settled = false;

    const finalize = () => clearTimeout(timer);

    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      finalize();
      try {
        child.kill("SIGKILL");
      } catch (_) {
        /* ignore */
      }
      reject(
        new Error(
          `${label}: timed out after ${Math.round(timeoutMs / 1000)}s. Check SONAR_HOST, Git/Sonar connectivity, ` +
            `or raise SAST_GIT_TIMEOUT_MS / SAST_SONAR_SCAN_TIMEOUT_MS in backend .env.`
        )
      );
    }, timeoutMs);

    child.stderr?.on("data", (c) => {
      stderr += c;
    });
    child.stdout?.on("data", (c) => {
      stdout += c;
    });

    child.on("error", (err) => {
      if (settled) return;
      settled = true;
      finalize();
      reject(label === "git clone" ? new Error(redactGitCredentials(err.message)) : err);
    });

    child.on("close", (code, signal) => {
      if (settled) return;
      settled = true;
      finalize();
      if (code === 0) resolve({ stdout, stderr });
      else {
        const detail = ((stderr || "") + (stdout || "")).trim();
        reject(
          new Error((label === "git clone" ? redactGitCredentials(detail) : detail) || `${label || command}: exited with ${code}${signal ? ` (${signal})` : ""}`)
        );
      }
    });
  });
}

function isUsableGithubToken(token) {
  if (!token || typeof token !== "string") return false;
  const t = token.trim();
  if (!t) return false;
  if (t.includes("your_github_pat_token_here")) return false;
  if (t.startsWith("ghp_your_")) return false;
  return true;
}
function redactGitCredentials(value) {
  return String(value || "").replace(/(https?:\/\/)[^/\s@]*@/gi, (_match, scheme) => scheme + "***@");
}


function githubHttpsCloneUrl(repoUrl, token) {
  if (!token) return repoUrl;
  try {
    const u = new URL(repoUrl);
    if (!/^github\.com$/i.test(u.hostname.replace(/^www\./, ""))) return repoUrl;
    u.username = "x-access-token";
    u.password = token;
    return u.href;
  } catch {
    return repoUrl;
  }
}

function resolveCloneUrl(project) {
  const raw = project.repo_url?.trim?.() || "";
  const isPrivateRepo =
    typeof project.is_private === "boolean"
      ? project.is_private
      : String(project.is_private || "").trim().toLowerCase() === "true";
  const token = isPrivateRepo
    ? (isUsableGithubToken(project.github_token) ? project.github_token.trim() : null)
    : (isUsableGithubToken(project.github_token) ? project.github_token.trim() : null) ||
      (isUsableGithubToken(process.env.GITHUB_TOKEN) ? process.env.GITHUB_TOKEN.trim() : null);
  if (/^https:\/\/(www\.)?github\.com\//i.test(raw) && token) return githubHttpsCloneUrl(raw, token);
  return raw;
}

const gitEnv = () => {
  const base = {
    ...process.env,
    GIT_TERMINAL_PROMPT: "0",
  };
  if (process.platform !== "win32") {
    base.GIT_ASKPASS = "/bin/false";
  }
  return base;
};

function useShallowGitClone() {
  return !/^false$/i.test(String(process.env.SAST_SHALLOW_CLONE ?? "true").trim());
}

function gitCloneArgs(repoUrl, targetDir) {
  const branch = process.env.GIT_CLONE_BRANCH?.trim();
  const shallow = useShallowGitClone();
  const depthArgs = shallow ? ["--depth", "1"] : [];

  if (branch) {
    return shallow
      ? ["clone", ...depthArgs, "-b", branch, "--single-branch", repoUrl, targetDir]
      : ["clone", "-b", branch, "--single-branch", repoUrl, targetDir];
  }
  return shallow ? ["clone", ...depthArgs, repoUrl, targetDir] : ["clone", repoUrl, targetDir];
}

function gitCloneAsync(repoUrl, targetDir) {
  return spawnWithTimeout(
    "git clone",
    "git",
    gitCloneArgs(repoUrl, targetDir),
    {
      env: gitEnv(),
      stdio: ["ignore", "pipe", "pipe"],
    },
    GIT_CLONE_TIMEOUT_MS
  ).then(() => {});
}

function runCommandAsync(command, args, cwd, timeoutMs = MAVEN_TIMEOUT_MS, spawnExtra = {}) {
  const shell =
    spawnExtra.shell !== undefined ? spawnExtra.shell : process.platform === "win32";
  const env = spawnExtra.env || process.env;
  return spawnWithTimeout(
    `${command}`,
    command,
    args,
    {
      cwd,
      env,
      stdio: ["ignore", "pipe", "pipe"],
      shell,
    },
    timeoutMs
  );
}

function gradleBuildEnv() {
  const env = { ...process.env };
  const jh = process.env.SAST_GRADLE_JAVA_HOME?.trim();
  if (jh) {
    env.JAVA_HOME = jh;
    env.PATH = `${path.join(jh, "bin")}${path.delimiter}${env.PATH || ""}`;
  }
  return env;
}

/** Extra args for every Gradle invocation (e.g. `-x spotlessCheck` for repos where Spotless/Prettier breaks headless CI). */
function gradleExtraArgsFromEnv() {
  const raw = process.env.SAST_GRADLE_EXTRA_ARGS?.trim();
  if (!raw) return [];
  return raw.match(/(?:[^\s"]+|"[^"]*")+/g)?.map((s) => s.replace(/^"(.*)"$/, "$1")) || [];
}

function mavenParallelArgs() {
  const raw = process.env.SAST_MAVEN_PARALLEL;
  if (raw !== undefined && String(raw).trim() === "") return [];
  const flag = (raw != null && String(raw).trim() ? String(raw).trim() : "-T 1C").split(/\s+/);
  return flag;
}

async function buildJavaProjectIfPresent(cloneTarget) {
  const pomPath = path.join(cloneTarget, "pom.xml");
  if (!fs.existsSync(pomPath)) return;

  const mvnTail = [...mavenParallelArgs(), "-DskipTests", "clean", "package"];
  const hasMvnw = fs.existsSync(path.join(cloneTarget, "mvnw"));
  const hasMvnwCmd = fs.existsSync(path.join(cloneTarget, "mvnw.cmd"));

  if (process.platform === "win32" && hasMvnwCmd) {
    await runCommandAsync("mvnw.cmd", mvnTail, cloneTarget);
    return;
  }
  if (process.platform !== "win32" && hasMvnw) {
    await runCommandAsync("sh", ["mvnw", ...mvnTail], cloneTarget);
    return;
  }

  const mavenCmd = process.env.MAVEN_CMD || "mvn";
  await runCommandAsync(mavenCmd, mvnTail, cloneTarget);
}

/**
 * Prefer compileJava first (fewer plugin side-effects than `classes` / `assemble`).
 * Repos with Spotless+Prettier may still need SAST_GRADLE_EXTRA_ARGS (see README).
 */
async function buildGradleProjectIfPresent(cloneTarget, opts = {}) {
  const { softFail = false } = opts;
  const hasPom = fs.existsSync(path.join(cloneTarget, "pom.xml"));
  if (hasPom) return false;

  const hasGradleFile =
    fs.existsSync(path.join(cloneTarget, "build.gradle")) ||
    fs.existsSync(path.join(cloneTarget, "build.gradle.kts")) ||
    fs.existsSync(path.join(cloneTarget, "settings.gradle")) ||
    fs.existsSync(path.join(cloneTarget, "settings.gradle.kts"));
  const hasBat = fs.existsSync(path.join(cloneTarget, "gradlew.bat"));
  const hasUnix = fs.existsSync(path.join(cloneTarget, "gradlew"));
  if (!hasGradleFile || (!hasBat && !hasUnix)) return false;

  const unixGradlePath = path.join(cloneTarget, "gradlew");
  if (process.platform !== "win32" && hasUnix) {
    try {
      fs.chmodSync(unixGradlePath, 0o755);
    } catch {
      /* non-fatal */
    }
  }

  const env = gradleBuildEnv();
  const genv = { env };
  const extra = gradleExtraArgsFromEnv();
  const taskSequences = [
    ["compileJava", "-x", "test", ...extra],
    ["classes", "-x", "test", ...extra],
    ["assemble", "-x", "test", ...extra],
  ];
  let lastError = null;

  const runGradle = async (tasks) => {
    if (process.platform === "win32" && hasBat) {
      await runCommandAsync("gradlew.bat", tasks, cloneTarget, GRADLE_TIMEOUT_MS, genv);
    } else if (process.platform === "win32" && hasUnix && !hasBat) {
      await runCommandAsync("bash", [unixGradlePath, ...tasks], cloneTarget, GRADLE_TIMEOUT_MS, {
        ...genv,
        shell: false,
      });
    } else if (hasUnix) {
      await runCommandAsync(unixGradlePath, tasks, cloneTarget, GRADLE_TIMEOUT_MS, {
        ...genv,
        shell: false,
      });
    } else if (hasBat) {
      await runCommandAsync("gradlew.bat", tasks, cloneTarget, GRADLE_TIMEOUT_MS, genv);
    } else {
      throw new Error("Gradle wrapper present but neither gradlew nor gradlew.bat could be run on this platform.");
    }
  };

  for (const tasks of taskSequences) {
    try {
      await runGradle(tasks);
      if (discoverJavaBytecodeRoots(cloneTarget).length > 0) {
        return true;
      }
      lastError = new Error(
        `Gradle ${tasks.join(" ")} exited 0 but no Java bytecode dirs were detected. ` +
          `Use JDK 17+ (SAST_GRADLE_JAVA_HOME) or allow Gradle toolchain download.`
      );
    } catch (err) {
      lastError = err;
    }
  }

  const finalErr = lastError || new Error("Gradle build failed.");
  if (softFail) {
    console.warn("[SAST] Gradle build did not yield usable bytecode:", sanitizeScanError(finalErr).slice(0, 900));
    return false;
  }
  throw finalErr;
}

function discoverJavaBytecodeRoots(cloneTarget) {
  const found = [];
  function walk(absDir) {
    const mavenClasses = path.join(absDir, "target", "classes");
    try {
      if (fs.statSync(mavenClasses).isDirectory()) {
        found.push(path.relative(cloneTarget, mavenClasses).replace(/\\/g, "/"));
      }
    } catch {
      /* skip */
    }
    const gradleDirs = [
      path.join(absDir, "build", "classes", "java", "main"),
      path.join(absDir, "build", "classes", "kotlin", "main"),
      path.join(absDir, "build", "classes", "groovy", "main"),
    ];
    for (const gd of gradleDirs) {
      try {
        if (fs.statSync(gd).isDirectory()) {
          found.push(path.relative(cloneTarget, gd).replace(/\\/g, "/"));
        }
      } catch {
        /* skip */
      }
    }

    let entries;
    try {
      entries = fs.readdirSync(absDir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      if (!e.isDirectory()) continue;
      const n = e.name;
      if (n === "node_modules" || n === ".git" || n === "dist") continue;
      if (n === "target") continue;
      if (n === "build") continue;
      walk(path.join(absDir, n));
    }
  }
  walk(cloneTarget);
  return [...new Set(found)].sort();
}

function detectedGitBranch(cloneTarget) {
  const r = spawnSync("git", ["rev-parse", "--abbrev-ref", "HEAD"], {
    cwd: cloneTarget,
    encoding: "utf8",
    env: gitEnv(),
  });
  const b = r.stdout?.trim();
  if (b && b !== "HEAD") return b;
  return process.env.SONAR_BRANCH_NAME?.trim() || "main";
}

function stripSonarProjectPropertiesFromClone(cloneTarget) {
  if (/^true$/i.test((process.env.SAST_USE_EMBEDDED_SONAR_PROPERTIES || "").trim())) {
    return;
  }
  const found = [];
  function walk(absDir) {
    const prop = path.join(absDir, "sonar-project.properties");
    if (fs.existsSync(prop)) found.push(prop);
    let entries;
    try {
      entries = fs.readdirSync(absDir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      if (!e.isDirectory()) continue;
      const n = e.name;
      if (n === "target" || n === "node_modules" || n === ".git" || n === "dist" || n === ".gradle") {
        continue;
      }
      walk(path.join(absDir, e.name));
    }
  }
  walk(cloneTarget);
  for (const f of found) {
    try {
      fs.unlinkSync(f);
    } catch (err) {
      console.warn("[SAST] Could not remove", f, err.message);
    }
  }
  if (found.length) {
    console.warn(
      `[SAST] Removed ${found.length} sonar-project.properties file(s) so CLI analysis params apply. ` +
        `If you need repo Sonar config, set SAST_USE_EMBEDDED_SONAR_PROPERTIES=true in backend .env.`
    );
  }
}

function runSonarScannerAsync(projectId, cloneTarget, sonarHost, branchName, executionCommit) {
  const scanner = process.env.SONAR_SCANNER_PATH || "sonar-scanner";
  const token = process.env.SONAR_TOKEN || "";

  const envBin = process.env.SAST_SONAR_JAVA_BINARIES?.trim();
  const discoveredBin = discoverJavaBytecodeRoots(cloneTarget);
  const javaBinaries =
    envBin || (discoveredBin.length ? discoveredBin.join(",") : null);

  /** Extra paths: IaC/K8s YAML under k8s/ often trips Sonar IAC/Kubernetes analyzers on CE (ContextException); Java SAST ignores them safely. Override via SAST_SONAR_EXCLUSIONS. */
  const exclusionsDefault =
    "**/node_modules/**,**/.git/**,**/.gradle/caches/**,**/build/generated/**," +
    "**/k8s/**,**/kubernetes/**,**/deployment/k8s/**,**/helm/**,**/charts/**";
  const exclusions =
    process.env.SAST_SONAR_EXCLUSIONS?.trim() || exclusionsDefault;
  const args = [
    `-Dsonar.projectKey=cloudsentinel_${projectId}`,
    `-Dsonar.projectBaseDir=${cloneTarget}`,
    `-Dsonar.sources=.`,
  ];
  if(executionCommit){if(!/^[a-f0-9]{40}$/.test(executionCommit))throw Error('Invalid Sonar execution revision');args.push(`-Dsonar.scm.revision=${executionCommit}`);}
  if (javaBinaries) {
    args.push(`-Dsonar.java.binaries=${javaBinaries}`);
    if (!envBin && discoveredBin.length) {
      console.warn(
        `[SAST] sonar.java.binaries = ${discoveredBin.length} path(s) (Maven target/classes / Gradle build/classes)`
      );
    }
  }
  args.push(
    `-Dsonar.exclusions=${exclusions}`,
    `-Dsonar.host.url=${sonarHost}`,
    `-Dsonar.token=${token}`,
    `-Dsonar.scm.disabled=true`
  );
  if (!javaBinaries) {
    console.warn(
      "[SAST] No bytecode dirs found under target/classes or build/classes/* — running without sonar.java.binaries (fewer Java rules may run). Confirm Maven/Gradle compiled successfully."
    );
  }
  if (shouldUseSonarBranchAnalysis() && branchName) args.push(`-Dsonar.branch.name=${branchName}`);
  return spawnWithTimeout(
    "sonar-scanner",
    scanner,
    args,
    {
      cwd: cloneTarget,
      env: process.env,
      stdio: ["ignore", "pipe", "pipe"],
      shell: process.platform === "win32",
    },
    SONAR_SCANNER_TIMEOUT_MS
  );
}

module.exports = {
  spawnWithTimeout,
  resolveCloneUrl,
  gitEnv,
  useShallowGitClone,
  gitCloneAsync,
  runCommandAsync,
  buildJavaProjectIfPresent,
  buildGradleProjectIfPresent,
  discoverJavaBytecodeRoots,
  detectedGitBranch,
  stripSonarProjectPropertiesFromClone,
  runSonarScannerAsync,
};
