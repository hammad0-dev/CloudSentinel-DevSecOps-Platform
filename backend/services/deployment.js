/**
 * backend/services/deployment.js
 *
 * Module 8: Automated Kubernetes deployment service.
 * Clones the project repo, auto-generates Dockerfile + K8s manifests if missing,
 * builds/loads the Docker image into Minikube, applies manifests, and returns the
 * live staging URL. Tracks whether files were auto-generated vs pre-existing.
 *
 * Supported auto-generation stacks: Node.js, Python, Java (Maven/Gradle).
 * Best-effort — not every project structure is guaranteed to build; stated limitation.
 */

const fs = require("fs");
const path = require("path");
const os = require("os");
const { spawn } = require("child_process");
const pool = require("../db");
const { resolveCloneUrl, gitCloneAsync } = require("./gitHelper");

// ─── Constants ────────────────────────────────────────────────────────────────
const DEPLOY_TIMEOUT_MS = 20 * 60 * 1000; // 20 min per stage
const CLONE_BASE = process.env.CLONE_DIR || "/tmp/cloudsentinel-scans";

// Ensure ~/.local/bin is in PATH so minikube/kubectl installed there are found
const os_mod = require("os");
const LOCAL_BIN = os_mod.homedir() + "/.local/bin";
const deployEnv = () => ({
  ...process.env,
  PATH: LOCAL_BIN + ":" + (process.env.PATH || "/usr/local/bin:/usr/bin:/bin"),
});

// ─── Spawn helper ─────────────────────────────────────────────────────────────
function runCmd(label, cmd, args, cwd, timeoutMs = DEPLOY_TIMEOUT_MS) {
  return new Promise((resolve, reject) => {
    console.log(`[deploy] ${label}: ${cmd} ${args.join(" ")}`);
    const proc = spawn(cmd, args, {
      cwd,
      stdio: ["ignore", "pipe", "pipe"],
      env: deployEnv(),
    });
    const timer = setTimeout(() => {
      proc.kill();
      reject(new Error(`${label} timed out after ${timeoutMs / 1000}s`));
    }, timeoutMs);
    let stdout = "";
    let stderr = "";
    proc.stdout.on("data", d => { stdout += d.toString(); });
    proc.stderr.on("data", d => { stderr += d.toString(); });
    proc.on("close", code => {
      clearTimeout(timer);
      if (code === 0) resolve(stdout.trim());
      else reject(new Error(`${label} failed (exit ${code}): ${stderr.trim() || stdout.trim()}`));
    });
  });
}

// ─── Stack Detection ─────────────────────────────────────────────────────────
function detectStack(repoDir) {
  if (fs.existsSync(path.join(repoDir, "package.json"))) return "node";
  if (fs.existsSync(path.join(repoDir, "requirements.txt"))) return "python";
  if (fs.existsSync(path.join(repoDir, "pom.xml"))) return "java-maven";
  if (
    fs.existsSync(path.join(repoDir, "build.gradle")) ||
    fs.existsSync(path.join(repoDir, "build.gradle.kts"))
  ) return "java-gradle";
  return "unknown";
}

// ─── Dockerfile Templates ─────────────────────────────────────────────────────
function generateDockerfileContent(stack, repoDir) {
  if (stack === "node") {
    // Detect port from package.json start script or default 3000
    let port = 3000;
    try {
      const pkg = JSON.parse(fs.readFileSync(path.join(repoDir, "package.json"), "utf8"));
      const startCmd = pkg.scripts?.start || "";
      const portMatch = startCmd.match(/PORT[= ]+(\d+)|--port[= ]+(\d+)/i);
      if (portMatch) port = parseInt(portMatch[1] || portMatch[2]);
    } catch {}
    return `FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev
COPY . .
EXPOSE ${port}
ENV NODE_ENV=production
CMD ["node", "index.js"]
`;
  }

  if (stack === "python") {
    return `FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 8080
CMD ["python", "app.py"]
`;
  }

  if (stack === "java-maven") {
    return `FROM maven:3.9-eclipse-temurin-17 AS build
WORKDIR /app
COPY pom.xml .
RUN mvn dependency:go-offline -q
COPY src ./src
RUN mvn package -DskipTests -q

FROM eclipse-temurin:17-jre-alpine
WORKDIR /app
COPY --from=build /app/target/*.jar app.jar
EXPOSE 8080
CMD ["java", "-jar", "app.jar"]
`;
  }

  if (stack === "java-gradle") {
    return `FROM gradle:8-jdk17-alpine AS build
WORKDIR /app
COPY build.gradle* settings.gradle* ./
COPY src ./src
RUN gradle bootJar --no-daemon -q

FROM eclipse-temurin:17-jre-alpine
WORKDIR /app
COPY --from=build /app/build/libs/*.jar app.jar
EXPOSE 8080
CMD ["java", "-jar", "app.jar"]
`;
  }

  // Fallback — generic static server
  return `FROM nginx:alpine
COPY . /usr/share/nginx/html
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
`;
}

// ─── Kubernetes Manifest Templates ────────────────────────────────────────────
function generateK8sManifests(projectName, imageTag, containerPort) {
  const safeAppName = projectName.toLowerCase().replace(/[^a-z0-9-]/g, "-").slice(0, 50);

  const deployment = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: ${safeAppName}
  labels:
    app: ${safeAppName}
    managed-by: cloudsentinel
spec:
  replicas: 1
  selector:
    matchLabels:
      app: ${safeAppName}
  template:
    metadata:
      labels:
        app: ${safeAppName}
    spec:
      containers:
        - name: ${safeAppName}
          image: ${imageTag}
          imagePullPolicy: Never
          ports:
            - containerPort: ${containerPort}
          resources:
            requests:
              cpu: "100m"
              memory: "128Mi"
            limits:
              cpu: "500m"
              memory: "512Mi"
          readinessProbe:
            httpGet:
              path: /
              port: ${containerPort}
            initialDelaySeconds: 10
            periodSeconds: 5
            failureThreshold: 6
`;

  const service = `apiVersion: v1
kind: Service
metadata:
  name: ${safeAppName}
  labels:
    app: ${safeAppName}
    managed-by: cloudsentinel
spec:
  selector:
    app: ${safeAppName}
  ports:
    - protocol: TCP
      port: 80
      targetPort: ${containerPort}
  type: NodePort
`;

  return { deployment, service, safeAppName };
}

// ─── Container port detection ─────────────────────────────────────────────────
function detectContainerPort(stack, repoDir) {
  if (stack === "node") {
    try {
      const pkg = JSON.parse(fs.readFileSync(path.join(repoDir, "package.json"), "utf8"));
      const startCmd = pkg.scripts?.start || "";
      const portMatch = startCmd.match(/PORT[= ]+(\d+)|--port[= ]+(\d+)/i);
      if (portMatch) return parseInt(portMatch[1] || portMatch[2]);
    } catch {}
    return 3000;
  }
  if (stack === "python") return 8080;
  if (stack.startsWith("java")) return 8080;
  return 80;
}

// ─── Find existing K8s manifests ──────────────────────────────────────────────
function findExistingManifests(repoDir) {
  const candidates = [
    path.join(repoDir, "k8s"),
    path.join(repoDir, "kubernetes"),
    path.join(repoDir, "deploy"),
    repoDir,
  ];
  for (const dir of candidates) {
    if (!fs.existsSync(dir)) continue;
    const files = fs.readdirSync(dir).filter(f =>
      (f.endsWith(".yaml") || f.endsWith(".yml")) &&
      (f.includes("deployment") || f.includes("service"))
    );
    if (files.length >= 1) return dir;
  }
  return null;
}

// ─── Main deploy function ─────────────────────────────────────────────────────
async function deployProject(projectId) {
  let cloneDir = null;
  let generatedDir = null;

  try {
    // 1. Load project from DB
    const projRes = await pool.query(
      "SELECT id, name, repo_url, github_token, is_private FROM projects WHERE id = $1",
      [projectId]
    );
    if (!projRes.rows.length) throw new Error(`Project ${projectId} not found`);
    const project = projRes.rows[0];
    const projectName = project.name || `project-${projectId}`;

    // 2. Clone repo
    const cloneBase = CLONE_BASE;
    if (!fs.existsSync(cloneBase)) fs.mkdirSync(cloneBase, { recursive: true });
    cloneDir = fs.mkdtempSync(path.join(cloneBase, `${projectId}-deploy-`));
    const cloneUrl = resolveCloneUrl(project);
    console.log(`[deploy] Cloning ${cloneUrl} into ${cloneDir}`);
    await gitCloneAsync(cloneUrl, cloneDir);

    // 3. Detect stack
    const stack = detectStack(cloneDir);
    console.log(`[deploy] Detected stack: ${stack}`);
    const containerPort = detectContainerPort(stack, cloneDir);

    // 4. Check for Dockerfile
    let dockerfileSource = "existing";
    const dockerfilePath = path.join(cloneDir, "Dockerfile");
    if (!fs.existsSync(dockerfilePath)) {
      console.log(`[deploy] No Dockerfile found — auto-generating for stack: ${stack}`);
      const dockerfileContent = generateDockerfileContent(stack, cloneDir);
      fs.writeFileSync(dockerfilePath, dockerfileContent, "utf8");
      dockerfileSource = "generated";
    }

    // 5. Check for K8s manifests
    let manifestSource = "existing";
    let manifestDir = findExistingManifests(cloneDir);
    if (!manifestDir) {
      console.log(`[deploy] No K8s manifests found — auto-generating`);
      const imageTag = `${projectName.toLowerCase().replace(/[^a-z0-9-]/g, "-")}:latest`;
      const { deployment, service, safeAppName } = generateK8sManifests(projectName, imageTag, containerPort);
      generatedDir = path.join(cloneDir, "k8s-generated");
      fs.mkdirSync(generatedDir, { recursive: true });
      fs.writeFileSync(path.join(generatedDir, "deployment.yaml"), deployment, "utf8");
      fs.writeFileSync(path.join(generatedDir, "service.yaml"), service, "utf8");
      manifestDir = generatedDir;
      manifestSource = "generated";

      // Write safeAppName to a helper file for later service URL lookup
      fs.writeFileSync(path.join(generatedDir, ".appname"), safeAppName, "utf8");
    }

    // Derive safeAppName from existing manifests or generated
    let safeAppName;
    const appNameFile = path.join(manifestDir, ".appname");
    if (fs.existsSync(appNameFile)) {
      safeAppName = fs.readFileSync(appNameFile, "utf8").trim();
    } else {
      safeAppName = projectName.toLowerCase().replace(/[^a-z0-9-]/g, "-").slice(0, 50);
    }

    const imageTag = `${safeAppName}:latest`;

    // 6. Docker build
    console.log(`[deploy] Building Docker image: ${imageTag}`);
    await runCmd("docker build", "docker", ["build", "-t", imageTag, "."], cloneDir);

    // 7. Load image into Minikube
    console.log(`[deploy] Loading image into Minikube`);
    await runCmd("minikube image load", "minikube", ["image", "load", imageTag], cloneDir, 10 * 60 * 1000);

    // 8. Apply K8s manifests
    console.log(`[deploy] Applying manifests from ${manifestDir}`);
    await runCmd("kubectl apply", "kubectl", ["apply", "-f", manifestDir], cloneDir, 5 * 60 * 1000);

    // 9. Wait for rollout
    console.log(`[deploy] Waiting for rollout to complete`);
    try {
      await runCmd(
        "kubectl rollout status",
        "kubectl",
        ["rollout", "status", `deployment/${safeAppName}`, "--timeout=5m"],
        cloneDir,
        6 * 60 * 1000
      );
    } catch (rolloutErr) {
      console.warn(`[deploy] Rollout status warning (continuing): ${rolloutErr.message}`);
    }

    // 10. Get staging URL
    console.log(`[deploy] Getting Minikube service URL`);
    let stagingUrl;
    try {
      stagingUrl = await runCmd(
        "minikube service url",
        "minikube",
        ["service", safeAppName, "--url"],
        cloneDir,
        60 * 1000
      );
      stagingUrl = stagingUrl.split("\n")[0].trim();
    } catch {
      // Fallback: get NodePort manually
      try {
        const nodePort = await runCmd(
          "get nodeport",
          "kubectl",
          ["get", "service", safeAppName, "-o", "jsonpath={.spec.ports[0].nodePort}"],
          cloneDir, 30000
        );
        const minikubeIp = await runCmd("minikube ip", "minikube", ["ip"], cloneDir, 30000);
        stagingUrl = `http://${minikubeIp.trim()}:${nodePort.trim()}`;
      } catch {
        stagingUrl = "http://minikube-url-unavailable";
      }
    }

    console.log(`[deploy] Staging URL: ${stagingUrl}`);

    // 11. Record deployment in DB
    await pool.query(
      `INSERT INTO deployment_history
       (project_id, status, deployed_at, staging_url, dockerfile_source, manifest_source, app_name, image_tag)
       VALUES ($1, 'SUCCESS', NOW(), $2, $3, $4, $5, $6)`,
      [projectId, stagingUrl, dockerfileSource, manifestSource, safeAppName, imageTag]
    );

    // 12. Update project's target_url for DAST
    await pool.query(
      "UPDATE projects SET target_url = $1 WHERE id = $2",
      [stagingUrl, projectId]
    );

    return { stagingUrl, dockerfileSource, manifestSource, safeAppName };

  } catch (err) {
    console.error(`[deploy] Deployment failed for project ${projectId}:`, err.message);

    // Record failure in DB
    try {
      await pool.query(
        `INSERT INTO deployment_history (project_id, status, deployed_at, failure_reason)
         VALUES ($1, 'FAILED', NOW(), $2)`,
        [projectId, err.message || "Unknown error"]
      );
    } catch {}

    throw err;
  } finally {
    // Cleanup clone directory
    if (cloneDir && fs.existsSync(cloneDir)) {
      try { fs.rmSync(cloneDir, { recursive: true, force: true }); } catch {}
    }
  }
}

module.exports = { deployProject };
