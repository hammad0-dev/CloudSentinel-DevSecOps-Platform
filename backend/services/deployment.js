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
const axios = require("axios");
const { spawn } = require("child_process");
const pool = require("../db");
const { redactGitCredentials, resolveCloneUrl, gitCloneAsync } = require("./gitHelper");
const { assertDeploymentImage, renderManifestWithImage, validateDeploymentSecurity } = require("./kubernetesSecurity");
const { ensureProjectNamespace, getProjectNamespace } = require("./kubernetesNamespace");
const { createImageIdentity } = require("./imageIdentity");
const { scanContainerImage } = require("./imageVulnerabilityScan");

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
RUN addgroup -g 10001 app && adduser -D -u 10001 -G app app
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev
COPY --chown=10001:10001 . .
ENV NODE_ENV=production PORT=${port}
EXPOSE ${port}
USER 10001:10001
CMD ["npm", "start"]
`;
  }

  if (stack === "python") {
    return `FROM python:3.11-slim
RUN groupadd --gid 10001 app && useradd --uid 10001 --gid app --no-create-home app
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY --chown=10001:10001 . .
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
EXPOSE 8080
USER 10001:10001
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
RUN addgroup -g 10001 app && adduser -D -u 10001 -G app app
WORKDIR /app
COPY --from=build --chown=10001:10001 /app/target/*.jar app.jar
EXPOSE 8080
USER 10001:10001
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
RUN addgroup -g 10001 app && adduser -D -u 10001 -G app app
WORKDIR /app
COPY --from=build --chown=10001:10001 /app/build/libs/*.jar app.jar
EXPOSE 8080
USER 10001:10001
CMD ["java", "-jar", "app.jar"]
`;
  }

  // Fallback - non-root static server on an unprivileged port.
  return `FROM nginx:1.30.5-alpine3.24@sha256:0985e772fb9f729e6fa0980da05fca5d9c468e870eed43071545afa9d2e27d94
RUN addgroup -g 10001 app && adduser -D -u 10001 -G app app \
    && sed -i -E "s/listen[[:space:]]+80;/listen 8080;/" /etc/nginx/conf.d/default.conf \
    && chown -R 10001:10001 /usr/share/nginx/html /var/cache/nginx /var/run
COPY --chown=10001:10001 . /usr/share/nginx/html
EXPOSE 8080
USER 10001:10001
CMD ["nginx", "-g", "daemon off;"]
`;
}

// ─── Kubernetes Manifest Templates ────────────────────────────────────────────
function generateK8sManifests(projectName, imageTag, containerPort, stack = "unknown", namespace) {
  if (!/^cloudsentinel-p-[1-9]\d*$/.test(namespace || "")) throw new Error("A valid CloudSentinel project namespace is required");
  const safeAppName = projectName.toLowerCase().replace(/[^a-z0-9-]/g, "-").slice(0, 50);
  const nginxMounts = stack === "unknown" ? `
            - name: nginx-cache
              mountPath: /var/cache/nginx
            - name: nginx-run
              mountPath: /var/run` : "";
  const nginxVolumes = stack === "unknown" ? `
        - name: nginx-cache
          emptyDir: {}
        - name: nginx-run
          emptyDir: {}` : "";

  const deployment = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: ${safeAppName}
  namespace: ${namespace}
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
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
        runAsGroup: 10001
        fsGroup: 10001
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: ${safeAppName}
          image: ${imageTag}
          imagePullPolicy: Never
          securityContext:
            privileged: false
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop:
                - ALL
          volumeMounts:
            - name: tmp
              mountPath: /tmp${nginxMounts}
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
      volumes:
        - name: tmp
          emptyDir: {}${nginxVolumes}
`;


  const service = `apiVersion: v1
kind: Service
metadata:
  name: ${safeAppName}
  namespace: ${namespace}
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
  return 8080;
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
async function deployProject(projectId, userId, options = {}) {
  const execute = options.runCmd || runCmd;
  let cloneDir = null;
  let generatedDir = null;
  let authorizedProject = false;
  const pipelineExecutionId = options.executionId === undefined ? null : options.executionId;
  let pipelineContextValidated = pipelineExecutionId === null;

  try {
    if (!Number.isInteger(projectId) || !Number.isInteger(userId)) {
      throw new Error("A valid project and authenticated user are required for deployment");
    }

    // 1. Load only a project owned by the trusted authenticated user context.
    const projRes = await pool.query(
      "SELECT id, name, repo_url, github_token, is_private FROM projects WHERE id = $1 AND user_id = $2",
      [projectId, userId]
    );
    if (!projRes.rows.length) throw new Error(`Project ${projectId} not found or not accessible`);
    const project = projRes.rows[0];
    authorizedProject = true;
    if (pipelineExecutionId !== null) {
      if (!Number.isInteger(pipelineExecutionId) || pipelineExecutionId <= 0) {
        throw new Error("A valid pipeline execution ID is required for a pipeline deployment");
      }
      const executionRes = await pool.query(
        "SELECT id FROM pipeline_executions WHERE id = $1 AND project_id = $2",
        [pipelineExecutionId, projectId]
      );
      if (!executionRes.rows.length) throw new Error("Pipeline execution does not belong to this project");
      pipelineContextValidated = true;
    }
    const projectName = project.name || `project-${projectId}`;
    const { namespace } = await ensureProjectNamespace(project.id, execute);
    const imageIdentity = (options.imageIdentityFactory || createImageIdentity)(project.id, {
      executionId: options.executionId,
      attempt: options.attempt ?? 1,
      now: options.now,
      nonce: options.nonce,
    });
    const imageTag = imageIdentity.imageReference;

    // 2. Clone repo
    const cloneBase = CLONE_BASE;
    if (!fs.existsSync(cloneBase)) fs.mkdirSync(cloneBase, { recursive: true });
    cloneDir = fs.mkdtempSync(path.join(cloneBase, `${projectId}-deploy-`));
    const cloneUrl = resolveCloneUrl(project);
    console.log(`[deploy] Cloning ${redactGitCredentials(cloneUrl)} into ${cloneDir}`);
    await gitCloneAsync(cloneUrl, cloneDir);
    const provenance=await require('./stageProvenance').prepare(pool,{projectId,executionId:pipelineExecutionId,userId},cloneDir);
    const sourceCommit = await execute("git source commit", "git", ["rev-parse", "HEAD"], cloneDir, 30000);
    if (!/^[a-f0-9]{40,64}$/i.test(sourceCommit)) throw new Error("Unable to determine the checked-out source commit");

    if(provenance?.artifact){
      // Static runtime uses only the previously scanned immutable files; no repository Dockerfile executes.
      fs.rmSync(cloneDir,{recursive:true,force:true});fs.mkdirSync(cloneDir,{mode:0o700});
      const manifest=require('./staticArtifact').materialize(provenance.artifact,path.join(cloneDir,'site'));
      fs.writeFileSync(path.join(cloneDir,'static.sha256'),manifest.files.map(f=>`${f.sha256}  ${f.path}`).join('\n')+'\n',{mode:0o600});
      const dockerfile=generateDockerfileContent('unknown',cloneDir).replace('COPY --chown=10001:10001 . /usr/share/nginx/html','RUN rm -rf /usr/share/nginx/html/*\nCOPY --chown=10001:10001 site/ /usr/share/nginx/html\nCOPY static.sha256 /opt/cloudsentinel-static.sha256\nRUN chmod 0444 /opt/cloudsentinel-static.sha256 && cd /usr/share/nginx/html && sha256sum -c /opt/cloudsentinel-static.sha256').replace('CMD ["nginx", "-g", "daemon off;"]','CMD '+JSON.stringify(['sh','-c','cd /usr/share/nginx/html && sha256sum -c /opt/cloudsentinel-static.sha256 && exec nginx -g "daemon off;"']));
      fs.writeFileSync(path.join(cloneDir,'Dockerfile'),dockerfile,{mode:0o600});
    }

    // 3. Detect stack
    const stack = detectStack(cloneDir);
    console.log(`[deploy] Detected stack: ${stack}`);
    const containerPort = detectContainerPort(stack, cloneDir);

    // 4. Check for Dockerfile
    let dockerfileSource = provenance?.artifact ? "generated" : "existing";
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
      const { deployment, service, safeAppName } = generateK8sManifests(projectName, imageTag, containerPort, stack, namespace);
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

    // 6. Docker build
    console.log(`[deploy] Building Docker image: ${imageTag}`);
    await execute("docker build", "docker", ["build", "-t", imageTag, "."], cloneDir);
    const localImageId = await execute("docker image inspect", "docker", ["image", "inspect", "--format={{.Id}}", imageTag], cloneDir, 30000);
    if (!/^sha256:[a-f0-9]{64}$/i.test(localImageId)) throw new Error("Docker did not return a valid local image ID");

    // 7. Scan the newly built immutable image before it is available to Kubernetes.
    // Scanner, parser, and persistence errors deliberately fail the deployment closed.
    console.log("[deploy] Scanning container image for OS-package vulnerabilities");
    const imageScan = await scanContainerImage({
      pool, execute, cwd: cloneDir, projectId, pipelineExecutionId,
      deploymentAttempt: imageIdentity.attempt, imageTag,
    });

    // 7. Load image into Minikube
    console.log(`[deploy] Loading image into Minikube`);
    await execute("minikube image load", "minikube", ["image", "load", imageTag], cloneDir, 10 * 60 * 1000);

    // 8. Validate the rendered resources structurally before applying anything.
    const dryRunResources = await execute(
      "kubectl security dry-run",
      "kubectl",
      ["create", "--dry-run=client", "--namespace", namespace, "-f", manifestDir, "-o", "json"],
      cloneDir,
      60000
    );
    const rendered = renderManifestWithImage(dryRunResources, safeAppName, namespace, imageTag);
    const renderedManifestPath = path.join(cloneDir, ".cloudsentinel-rendered.json");
    fs.writeFileSync(renderedManifestPath, rendered.renderedJson, "utf8");

    console.log(`[deploy] Applying validated manifests in ${namespace}`);
    await execute("kubectl apply", "kubectl", ["apply", "--namespace", namespace, "-f", renderedManifestPath], cloneDir, 5 * 60 * 1000);
    await execute("kubectl rollout restart", "kubectl", ["rollout", "restart", `deployment/${safeAppName}`, "--namespace", namespace], cloneDir, 60000);

    // 9. Wait for rollout
    console.log(`[deploy] Waiting for rollout to complete`);
    try {
      await execute(
        "kubectl rollout status",
        "kubectl",
        ["rollout", "status", `deployment/${safeAppName}`, "--namespace", namespace, "--timeout=5m"],
        cloneDir,
        6 * 60 * 1000
      );
    } catch (rolloutErr) {
      let diagnostic = "";
      try {
        const pods = JSON.parse(await execute("kubectl get pods", "kubectl", ["get", "pods", "--namespace", namespace, "-l", `app=${safeAppName}`, "-o", "json"], cloneDir, 30000));
        const waiting = pods.items?.flatMap(p => p.status?.containerStatuses || []).map(c => c.state?.waiting).find(Boolean);
        diagnostic = waiting?.reason ? `${waiting.reason}${waiting.message ? `: ${waiting.message}` : ""}` : "";
      } catch {}
      throw new Error(`Kubernetes rollout failed for deployment ${safeAppName}: ${diagnostic || rolloutErr.message}`);
    }

    const deployment = JSON.parse(await execute("kubectl get deployment", "kubectl", ["get", "deployment", safeAppName, "--namespace", namespace, "-o", "json"], cloneDir, 30000));
    validateDeploymentSecurity(deployment);
    const applicationContainer = assertDeploymentImage(deployment, safeAppName, imageTag);
    const desired = deployment.spec?.replicas ?? 1;
    const status = deployment.status || {};
    if (deployment.metadata?.name !== safeAppName || (status.observedGeneration ?? 0) < (deployment.metadata?.generation ?? 0) ||
        (status.updatedReplicas ?? 0) < desired || (status.readyReplicas ?? 0) < desired ||
        (status.availableReplicas ?? 0) < desired || (status.unavailableReplicas ?? 0) > 0) {
      throw new Error(`Deployment ${safeAppName} is not ready (${status.readyReplicas ?? 0}/${desired} ready)`);
    }

    const deployedPods = JSON.parse(await execute(
      "kubectl get deployed pods",
      "kubectl",
      ["get", "pods", "--namespace", namespace, "-l", `app=${safeAppName}`, "-o", "json"],
      cloneDir,
      30000
    ));
    const runningPod = (deployedPods.items || []).find(pod =>
      pod.status?.phase === "Running" &&
      (pod.status?.containerStatuses || []).some(container => container.name === applicationContainer.name && container.ready)
    );
    if (!runningPod) throw new Error(`No ready pod is running the deployed application container ${applicationContainer.name}`);
    const podContainer = (runningPod.spec?.containers || []).find(container => container.name === applicationContainer.name);
    if (podContainer?.image !== imageTag) throw new Error(`Running pod does not reference expected image ${imageTag}`);
    const podContainerStatus = (runningPod.status?.containerStatuses || []).find(container => container.name === applicationContainer.name);
    const runningImageId = String(podContainerStatus?.imageID || "").trim();
    if (!runningImageId) throw new Error(`Running pod did not report an image ID for ${applicationContainer.name}`);

    const service = JSON.parse(await execute("kubectl get service", "kubectl", ["get", "service", safeAppName, "--namespace", namespace, "-o", "json"], cloneDir, 30000));
    const nodePort = service.spec?.ports?.[0]?.nodePort;
    if (service.metadata?.name !== safeAppName || service.metadata?.namespace !== namespace || service.spec?.type !== "NodePort" || !Number.isInteger(nodePort)) {
      throw new Error(`Service ${safeAppName} is not a valid NodePort service`);
    }

    // 10. Discover the NodePort endpoint directly. Avoid minikube service --url,
    // which can create a Docker-driver tunnel and block for up to a minute.
    console.log("[deploy] Getting Minikube IP for NodePort service");
    let minikubeIp;
    try {
      minikubeIp = String(await execute("minikube ip", "minikube", ["ip"], cloneDir, 10000)).trim();
    } catch (ipError) {
      throw new Error("Unable to discover Minikube IP for service " + safeAppName + ": " + ipError.message);
    }
    if (!minikubeIp || /\s/.test(minikubeIp)) throw new Error("Invalid Minikube IP for service " + safeAppName);
    let stagingUrl = "http://" + minikubeIp + ":" + nodePort;
    stagingUrl = String(stagingUrl || "").split("\n")[0].trim();
    let parsedUrl;
    try { parsedUrl = new URL(stagingUrl); } catch { throw new Error(`Invalid staging URL for service ${safeAppName}`); }
    if (!["http:", "https:"].includes(parsedUrl.protocol) || !parsedUrl.hostname || stagingUrl.includes("minikube-url-unavailable")) {
      throw new Error(`Invalid staging URL for service ${safeAppName}`);
    }
    stagingUrl = parsedUrl.toString().replace(/\/$/, "");

    let readinessError;
    for (let attempt = 1; attempt <= 10; attempt++) {
      try {
        const response = await axios.get(stagingUrl, { timeout: 5000, validateStatus: code => code >= 200 && code < 400 });
        if (response.status >= 200 && response.status < 400) { readinessError = null; break; }
      } catch (err) { readinessError = err; }
      if (attempt < 10) await new Promise(resolve => setTimeout(resolve, 3000));
    }
    if (readinessError) throw new Error(`Staging URL ${stagingUrl} did not become ready: ${readinessError.message}`);

    console.log(`[deploy] Staging URL: ${stagingUrl}`);

    // 11. Record deployment in DB
    await pool.query(
      `INSERT INTO deployment_history
       (project_id, pipeline_execution_id, deployment_attempt, status, deployed_at, staging_url, dockerfile_source, manifest_source, app_name, image_tag)
       VALUES ($1, $2, $3, 'SUCCESS', NOW(), $4, $5, $6, $7, $8)`,
      [projectId, pipelineExecutionId, imageIdentity.attempt, stagingUrl, dockerfileSource, manifestSource, safeAppName, imageTag]
    );

    if(provenance?.artifact){
      const deployed=await pool.query("SELECT id FROM deployment_history WHERE project_id=$1 AND pipeline_execution_id=$2 AND status='SUCCESS' ORDER BY id DESC LIMIT 1",[projectId,pipelineExecutionId]);
      await require('./stageProvenance').attest(pool,{projectId,executionId:pipelineExecutionId,userId},'Deploy',deployed.rows[0].id,{commit:sourceCommit,reports:[{kind:'generated-staging-verification',bytes:Buffer.from(JSON.stringify({sourceCommit,localImageId,runningImageId,artifact:provenance.artifact.sha256,stagingUrl}))}],reportHash:require('./deploymentEligibility').digest({sourceCommit,localImageId,runningImageId,artifact:provenance.artifact.sha256,stagingUrl}),tool:`Pinned nginx image; built ${localImageId}; running ${runningImageId}`});
    }

    // 12. Update project's target_url for DAST
    await pool.query(
      "UPDATE projects SET target_url = $1 WHERE id = $2 AND user_id = $3",
      [stagingUrl, projectId, userId]
    );

    return {
      stagingUrl, dockerfileSource, manifestSource, safeAppName, namespace,
      imageTag, sourceCommit, localImageId, runningImageId, imageScan,
      executionId: imageIdentity.executionId, attempt: imageIdentity.attempt,
    };

  } catch (err) {
    console.error(`[deploy] Deployment failed for project ${projectId}:`, err.message);

    // Record failure in DB
    if (authorizedProject && pipelineContextValidated) {
      try {
        await pool.query(
          `INSERT INTO deployment_history (project_id, pipeline_execution_id, deployment_attempt, status, deployed_at, failure_reason)
           VALUES ($1, $2, $3, 'FAILED', NOW(), $4)`,
          [projectId, pipelineExecutionId, Number.isInteger(options.attempt) ? options.attempt : 1, err.message || "Unknown error"]
        );
      } catch {}
    }

    throw err;
  } finally {
    // Cleanup clone directory
    if (cloneDir && fs.existsSync(cloneDir)) {
      try { fs.rmSync(cloneDir, { recursive: true, force: true }); } catch {}
    }
  }
}

module.exports = { deployProject, detectContainerPort, generateDockerfileContent, generateK8sManifests, getProjectNamespace };
