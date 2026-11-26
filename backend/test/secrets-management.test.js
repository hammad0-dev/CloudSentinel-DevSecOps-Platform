// Module 9 / SRS FR-20: Secrets Management screen backend. kubectl and the database are mocked.
const assert = require("node:assert/strict");
const test = require("node:test");
const s = require("../services/secretsInventory");

const NOW = new Date("2026-11-27T10:00:00Z");
const line = (...cols) => cols.join("\t");
const SECRETS_OUT = [
  line("p24-app-secrets", "Opaque", "2026-11-01T10:00:00Z", "...", "ExternalSecret,", "reconcile.external-secrets.io/created-by=abc;", "2026-11-01T10:00:00Z,2026-11-20T10:00:00Z,"),
  line("registry-cred", "kubernetes.io/dockerconfigjson", "2026-10-01T10:00:00Z", ".", "", "", "2026-10-01T10:00:00Z,"),
  line("plain", "Opaque", "2026-08-01T10:00:00Z", "", "", "", ""),
].join("\n") + "\n";

function kube({ context = "minikube", namespaces = "cloudsentinel-p-24\n", secrets = SECRETS_OUT, eso = false, fail } = {}) {
  const calls = [];
  const run = async (args) => {
    calls.push(args);
    if (fail) throw fail;
    if (args[0] === "config") return `${context}\n`;
    if (args.includes("namespaces")) return namespaces;
    if (args.includes("secrets")) return secrets;
    if (args.includes("crd")) { if (eso) return "customresourcedefinition/externalsecrets.external-secrets.io"; throw new Error("NotFound"); }
    throw new Error(`unexpected ${args.join(" ")}`);
  };
  return { run, calls };
}

function db({ owner = 5, policies = [], policyError, writes = [] } = {}) {
  return {
    writes,
    query: async (sql, params) => {
      if (sql.startsWith("SELECT id, user_id FROM projects")) return { rows: params[0] === 24 ? [{ id: 24, user_id: owner }] : [] };
      if (sql.startsWith("SELECT namespace, secret_name")) { if (policyError) throw policyError; return { rows: policies }; }
      if (/INSERT INTO secret_policies|DELETE FROM secret_policies/.test(sql)) {
        if (policyError) throw policyError;
        writes.push({ sql, params });
        return { rows: [{ rotation_days: params[3], expires_at: params[4], updated_at: NOW.toISOString() }] };
      }
      if (sql.includes("FROM secret_policies") && sql.includes("expires_at <=")) { if (policyError) throw policyError; return { rows: policies }; }
      throw new Error(`unexpected SQL ${sql}`);
    },
  };
}
const owner = { id: 5, email: "owner@example.test" };
const stranger = { id: 6, email: "someone@example.test" };
const missingTable = Object.assign(new Error('relation "secret_policies" does not exist'), { code: "42P01" });

test("kubectl template never prints secret data, key names or annotations", () => {
  assert.ok(s.TEMPLATE.includes("{{range $k, $v := .data}}.{{end}}"), "one '.' per data key, nothing else");
  assert.ok(!/annotations/.test(s.TEMPLATE));
  assert.ok(!/\.data\./.test(s.TEMPLATE) && !/stringData/.test(s.TEMPLATE));
});

test("parseLines returns metadata only: keys count, source, masked value, last change time", () => {
  const rows = s.parseLines(SECRETS_OUT, "cloudsentinel-p-24");
  assert.deepEqual(rows.map(r => [r.name, r.keysCount, r.source, r.value, r.lastChangedAt]), [
    ["p24-app-secrets", 3, "External Secrets Operator", s.MASK, "2026-11-20T10:00:00Z"],
    ["registry-cred", 1, "Image pull secret", s.MASK, "2026-10-01T10:00:00Z"],
    ["plain", 0, "Kubernetes Secret (kubectl or an operator)", s.MASK, "2026-08-01T10:00:00Z"],
  ]);
  assert.throws(() => s.parseLines(line("Bad_Name", "Opaque", "x", ""), "ns"), /Unexpected secret name/);
  assert.throws(() => s.parseLines(line("ok", "Opaque", "2026-01-01T00:00:00Z", "..x"), "ns"), /Unexpected key count/);
});

test("roles: owner and SECRETS_ADMIN_EMAILS admins only; others get 404; invalid id 400", async () => {
  assert.deepEqual(await s.access(db(), owner, "24"), { projectId: 24, role: "owner" });
  assert.equal((await s.access(db(), stranger, "24")).code, 404);
  process.env.SECRETS_ADMIN_EMAILS = " Someone@Example.test ,x@y.z";
  try { assert.deepEqual(await s.access(db(), stranger, "24"), { projectId: 24, role: "admin" }); }
  finally { delete process.env.SECRETS_ADMIN_EMAILS; }
  assert.equal((await s.access(db(), owner, "24x")).code, 400);
  assert.equal((await s.access(db(), owner, "99")).code, 404);
});

test("expiry status: not set, ok, expiring soon (warn window), today, expired", () => {
  assert.equal(s.expiryStatus(null, NOW).status, "NOT_SET");
  assert.deepEqual(s.expiryStatus("2027-01-30", NOW, 14), { status: "OK", daysLeft: 64, text: "Expires in 64 day(s)" });
  assert.equal(s.expiryStatus("2026-12-05", NOW, 14).status, "EXPIRING_SOON");
  assert.equal(s.expiryStatus("2026-11-27", NOW, 14).text, "Expires today");
  assert.deepEqual(s.expiryStatus("2026-11-20", NOW, 14), { status: "EXPIRED", daysLeft: -7, text: "Expired 7 day(s) ago" });
});

test("rotation status from the policy and the last change time", () => {
  assert.equal(s.rotationStatus(null, "2026-11-01T00:00:00Z", NOW).status, "NO_POLICY");
  assert.equal(s.rotationStatus(30, null, NOW).status, "UNKNOWN");
  assert.equal(s.rotationStatus(30, "2026-11-20T10:00:00Z", NOW).status, "WITHIN_POLICY");
  const overdue = s.rotationStatus(30, "2026-08-01T10:00:00Z", NOW);
  assert.equal(overdue.status, "OVERDUE");
  assert.match(overdue.text, /overdue by \d+ day/);
});

test("listing joins policies, computes statuses, never returns values, and states the rotation status honestly", async () => {
  const k = kube();
  const r = await s.projectSecrets(db({ policies: [{ namespace: "cloudsentinel-p-24", secret_name: "plain", rotation_days: 30, expires_at: new Date("2026-12-01T00:00:00Z"), updated_at: NOW }] }), owner, "24", { run: k.run, now: NOW });
  assert.equal(r.code, 200);
  assert.equal(r.body.status, "observed");
  assert.equal(r.body.role, "owner");
  assert.equal(r.body.canEditPolicies, true);
  const plain = r.body.secrets.find(x => x.name === "plain");
  assert.equal(plain.expiry.status, "EXPIRING_SOON");
  assert.equal(plain.rotation.status, "OVERDUE");
  assert.ok(r.body.secrets.every(x => x.value === s.MASK && !("data" in x)));
  assert.equal(r.body.rotation.available, false);
  assert.match(r.body.rotation.text, /^Not available on this cluster: minikube has no External Secrets Operator/);
  // Every kubectl call pins the expected context, except the current-context check itself.
  assert.ok(k.calls.filter(a => a[0] !== "config").every(a => a[0] === "--context" && a[1] === "minikube"));
  assert.ok(k.calls.some(a => a.includes("secrets") && a.at(-1).startsWith("go-template=")));
  assert.ok(!k.calls.some(a => a.includes("-o") && a[a.indexOf("-o") + 1] === "json" && a.includes("secrets")), "secrets are never read as JSON");
});

test("with ESO installed the rotation card names the script and the refresh behaviour", async () => {
  const r = await s.projectSecrets(db(), owner, "24", { run: kube({ eso: true }).run, now: NOW });
  assert.equal(r.body.rotation.available, true);
  assert.match(r.body.rotation.command, /^scripts\/rotate-secret\.sh --secret-id cloudsentinel\/p-24\//);
});

test("context mismatch, no namespace and missing migration are reported, not guessed", async () => {
  const mismatch = await s.projectSecrets(db(), owner, "24", { run: kube({ context: "eks-cloudsentinel" }).run, now: NOW });
  assert.equal(mismatch.body.status, "not_connected");
  assert.match(mismatch.body.reason, /Current kube context is not minikube/);
  const none = await s.projectSecrets(db(), owner, "24", { run: kube({ namespaces: "" }).run, now: NOW });
  assert.equal(none.body.status, "not_deployed");
  const noTable = await s.projectSecrets(db({ policyError: missingTable }), owner, "24", { run: kube().run, now: NOW });
  assert.equal(noTable.body.policiesAvailable, false);
  assert.equal(noTable.body.canEditPolicies, false);
  const forged = await s.projectSecrets(db(), owner, "24", { run: kube({ namespaces: "cloudsentinel-p-25\n" }).run, now: NOW });
  assert.equal(forged.body.status, "not_connected");
});

test("setPolicy: validates input, ownership, namespace and existence; upserts or clears", async () => {
  const k = kube();
  assert.equal((await s.setPolicy(db(), stranger, "24", { namespace: "cloudsentinel-p-24", name: "plain", rotationDays: 30 }, { run: k.run })).code, 404);
  assert.equal((await s.setPolicy(db(), owner, "24", { namespace: "cloudsentinel-p-24", name: "plain", rotationDays: 0 }, { run: k.run })).code, 400);
  assert.equal((await s.setPolicy(db(), owner, "24", { namespace: "cloudsentinel-p-24", name: "plain", expiresAt: "2026-13-45" }, { run: k.run })).code, 400);
  assert.equal((await s.setPolicy(db(), owner, "24", { namespace: "cloudsentinel-p-9", name: "plain", rotationDays: 30 }, { run: k.run })).code, 400);
  assert.equal((await s.setPolicy(db(), owner, "24", { namespace: "cloudsentinel-p-24", name: "ghost", rotationDays: 30 }, { run: k.run })).code, 404);
  const d = db();
  const ok = await s.setPolicy(d, owner, "24", { namespace: "cloudsentinel-p-24", name: "plain", rotationDays: "90", expiresAt: "2027-02-01" }, { run: k.run });
  assert.equal(ok.code, 200);
  assert.deepEqual(d.writes[0].params, [24, "cloudsentinel-p-24", "plain", 90, "2027-02-01", 5]);
  const cleared = await s.setPolicy(d, owner, "24", { namespace: "cloudsentinel-p-24", name: "plain", rotationDays: null, expiresAt: "" }, { run: k.run });
  assert.equal(cleared.body.policy, null);
  assert.match(d.writes[1].sql, /^DELETE FROM secret_policies/);
  const noTable = await s.setPolicy(db({ policyError: missingTable }), owner, "24", { namespace: "cloudsentinel-p-24", name: "plain", rotationDays: 30 }, { run: k.run });
  assert.equal(noTable.code, 503);
  assert.match(noTable.body.error, /migration 025/);
  const down = await s.setPolicy(db(), owner, "24", { namespace: "cloudsentinel-p-24", name: "plain", rotationDays: 30 }, { run: kube({ fail: new Error("connection refused") }).run });
  assert.equal(down.code, 503);
});

test("expiry notifier raises one deduplicated alert per expiring or expired secret (metadata only)", async () => {
  const d = db({ policies: [
    { project_id: 24, namespace: "cloudsentinel-p-24", secret_name: "plain", expires_at: new Date("2026-11-20T00:00:00Z") },
    { project_id: 24, namespace: "cloudsentinel-p-24", secret_name: "registry-cred", expires_at: "2026-12-03" },
  ] });
  const found = await s.expiryDetections(d, NOW, 14);
  assert.deepEqual(found.map(x => [x.rule, x.severity, x.details.key]), [
    ["secret_expiring", "HIGH", "24/cloudsentinel-p-24/plain/2026-11-20"],
    ["secret_expiring", "MEDIUM", "24/cloudsentinel-p-24/registry-cred/2026-12-03"],
  ]);
  assert.match(found[0].details.description, /expired 7 day\(s\) ago/);
  assert.deepEqual(await s.expiryDetections(db({ policyError: missingTable }), NOW), []);
});

test("SECRETS_EXPIRY_WARN_DAYS is bounded, default 14", () => {
  assert.equal(s.warnDays({}), 14);
  assert.equal(s.warnDays({ SECRETS_EXPIRY_WARN_DAYS: "30" }), 30);
  assert.equal(s.warnDays({ SECRETS_EXPIRY_WARN_DAYS: "-1" }), 14);
  assert.equal(s.warnDays({ SECRETS_EXPIRY_WARN_DAYS: "abc" }), 14);
});
