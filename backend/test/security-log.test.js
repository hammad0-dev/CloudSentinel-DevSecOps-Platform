// Module 11 FE-4: Loki push client (URL forms, failure warning). node --test test/security-log.test.js
process.env.APP_LOG_FILE = "off";
process.env.APP_LOG_STDOUT = "off";
const test = require("node:test");
const assert = require("node:assert/strict");
const securityLog = require("../services/securityLog");

const PUSH = "http://loki:3100/loki/api/v1/push";

test("lokiPushUrl accepts a base URL or the full push URL", () => {
  for (const input of ["http://loki:3100", "http://loki:3100/", PUSH, PUSH + "/", ` ${PUSH} `]) {
    assert.equal(securityLog.lokiPushUrl(input), PUSH, input);
  }
  assert.equal(securityLog.lokiPushUrl("http://gw/prefix"), "http://gw/prefix/loki/api/v1/push");
});

for (const [form, url] of [["base", "http://loki:3100"], ["full push", PUSH]]) {
  test(`push posts once to /loki/api/v1/push with LOKI_PUSH_URL as ${form} URL`, async () => {
    securityLog._reset();
    process.env.LOKI_PUSH_URL = url;
    const calls = [];
    securityLog._setPoster(async (target, body) => { calls.push({ target, body }); });
    securityLog.logEvent({ event: "auth_login_failed" });
    securityLog.logEvent({ event: "webhook_signature_invalid" });
    await securityLog.flushPush();
    securityLog._reset();
    delete process.env.LOKI_PUSH_URL;
    assert.equal(calls.length, 1);
    assert.equal(calls[0].target, PUSH);
    const [stream] = calls[0].body.streams;
    assert.equal(stream.stream.source, "backend");
    assert.equal(stream.values.length, 2);
    assert.match(stream.values[0][1], /"event":"auth_login_failed"/);
  });
}

test("push failure logs one structured warn per minute and is not re-pushed", async () => {
  securityLog._reset();
  process.env.LOKI_PUSH_URL = "http://user:secret@loki:3100";
  let posts = 0;
  securityLog._setPoster(async () => {
    posts += 1;
    throw Object.assign(new Error("Request failed with status code 404"), { response: { status: 404 } });
  });
  const t0 = Date.now();
  const failAt = async (ms) => {
    securityLog.logEvent({ event: "http_request" });
    await securityLog.flushPush({ now: () => t0 + ms });
  };
  await failAt(0);
  await failAt(30 * 1000);
  await failAt(61 * 1000);
  const warns = securityLog.recentEvents(Infinity).filter((e) => e.event === "loki_push_failed");
  await securityLog.flushPush();
  securityLog._reset();
  delete process.env.LOKI_PUSH_URL;

  assert.equal(posts, 3);
  assert.equal(warns.length, 2);
  assert.equal(warns[0].level, "warn");
  assert.deepEqual(warns[0].detail, {
    url: "http://loki:3100/loki/api/v1/push",
    status: 404,
    code: null,
    message: "Request failed with status code 404",
    droppedLines: 1,
  });
  assert.equal(posts, 3, "the warn itself is never queued for push");
});

test("a dead Loki endpoint pauses pushing with back-off and resumes after a success", async () => {
  securityLog._reset();
  process.env.LOKI_PUSH_URL = "http://127.0.0.1:3100";
  let posts = 0, up = false;
  securityLog._setPoster(async () => { posts += 1; if (!up) throw Object.assign(new Error("connect ECONNREFUSED 127.0.0.1:3100"), { code: "ECONNREFUSED" }); });
  const t0 = Date.now();
  const at = async (ms) => { securityLog.logEvent({ event: "http_request" }, { now: t0 + ms }); await securityLog.flushPush({ now: () => t0 + ms }); };
  await at(0); await at(2000); await at(4000);             // 3 consecutive failures -> pause 60 s
  await at(10000); await at(50000);                        // paused: no request is sent
  const pausedPosts = posts;
  const paused = securityLog.recentEvents(Infinity).filter((e) => e.event === "loki_push_paused");
  await at(65000);                                         // after the pause: one try, fails again -> pause 120 s
  await at(120000);                                        // still paused
  const secondPause = securityLog.recentEvents(Infinity).filter((e) => e.event === "loki_push_paused");
  up = true;
  await at(190000);                                        // after the second pause: succeeds and resumes
  const resumed = securityLog.recentEvents(Infinity).filter((e) => e.event === "loki_push_resumed");
  await at(192000);
  const finalPosts = posts;
  securityLog._reset();
  delete process.env.LOKI_PUSH_URL;
  assert.equal(pausedPosts, 3);
  assert.equal(paused.length, 1);
  assert.equal(paused[0].detail.pauseSeconds, 60);
  assert.equal(paused[0].detail.url, "http://127.0.0.1:3100/loki/api/v1/push");
  assert.equal(secondPause.length, 2);
  assert.equal(secondPause[1].detail.pauseSeconds, 120);
  assert.equal(resumed.length, 1);
  assert.equal(finalPosts, 6, "pushes resume normally after a success");
});

test("LOKI_PUSH_URL unset, empty or off disables pushing cleanly", async () => {
  for (const value of [undefined, "", "off", "OFF", "none", "false"]) {
    securityLog._reset();
    if (value === undefined) delete process.env.LOKI_PUSH_URL; else process.env.LOKI_PUSH_URL = value;
    let posts = 0;
    securityLog._setPoster(async () => { posts += 1; });
    securityLog.logEvent({ event: "http_request" });
    await securityLog.flushPush();
    assert.equal(posts, 0, String(value));
    assert.equal(securityLog.recentEvents(Infinity).filter((e) => e.event.startsWith("loki_push")).length, 0);
  }
  securityLog._reset();
  delete process.env.LOKI_PUSH_URL;
});
