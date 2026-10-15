const assert = require("node:assert/strict");
const { EventEmitter } = require("node:events");
const test = require("node:test");

const childProcess = require("node:child_process");
const gitHelperPath = require.resolve("../services/gitHelper");
const originalSpawn = childProcess.spawn;

function loadGitHelper(spawn) {
  childProcess.spawn = spawn;
  delete require.cache[gitHelperPath];
  return require("../services/gitHelper");
}

function fakeChild(onStart) {
  const child = new EventEmitter();
  child.stdout = new EventEmitter();
  child.stderr = new EventEmitter();
  child.kill = () => {};
  queueMicrotask(() => onStart(child));
  return child;
}

test.afterEach(() => {
  childProcess.spawn = originalSpawn;
  delete require.cache[gitHelperPath];
});

test("authenticated private clone keeps credentials for git but redacts them for display", async () => {
  const fakeToken = "ghp_FAKE_TOKEN_FOR_REGRESSION_ONLY";
  let spawnedArgs;
  const gitHelper = loadGitHelper((_command, args) => {
    spawnedArgs = args;
    return fakeChild(child => child.emit("close", 0));
  });
  const cloneUrl = gitHelper.resolveCloneUrl({
    repo_url: "https://github.com/example/private-repo.git",
    github_token: fakeToken,
  });

  await gitHelper.gitCloneAsync(cloneUrl, "/tmp/cloudsentinel-private-clone");
  assert.ok(spawnedArgs.includes(cloneUrl));
  assert.ok(cloneUrl.includes(fakeToken));
  assert.equal(gitHelper.redactGitCredentials(cloneUrl).includes(fakeToken), false);
  assert.equal(
    gitHelper.redactGitCredentials(cloneUrl),
    "https://***@github.com/example/private-repo.git"
  );
});

test("failed git clone redacts credentials from git output", async () => {
  const fakeToken = "ghp_FAKE_TOKEN_FOR_REGRESSION_ONLY";
  const cloneUrl = `https://x-access-token:${fakeToken}@github.com/example/private-repo.git`;
  const gitHelper = loadGitHelper(() => fakeChild(child => {
    child.stderr.emit("data", `fatal: unable to access '${cloneUrl}': Authentication failed`);
    child.emit("close", 128);
  }));

  await assert.rejects(
    gitHelper.gitCloneAsync(cloneUrl, "/tmp/cloudsentinel-private-clone"),
    error => {
      assert.equal(error.message.includes(fakeToken), false);
      assert.match(error.message, /https:\/\/\*\*\*@github\.com/);
      return true;
    }
  );
});
test("SAST git-clone failure output redacts credentials before it can reach an API response", async () => {
  const fakeToken = "ghp_FAKE_TOKEN_FOR_REGRESSION_ONLY";
  const cloneUrl = `https://x-access-token:${fakeToken}@github.com/example/private-repo.git`;
  const pipelinePath = require.resolve("../routes/sast/pipeline");
  childProcess.spawn = () => fakeChild(child => {
    child.stderr.emit("data", `fatal: unable to access '${cloneUrl}': Authentication failed`);
    child.emit("close", 128);
  });
  delete require.cache[pipelinePath];
  const { spawnWithTimeout } = require("../routes/sast/pipeline");
  try {
    await assert.rejects(
      spawnWithTimeout("git clone", "git", ["clone", cloneUrl], {}, 1000),
      error => {
        assert.equal(error.message.includes(fakeToken), false);
        assert.match(error.message, /https:\/\/\*\*\*@github\.com/);
        return true;
      }
    );
  } finally {
    delete require.cache[pipelinePath];
  }
});