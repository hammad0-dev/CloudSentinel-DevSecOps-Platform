"use strict";
const fs = require('fs/promises');
const os = require('os');
const path = require('path');
const { connectCapture } = require('./dastAcceptanceClient');

async function saveConnectDiagnostic(probe, { scanId, provenance, gateway }) {
  if (!/^[a-z0-9_.-]+$/i.test(scanId)) throw Object.assign(new Error('invalid diagnostic identity'), { code: 'INVALID_IDENTITY' });
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), `cloudsentinel-connect-diagnostic-${scanId}-`));
  try {
    await fs.chmod(directory, 0o700);
    const file = path.join(directory, 'connect.json');
    const native = connectCapture(probe);
    await fs.writeFile(file, JSON.stringify({ schemaVersion: '1.0', mode: 'connect-diagnostic', fullContainment: false,
      provenance, scanId, gateway, actual: probe.actual, complete: probe.complete, sourceId: probe.sourceId,
      httpStatus: probe.httpStatus ?? null, connectStatus: probe.connectStatus ?? null, exitCode: probe.exitCode ?? null,
      nativeEvidence:probe.nativeEvidence ?? null, connectEvidence: probe.connectEvidence ?? null, captureAvailable: !!native || !!probe.nativeEvidence, native: native ?? null }, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
    await fs.chmod(file, 0o600);
    return file;
  } catch (_) {
    await fs.rm(directory, { recursive: true, force: true });
    throw Object.assign(new Error('unable to save private CONNECT diagnostic'), { code: 'DIAGNOSTIC_WRITE_FAILED' });
  }
}
module.exports = { saveConnectDiagnostic };
