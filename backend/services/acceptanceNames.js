"use strict";
const { createHash } = require('crypto');
const VALID = /^[a-z0-9][a-z0-9_.-]{0,62}$/;
function checked(value) {
  if (typeof value !== 'string' || !VALID.test(value)) throw Object.assign(new Error('unsafe acceptance identity'), { code: 'INVALID_ID' });
  return value;
}
function bounded(name, prefix, identity, role) {
  const digest = createHash('sha256').update(JSON.stringify(identity)).digest('hex').slice(0,32);
  return checked(name.length <= 63 ? name : `${prefix}-${digest}-${role}`);
}
function containerName(scanId, role) {
  checked(scanId);
  if (!['gateway','fixture','client'].includes(role)) throw Object.assign(new Error('invalid container role'), { code:'INVALID_ROLE' });
  return bounded(`cs-${role}-${scanId}`, 'cs', [scanId,role], role);
}
function validateNames(input) {
  for (const key of ['projectId','executionId','scanId']) checked(input?.[key]);
  const names = ['gateway','fixture','client'].map(role=>containerName(input.scanId,role));
  // Validate network-name construction before staging or any resource creation.
  const networkIdentity = { ...input, hash:'0'.repeat(12) };
  for (const role of ['scanner','fixture']) names.push(require('./ownedDockerNetworks').names(networkIdentity,role));
  if (new Set(names).size !== names.length) throw Object.assign(new Error('resource name collision'),{code:'INVALID_ID'});
  return names;
}
module.exports = { checked, bounded, containerName, validateNames };
