'use strict';

function parseVersion(value) {
  const match = String(value).trim().match(/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/);
  if (!match) throw new Error(`Invalid semantic version: ${value}`);
  return match.slice(1, 4).map(Number);
}

function compare(a, b) {
  const left = parseVersion(a), right = parseVersion(b);
  for (let i = 0; i < 3; i += 1) if (left[i] !== right[i]) return left[i] > right[i] ? 1 : -1;
  return 0;
}

function satisfiesMinimum(version, minimum) { return compare(version, minimum) >= 0; }

module.exports = { parseVersion, compare, satisfiesMinimum };
