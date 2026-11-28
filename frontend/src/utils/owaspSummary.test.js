import test from "node:test";
import assert from "node:assert/strict";
import { owaspCardText } from "./owaspSummary.js";
test("OWASP card: categories with findings, never a failed / 0% pass rate", () => {
  const t = owaspCardText({ matching: { owasp: { matched: 3 } }, owaspMetrics: { PASS: 0, FAIL: 3, NOT_ASSESSED: 7, passRate: 0 } });
  assert.equal(t.description, "3/10 categories matched · 3 categories with findings · 7 without findings (not assessed) — project-category slots");
  assert.doesNotMatch(t.description + t.note, /failed|pass rate|0%/);
  assert.match(t.note, /not a pass\/fail result/);
  assert.match(owaspCardText({ owaspMetrics: { FAIL: 1 } }).description, /1 category with findings/);
});
