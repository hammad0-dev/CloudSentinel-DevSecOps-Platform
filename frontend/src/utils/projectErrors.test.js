import test from "node:test";
import assert from "node:assert/strict";
import { deleteErrorMessage } from "./projectErrors.js";
test("delete toast is a readable sentence, never a raw trigger code", () => {
  const readable = "This project can't be deleted because it has completed security scans. Their results are kept as audit evidence and cannot be removed.";
  assert.equal(deleteErrorMessage({ response: { status: 409, data: { error: readable } } }), readable);
  assert.match(deleteErrorMessage({ response: { status: 409, data: { error: "COMPLETED_SCAN_EVIDENCE_IMMUTABLE" } } }), /^This project can't be deleted/);
  assert.equal(deleteErrorMessage({ response: { status: 500, data: { error: "COMPLETED_SCAN_EVIDENCE_IMMUTABLE" } } }), "Could not delete project on the server.");
  assert.match(deleteErrorMessage({ response: { status: 401 } }), /Session expired/);
  assert.equal(deleteErrorMessage(new Error("Network Error")), "Could not delete project on the server.");
});
