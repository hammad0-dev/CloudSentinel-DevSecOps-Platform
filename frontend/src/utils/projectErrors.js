// Toast text for a failed project delete. A raw database/trigger code (e.g. COMPLETED_SCAN_EVIDENCE_IMMUTABLE)
// is never shown; the server sends a sentence for the known cases.
const CODE = /^[A-Z][A-Z0-9_]{3,}$/;
export function deleteErrorMessage(error) {
  const status = error?.response?.status, msg = error?.response?.data?.error;
  if (status === 401) return "Session expired. Sign in again, then delete the project.";
  if (typeof msg === "string" && msg.trim() && !CODE.test(msg.trim())) return msg;
  if (status === 409) return "This project can't be deleted because it has completed security scans. Their results are kept as audit evidence.";
  return "Could not delete project on the server.";
}
