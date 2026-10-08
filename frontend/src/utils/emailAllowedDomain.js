// Allows any syntactically valid email address.
// Previously restricted to @gmail.com only — removed to support all users.

export const GMAIL_ONLY_MESSAGE = "Please enter a valid email address.";

export function isGmailAddress(email) {
  // Accept any address that has a local part + @ + domain with a dot
  const e = String(email ?? "").trim();
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e);
}
