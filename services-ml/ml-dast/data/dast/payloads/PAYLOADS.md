# ml-dast payloads

`payloads.json` holds 28 SQL injection payloads (CWE-89) and 16 reflected-XSS payloads (CWE-79).

**Disclosure:** the two parenthesis-depth boolean pairs (`') OR 1=1-- -` and `')) OR 1=1-- -`, each
with its false twin) were added before any data was collected, but after I tested Juice Shop's
search endpoint by hand. Its query sits inside two parentheses. These are standard prefix depths
(sqlmap tries up to three), but knowing about this endpoint motivated adding them. That is a
possible source of optimism for Juice Shop's CWE-89 results.

- **Source:** I wrote this list for CloudSentinel; it is distributed with the repository. Its
  categories (error-based, boolean pairs, UNION, time-based; tag, attribute, script-string,
  filter-evasion) follow the structure of PayloadsAllTheThings, which is MIT-licensed
  (https://github.com/swisskyrepo/PayloadsAllTheThings). No PayloadsAllTheThings or SecLists file was
  downloaded or copied.
- **Marker:** `{M}` is replaced by a unique token for every request, so a reflection can be traced to
  the request that caused it.
- **Boolean pairs:** these share a `pair` id, with `truth: true` and `truth: false`. The feature
  extractor compares the two responses with each other and with the baseline, which is how blind
  injection becomes visible.
- **Benign probes:** every injection point first gets two benign requests:
  - the original value, sent twice, to measure the noise in length and time;
  - a random token, to test whether the parameter is reflected at all.
- **Gentle on purpose:**
  - time payloads sleep 1 second;
  - there are no stacked writes, no `DROP`, `DELETE` or `UPDATE`, and no file or OS functions.
- **Phase 2 (only after CWE-89 and CWE-79 work):** CWE-78 and CWE-22 payloads will be added here
  with the same rules: harmless commands only (`id`, `sleep 1`) and read-only path probes.
