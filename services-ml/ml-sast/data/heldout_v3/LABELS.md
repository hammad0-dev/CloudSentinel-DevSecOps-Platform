# ml-sast v3 held-out sets (RealVuln, frozen before any v3 training)

**Source:** RealVuln Benchmark `kolega-ai/Real-Vuln-Benchmark` @ `0152445` (Apache-2.0), ground truth v3.0.0.
- **Apps:** only the community, human-authored apps that were never used anywhere in this project. Each app is
  pinned to the commit in its RealVuln ground truth.
- **Where the code is:** sources and rows stay on D: (`/mnt/d/cs-data/sast-v3/heldout/`) or gitignored. Only
  `FREEZE.json` and this file are committed.

**Sets:**

| Set | Apps | Units | Scored | Vulnerable | Excluded |
|---|---|---|---|---|---|
| python | 20 apps (see FREEZE.json) | 831 | 660 | 132 | 171 |
| node | ninjasworkout, vuln-node-express, vulnerable-nodejs, VulnNodeApp | 163 | 137 | 19 | 26 |

**Labels** are built by `scripts/v3/build_heldout_v3.py` with the same unit method as v2's fresh set:
- **Vulnerable:** a function or `<module>` unit overlapping a RealVuln vulnerable finding gets the finding's target
  class (via the v2 CWE map).
- **Excluded:**
  - units overlapping only out-of-class findings;
  - units where a target CWE appears only as an acceptable alternative;
  - units overlapping non-scoring entries.
- **Safe:** every other unit, false-positive traps included.

**Spot-check before freezing:** 10 random vulnerable units read against their code and finding; all were correct
(details in the final report).

**Known effects:**
- **Broad entries:** 8 findings span more than 30 lines. The 2 in a target class (hard-coded credentials in djangoat
  `seed.py` and vuln-node-express `bootstrapdb.js`) cover functions that do hold the literals. The 6 out-of-class
  ones (rate limiting, IDOR, CSRF) only exclude units.
- **Unmapped findings:** 46 Python and 9 Node.js target-class findings fall outside every code unit (templates,
  config files, skipped directories) and are not scored.
- **Licences:** several apps state no licence. They are used for local evaluation only and are never trained on or
  committed.
