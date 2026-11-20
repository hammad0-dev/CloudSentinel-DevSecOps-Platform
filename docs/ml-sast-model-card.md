# Model card: ml-sast 1.0.0 (`ml-sast-rf`)

Function-level vulnerability classifier for the CloudSentinel `ml-sast` service (`SAST_ENGINE=ml`).
**SonarQube stays the default SAST engine.** On held-out code this model finds about a third of the
vulnerable functions, and it is not good enough to replace a rule-based scanner as a pipeline gate.

| | |
|---|---|
| Artifact | `services-ml/ml-sast/models/release/model.joblib` (gitignored), metadata in `model.json` |
| SHA-256 | `f8a6c5454a158812…` (full value in `/model-info` and `reports/selected_model.json`) |
| Model | Random Forest (400 trees, `max_depth=40`, `min_samples_leaf=2`, balanced class weights) over TF-IDF code tokens (1–2-grams, 8k features), 31 hand-made security features and a language flag |
| Decision rule | Most likely vulnerable class if its probability is ≥ 0.3 (chosen on validation data), else `safe`. Override with `ML_SAST_CONFIDENCE_THRESHOLD`. |
| Targets | Python and JavaScript (`.py .js .mjs .cjs .jsx`), one prediction per function, plus one for top-level code (`<module>`) |
| Classes | `safe`, CWE-89 SQL injection, CWE-79 XSS, CWE-78 command injection, CWE-22 path traversal, CWE-798 hardcoded credentials, CWE-502 insecure deserialization, CWE-327 weak crypto (including non-cryptographic randomness for tokens) |
| Selection | Highest held-out macro-F1 at the model's own threshold, out of 5 candidates. The candidates are statistically tied (see Results) |

## Data

The full counts are in `services-ml/ml-sast/data/manifest.json`.

| Source | What | Rows (train / val / test) |
|---|---|---|
| CrossVul (Zenodo 4734050, 367 MB) | Real fix commits. Each Python/JS function that changed in a fix gives a vulnerable row (before the fix) and a safe row (after) | 665 / 140 / 138 |
| Synthetic (`sastml/synthetic.py`) | 66 template families covering Flask/Django/stdlib and Express/child_process/fs/crypto, rendered as vulnerable/safe pairs with randomized names, input sources, wrappers and filler code; includes safe-only "hard negative" families | 1,956 / 1,079 / 1,160 |

- **CWE mapping:**
  - CWE-89 and CWE-564 → CWE-89.
  - CWE-79/80/83/87 → CWE-79.
  - CWE-77/78/88 → CWE-78.
  - CWE-22/23/35/36/73 → CWE-22.
  - CWE-798/259/321 → CWE-798.
  - CWE-502 → CWE-502.
  - CWE-326/327/328/759/760/916 → CWE-327.
  - Other CWEs are dropped. Eval/exec (CWE-95) is deliberately *not* treated as CWE-502.
- **Cleaning:** 184 real rows were dropped because the same normalized code appeared with
  conflicting labels. These come from successive fixes in one repo, where one fix's "after" is the
  next fix's "before" (for example MISP and jQuery).
- **Splits:** real data is split by repository, synthetic data by template family (one held out for
  test and one for val per class and language). No group appears in two splits.
- **Real training data per class.** Three classes have little or none, so for them the model learned
  almost entirely from synthetic data. The held-out apps are the only real test of those classes.

  | Class | Real train rows | Status |
  |---|---|---|
  | CWE-89 | 40 | |
  | CWE-79 | 213 | |
  | CWE-78 | 33 | |
  | CWE-22 | 33 | |
  | CWE-798 | **0** | synthetic only |
  | CWE-502 | 9 | mostly synthetic |
  | CWE-327 | 4 | mostly synthetic |

- **Held-out apps:** NodeGoat, DVNA, vulpy and PyGoat at pinned commits. They were never used for
  training, tuning or template design. There are 455 function-level units: 48 vulnerable in a target
  class, 392 safe and 15 excluded. The excluded units are real issues outside the 8 classes, or cases I
  couldn't decide. Labels were hand-checked by sink line; see
  `services-ml/ml-sast/data/heldout/LABELS.md`.

## Features

- **Function extraction** (`sastml/extract.py`): Python uses `ast`. JavaScript uses tree-sitter, with
  a regex/brace-matching fallback. Large "container" functions are split into their named members,
  while anonymous callbacks stay with their parent.
- **Code tokens:** locals and the function's own name become `ID`, numbers become `NUM`, and string
  literals become a category (`STR_SQL`, `STR_HTML`, `STR_CMD`, `STR_PATH`, `STR_SECRET`…). F-strings
  and template-literal interpolation are marked.
- **Hand-made features:**
  - sinks: SQL execute/raw, shell, file, HTML output, deserializers, weak hash/cipher/random;
  - sources: `request.*`, `req.*`, `argv`;
  - sanitizers: placeholders, `shlex.quote`, `secure_filename`/`basename`/`realpath`, `escape`,
    `safe_load`, bcrypt/scrypt;
  - risky combinations: SQL/command/HTML strings built by concatenation or formatting, secret-named
    literals, key prefixes.

## Results

Macro-F1 is taken over the classes present in each set. "Vuln P/R" means vulnerable-vs-safe precision
and recall, ignoring which CWE. Full per-class tables, confusion-matrix PNGs and every candidate model
are in `services-ml/ml-sast/reports/`.

### (a) Test split: groups never seen in training

| Set | n | macro-F1 | Vuln P / R |
|---|---|---|---|
| Test, all | 1,298 | 0.750 | 0.70 / 0.82 |
| Test, real CrossVul only | 138 | 0.366 | 0.51 / 0.81 |

The all-test number is dominated by synthetic templates and overstates real-world quality. On real
code the model rarely calls anything safe: safe recall is 0.22.

### (b, c) Held-out apps, with and without the 5 template-XSS units

| Set | n | macro-F1 (95% bootstrap CI) | Vuln P / R |
|---|---|---|---|
| Held-out, all labels | 440 | 0.498 (0.371–0.610) | 0.31 / 0.35 |
| Held-out, code-visible only (template-sink XSS removed) | 435 | 0.549 | 0.28 / 0.35 |

Per class on held-out (all labels), as P / R / F1 with support. With supports this small, every number
here is very uncertain.

| Class | P | R | F1 | Support | Note |
|---|---|---|---|---|---|
| safe | 0.92 | 0.90 | 0.91 | 392 | |
| CWE-89 | 0.19 | 0.50 | 0.27 | 6 | |
| CWE-79 | 0.09 | 0.40 | 0.14 | 5 | All 5 are template-sink cases |
| CWE-78 | 1.00 | 1.00 | 1.00 | 2 | |
| CWE-22 | 0.20 | 1.00 | 0.33 | 1 | |
| CWE-798 | 1.00 | **0.05** | 0.09 | 22 | Synthetic-only class; finds 1 of 22 |
| CWE-502 | 1.00 | 0.50 | 0.67 | 4 | Mostly synthetic |
| CWE-327 | 0.67 | 0.50 | 0.57 | 8 | Mostly synthetic |

### Model comparison (macro-F1 at each model's validation-chosen threshold)

| Model | val | test | test (real) | held-out (all) | held-out (code-visible) |
|---|---|---|---|---|---|
| LR (TF-IDF 1–3-grams + hand features) | 0.713 | 0.832 | 0.482 | 0.447 | 0.517 |
| **RF (selected)** | 0.503 | 0.750 | 0.366 | **0.498** | 0.549 |
| LightGBM | 0.685 | 0.812 | 0.282 | 0.486 | 0.557 |
| CodeBERT fine-tuned (3 epochs, CPU, max_len 256) | 0.652 | 0.786 | 0.391 | 0.458 | 0.524 |
| CodeBERT embeddings + XGBoost | 0.529 | 0.524 | 0.177 | 0.200 | 0.221 |

**The top four are statistically tied on held-out data.** Every pairwise difference has a 95%
bootstrap interval that includes zero (for example RF − LightGBM: +0.03, interval −0.06 to +0.11).
See `reports/heldout_bootstrap.json`.

RF was chosen because the selection rule is held-out macro-F1. But it is clearly the worst of the four
on hardcoded secrets (held-out CWE-798 F1: RF 0.09, LightGBM 0.31, CodeBERT 0.45), and it has the
lowest validation score.

- LightGBM is a reasonable alternative: `scripts/package_model.py --model lgbm`.
- CodeBERT is about 125M parameters and needs the `WITH_CODEBERT=1` image. It is not better here,
  probably because there are only 2.6k training rows.

### Comparison with SonarQube

**TODO, not measured.** There are no existing SonarQube results for the held-out apps at the pinned
commits, so no Sonar numbers are reported. To fill this in:

1. Run the existing `SAST_ENGINE=sonar` pipeline on the four apps.
2. Map each Sonar issue to the unit that contains its line.
3. Score it with `sastml/evaluation.py`.

## Intended use

- **Intended:** an experimental, opt-in second opinion for Python and JS repositories in CloudSentinel
  (`SAST_ENGINE=ml`), and a baseline for further ML SAST work.
- **Not intended:** replacing SonarQube as the blocking SAST gate, any language other than Python or
  JavaScript, or certifying code as secure.

## Limitations

1. **Granularity.** It works per function and reports the function's start line, not the sink line,
   with one finding per function. There is no inter-procedural or cross-file taint tracking.
2. **Template sinks.** XSS whose sink is in a template (`|safe`, `<%- %>`, `autoescape: false`) is
   essentially invisible.
3. **Synthetic-only classes.** CWE-798 has no real training data, and CWE-327 (4 real rows) and
   CWE-502 (9) are mostly synthetic.
   - The held-out apps show the cost. Most of their hardcoded secrets are module-level `SECRET_KEY` /
     config-dict literals, while the synthetic secrets live inside functions.
   - Adding module-level secret templates is the obvious next step. It was **not** done after seeing
     the held-out results, because that would turn the held-out apps into training data.
4. **False positives on real code.** On real CrossVul code the model flags many fixed (safe)
   functions as vulnerable: safe recall is 0.22 on test-real. The "after" side of a minimal fix
   looks almost identical to the "before" side.
5. **Coverage.** Minified files, files over 512 KB, TypeScript and Python files that don't parse
   yield no units, so they are never flagged.

## Threats to validity

- **Small held-out set.** 48 vulnerable units, with 1–8 per class apart from CWE-798, so per-class
  numbers can swing a lot from one or two functions. The bootstrap intervals above are wide.
- **One labeller.** The held-out labels have no second reviewer. Unlabelled real issues would count
  as false positives, and mislabels in either direction distort recall. The method is documented in
  `LABELS.md`.
- **Held-out set used for selection.** It chose between 5 candidates, as specified. That is a mild
  form of tuning on it, so the selected model's held-out score is slightly optimistic.
- **Synthetic test.** Scores on the synthetic part of the test split mainly measure generalization to
  new templates written by the same author. They are reported separately from the real-only numbers
  for that reason.
- **CrossVul label noise.** A function changed in a security fix is not always the vulnerable one:
  fixes can touch helpers, refactors or tests. Successive fixes also make "after" versions that are
  still vulnerable. Conflicting duplicates are dropped, but some noise remains.
- **Teaching apps.** The held-out apps are deliberately vulnerable teaching code, and they share
  idioms with tutorials. Production code may behave differently.

## Reproduce

See [`services-ml/ml-sast/README.md`](../services-ml/ml-sast/README.md#reproduce-the-model).

On 8 CPU threads, the classic models take about 10 minutes to train, the CodeBERT fine-tune about 2.5
hours, and the embeddings + XGBoost model about 20 minutes.
