# ml-sast model comparison

Macro-F1 over classes present in each set; argmax / validation-chosen threshold.

| Model | val | test | test (real only) | held-out (all) | held-out (code-visible) |
|---|---|---|---|---|---|
| lr | 0.713 | 0.841/0.832 | 0.471/0.482 | 0.409/0.447 | 0.471/0.517 |
| rf | 0.503 | 0.704/0.750 | 0.270/0.366 | 0.410/0.498 | 0.470/0.549 |
| lgbm | 0.685 | 0.811/0.812 | 0.260/0.282 | 0.440/0.486 | 0.504/0.557 |
| codebert | 0.652 | 0.806/0.786 | 0.466/0.391 | 0.420/0.458 | 0.461/0.524 |
| codebert_xgb | 0.529 | 0.471/0.524 | 0.193/0.177 | 0.183/0.200 | 0.193/0.221 |

Data flags (real CrossVul rows in train): CWE-89: 40, CWE-79: 213, CWE-78: 33, CWE-22: 33, CWE-798 (synthetic-only): 0, CWE-502 (mostly synthetic): 9, CWE-327 (mostly synthetic): 4

SonarQube comparison: TODO - No existing SonarQube results are available for NodeGoat, DVNA, vulpy or PyGoat at the pinned commits. No Sonar numbers are reported; run the existing SAST_ENGINE=sonar pipeline on these apps and map issues to units to fill this in.
