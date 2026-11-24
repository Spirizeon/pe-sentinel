# How it works

This page explains the pipeline end to end: what is extracted, how the dataset
is built, how models are compared, how predictions are explained, and what the
web UI does.

## Data flow

```
  PE file (never executed)
        │
        ▼
  src/pe_features.py ──► 64 numeric features + evidence dict
        │
        ├──► src/dataset.py ──► data/dataset.csv + data/manifest.json
        │                         (real benign + synthetic malware-like rows)
        ▼
  src/models.py ────────► artifacts/model.joblib + artifacts/metrics.json
        │                 (5 models, 5-fold CV, held-out test metrics)
        ▼
  src/explain.py ───────► artifacts/reports/*.json
        │                 (probability, SHAP values, rule-based evidence)
        ▼
  src/ui/server.py ─────► http://127.0.0.1:8000
                          (ascii.rest banner/spinner/donut + HTML controls)
```

## 1. Static feature extraction

`src/pe_features.py` reads the file bytes and parses the PE headers with
`pefile`. It does **not** run the executable, load its DLLs, or emulate code.

### Feature groups (64 fixed-order columns)

| Group | Examples |
| --- | --- |
| File/header | size, PE32 vs PE32+, machine, subsystem, DLL flag, Authenticode directory, build timestamp |
| Security flags | DEP/NX disabled, ASLR/DYNAMIC_BASE disabled, NO_SEH, high-entropy VA |
| Sections | count, entropy (Shannon bits/byte), writable/executable/RWX counts, empty raw sections, packer-like names |
| Entry point | whether the EP falls in an executable section, section index |
| Imports | total count, DLL count, and 11 API categories |
| Exports / resources / overlay | export count, resource entries and size, appended overlay bytes |
| Strings | counts of URLs, IPs, registry keys, paths, PowerShell indicators, `cmd.exe`, script extensions, base64-like blobs |

The import categories are: `inject`, `antidebug`, `network`, `crypto`,
`persistence`, `file_ops`, `dynamic_load`, `shell_exec`, `privilege`, `sleep`,
`native`.

**Dual-use APIs were deliberately excluded** from the high-signal categories:
`OpenProcess`, `ReadProcessMemory`, `GetTickCount` and `QueryPerformanceCounter`
are common in legitimate installers and games. Including them caused false
positives on the held-out safe sample without adding real detection signal.

Every feature has a human-readable definition in
`FEATURE_DESCRIPTIONS`, and `human_evidence()` turns raw values into short
statements such as "2 sections have entropy > 7.0 (possible packing)".

The feature order is fixed in `FEATURE_NAMES`. Reordering it requires retraining
and a schema-version bump.

## 2. Dataset construction

`src/dataset.py::build_dataset` creates a deterministic dataset (default seed
42).

### Benign class (real files)

- Source: PE files (`.exe`, `.dll`) under the local Wine/Proton runtime, by
  default `/home/berzi/.local/share/Steam/steamapps/common/Proton - Experimental/files/lib/wine`.
- Paths are sorted, shuffled with the seed, and sampled up to `--n-benign`.
- Files larger than 40 MiB are skipped.
- The target file (`GeminiSetup.exe`) is **removed from this pool** and appended
  to the test split only. Its SHA-256 is recorded in the manifest.

### Malicious class (synthetic, safe)

No malware is fetched, generated, or run. For each malicious row, a random
benign feature row is copied and mutated in **feature space** with seeded
patterns:

- `strong` (55%): packing, RWX sections, injection APIs, networking,
  persistence, anti-debug, crypto, shell execution, overlay, suspicious strings,
  disabled security flags, abnormal entry point
- `medium` (30%): a smaller subset of those
- `weak` (15%): 1–2 subtle indicators only, intentionally overlapping benign
  space

Small Gaussian jitter is applied to make the task non-trivial. The weak rows
and benign overlap are what produce the handful of test errors.

### Benign look-alikes

About 22% of benign rows are augmented with generic installer/updater traits —
signed, many embedded URLs/IPs, service and registry imports, large resources —
using domain knowledge only. This prevents the model from learning the naive
rule "URLs or service APIs means malware". The remaining benign rows get mild
noise. This is why the held-out installer is classified correctly.

### Splits

Rows are shuffled with the seed, then split 80/20 into train/test. The target
row is forced into test. `data/manifest.json` records counts, seed, source root,
target hash, and the explicit disclaimer.

## 3. Model comparison and selection

`src/models.py::make_pipelines` defines five pipelines:

1. majority-class baseline
2. logistic regression with `StandardScaler`
3. random forest
4. extra trees
5. histogram gradient boosting

All are fit on the train split only. `StratifiedKFold(5, shuffle=True,
random_state=seed)` produces cross-validated accuracy, F1 and ROC-AUC. The
**best model is chosen by mean CV F1**, a rule fixed before looking at the test
split. The winner is refit on train and saved with `joblib`, together with the
training rows that SHAP needs.

## 4. Evaluation metrics

On the held-out test split the report records:

- **Accuracy** — fraction of correct predictions
- **F1** — harmonic mean of precision and recall for the malware class
- **Precision / recall** — explicitly reported per model
- **ROC-AUC** — ranking quality across thresholds
- **Confusion matrix** — `tn`, `fp`, `fn`, `tp`
- **False positives** — count and rate (`fp / (fp + tn)`)
- **Inference time** — median wall-clock for a batch prediction divided by the
  number of rows, plus a loop of up to 200 single-row `predict_proba` calls

These numbers are measured on the synthetic dataset and are only a demonstration
of the machinery.

## 5. Explaining a prediction

`src/explain.py::explain_file`:

1. Extracts features for the file and builds the 64-column row.
2. Runs `predict_proba` to get the malware probability (threshold 0.50).
3. Applies SHAP:
   - `TreeExplainer` for random forest, extra trees, histogram GB
   - `LinearExplainer` for logistic regression
   - binary outputs are normalised to the positive (malware) class
4. Sorts features by absolute SHAP value and keeps the top 12.
5. Adds the independent `human_evidence()` list and raw PE metadata.

**Interpretation:** a positive SHAP value pushes the score toward "malicious"
relative to the model baseline; a negative one pushes toward "benign". The
evidence list is rule-based and can be checked against the PE metadata without
trusting the model.

Example output shape:

```json
{
  "prediction": "benign",
  "malware_probability": 0.397428,
  "model": "random_forest",
  "top_attributions": [
    {"feature": "import_antidebug", "shap_value": 0.09567,
     "direction": "towards_malware", "description": "anti-debugging / timing APIs"}
  ],
  "evidence": ["2 import(s) in the antidebug API category"]
}
```

## 6. Web UI

`src/ui/server.py` is a small Flask app launched by `./run.sh ui`.

| Route | Purpose |
| --- | --- |
| `GET /`, `GET /assets/...` | serve the HTML/CSS/JS |
| `GET /health`, `GET /api/health` | model readiness |
| `GET /api/metrics` | model comparison from `metrics.json` |
| `GET /api/target-report` | saved demo report |
| `POST /api/predict` | multipart upload → prediction report |

Uploaded files are restricted to PE-like extensions and 100 MiB, saved in a
temporary directory, parsed statically, and deleted immediately. Nothing is
executed.

The page uses **ascii.rest** custom elements loaded from
`https://ascii.rest/ascii.js`:

- `<ascii-banner>` for the "PE SENTINEL" title
- `<ascii-art piece="spinners">` while analysis runs
- `<ascii-art piece="donut">` in the drop zone
- `<ascii-art piece="progress-bar">` in the footer

All interactive controls are plain HTML/JavaScript (`src/ui/static/app.js`), so
no npm build step is needed. The browser needs internet access for the CDN
script; the classifier itself works offline via the CLI.

## 7. Module map

| File | Responsibility |
| --- | --- |
| `src/pe_features.py` | feature schema, PE parser, string counters, evidence |
| `src/dataset.py` | deterministic dataset + synthetic variants + manifest |
| `src/models.py` | model pipelines, CV, held-out evaluation, artefact saving |
| `src/explain.py` | SHAP + rule-based evidence + JSON report |
| `src/cli.py` | command line entry point |
| `src/ui/server.py` | Flask API and static file serving |
| `src/ui/static/` | HTML, CSS, JS for the browser UI |
| `run.sh` | venv wrapper and Nix `LD_LIBRARY_PATH` fix |

## 8. Reproducibility

- All randomness uses `--seed` (default 42): file sampling, splits, synthetic
  mutations and model initialisation.
- `data/manifest.json` records the source root, seed, counts and target hash.
- `FEATURE_NAMES` fixes the schema; `artifacts/model.joblib` stores the feature
  list and training rows alongside the pipeline.
- Dependency versions are in `requirements.txt`; this run used Python 3.14,
  numpy 2.5, pandas 3.1, scikit-learn 1.9, shap 0.54, pefile 2024.8.26.

## 9. Limitations and using real data

The synthetic labels make high scores expected. Do not deploy this model as a
malware detector.

To use real labelled data:

1. Replace `build_dataset` with a loader for a curated corpus (e.g. EMBER
   features or internal sandbox-labelled samples). Keep the exact
   `FEATURE_NAMES` schema or retrain with a new schema version.
2. Deduplicate by SHA-256 and split **chronologically** to avoid leakage from
   near-duplicate samples.
3. Calibrate probabilities on a benign-heavy validation set; tune the decision
   threshold to meet a false-positive budget.
4. Add behavioral features (process tree, network destinations, file-system
   traces) for samples where static analysis is inconclusive.
5. Log every report, hash the model artefact, and route uncertain scores to a
   human reviewer.
