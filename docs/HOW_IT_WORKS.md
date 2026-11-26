# How it works

This page explains the pipeline end to end: what is extracted, how the labelled
dataset is encoded, how models are compared, how predictions are explained, and
what the web UI does.

## Data flow

```
  data/ficheiro_final.csv (real labelled rows)
         │
         ▼
  src/dataset.py ──► data/dataset.csv + data/manifest.json
         │            (27 encoded features, labels, train/test split)
         ▼
  src/models.py ────────► artifacts/model.joblib + artifacts/metrics.json
         │                 (5 models, 5-fold CV, held-out test metrics)
         ▼
  file upload ──► src/pe_features.py ──► 27 features + evidence dict
         │
         ▼
  src/explain.py ───────► artifacts/reports/*.json
         │                 (probability, SHAP values, rule-based evidence)
         ▼
  src/ui/server.py ─────► http://127.0.0.1:8000
                          (ascii.rest banner/spinner/donut + HTML controls)
```

## 1. Feature schema and extraction

`src/pe_features.py` defines the 27 fixed-order columns (`FEATURE_NAMES`) that
the model was trained on. The same module encodes the CSV and extracts features
from uploaded files, so a value has the same meaning on both sides.

| Group | Columns |
| --- | --- |
| Byte statistics | `Size`, `Entropy`, `entropy`, `Non-Printable Exists`, `Non-Printable Count`, `unicode_strings` |
| PE headers | `header_match`, `creation_time`, `arch`, `extension`, `encoding`, `Permissions` |
| Sections / resources | `num_text_sections`, `num_custom_sections`, `Data Sections Count`, `rsrc`, `digital_signature` |
| Packer / APIs / strings | `packer`, `Packed Status`, `Suspicious Functions Count`, `suspicious_strings`, `suspicious_strings_found`, `suspicious_encoding` |
| Opcode statistics | `unique_instruction_count`, `average_opcode_count`, `total_instruction_count`, `instruction_diversity_ratio` |

Files are never executed. PE headers are parsed with `pefile`; the remaining
values come from byte-level statistics and string searches. Non-PE files are
accepted by the extractor: `header_match` becomes 0 and all PE-specific fields
are zero.

Categorical columns are **not** factorized at load time. Fixed vocabularies in
`VOCABULARIES` map values to integers (e.g. `packer`: Unknown=0, UPX=1,
MinPack=2; `arch`: x86=0, x86_64=1, not_pe=2, …). Unknown values go into a
stable `other` bucket. `Yes`/`No` and `TRUE`/`FALSE` become 1/0. The
`suspicious_strings_found` list from the CSV is encoded as its number of
entries.

The opcode columns cannot be reproduced without a disassembler dependency, so
extraction emits 0.0 for them. They are kept in the schema because they exist
in the corpus, and they are labelled as unavailable in the UI and
`FEATURE_DESCRIPTIONS`.

`creation_time` and `Permissions` stay in the report schema but are **excluded
from model input** (`NON_MODEL_FEATURES`). Every benign corpus row is stamped
2025-04-24 with permission bits `777`, so these columns describe the collection
environment rather than file behaviour: they gave near-perfect CV scores and
pushed out-of-range uploads toward "malicious". The model uses the remaining
25 columns; the full 27-column vector is still shown for auditing.

## 2. Dataset construction

`src/dataset.py::build_dataset` reads `data/ficheiro_final.csv` (override with
`--csv`). There are **no synthetic rows**.

- All 1,237 labelled rows are used — 911 `.exe`, 232 `.elf`, and smaller groups
  of `.dll`, scripts, archives and other formats.
- Label 0 is benign (703 rows), label 1 is malicious (534 rows), taken from the
  `classification` column.
- Each column is encoded with `pe_features.encode_value`; missing values become
  0. The result is written to `data/dataset.csv` with `label`, `source`,
  `source_path`, `sha256` and `split` metadata.
- Rows are split 80/20 with a seed-stratified `train_test_split` (989 train /
  248 test at seed 42).
- `data/manifest.json` records the source CSV path, row and class counts, split
  counts, feature list and disclaimer.

`GeminiSetup.exe` is not part of the corpus. It is only a convenient demo file
for `predict`/`run-all`; no label is attached to its report.

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

The committed run scores 0.980 accuracy / 0.977 F1 for the selected model on a
248-row test split. An earlier run that included `creation_time` and
`Permissions` scored 1.000; those columns encoded the collection environment
(uniform timestamps and permission bits), so they are now reported but excluded
from the model. These figures demonstrate the machinery on the supplied data;
they are **not** estimates of detection performance on new samples.

## 5. Explaining a prediction

`src/explain.py::explain_file`:

1. Extracts the 27 features for the file; the model row uses the 25 non-artifact columns.
2. Runs `predict_proba` to get the malware probability (threshold 0.50).
3. Applies SHAP:
   - `TreeExplainer` for random forest, extra trees, histogram GB
   - `LinearExplainer` for logistic regression
   - binary outputs are normalised to the positive (malware) class
4. Sorts features by absolute SHAP value and keeps the top 12.
5. Adds the independent `human_evidence()` list and raw PE metadata.

**Interpretation:** a positive SHAP value pushes the score toward "malicious"
relative to the model baseline; a negative one pushes toward "benign". The
evidence list is rule-based and can be checked against the extracted values
without trusting the model.

Example output shape:

```json
{
  "prediction": "benign",
  "malware_probability": 0.205856,
  "model": "hist_gradient_boosting",
  "top_attributions": [
    {"feature": "average_opcode_count", "shap_value": 3.91678,
     "direction": "towards_malware", "description": "mean opcode count (unavailable in this build; encoded as 0)"}
  ],
  "evidence": ["PE header parsed; architecture x86, extension .exe"]
}
```

The demo installer comes out benign once the collection-artifact columns are
excluded. It is still unlabelled, so the verdict demonstrates the explanation
path rather than ground truth.

## 6. Web UI

`src/ui/server.py` is a small Flask app launched by `./run.sh ui`.

| Route | Purpose |
| --- | --- |
| `GET /`, `GET /assets/...` | serve the HTML/CSS/JS |
| `GET /health`, `GET /api/health` | model readiness |
| `GET /api/metrics` | model comparison from `metrics.json` |
| `GET /api/target-report` | saved demo report |
| `POST /api/predict` | multipart upload → prediction report |

Uploads are restricted to PE-like extensions and 100 MiB, saved in a temporary
directory, parsed statically, and deleted immediately. Nothing is executed.
The model schema also supports non-PE rows from the corpus; the upload filter
keeps the browser demo focused on Windows executables.

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
| `src/pe_features.py` | 27-feature schema, encoding vocabularies, extraction, evidence |
| `src/dataset.py` | labelled-corpus loader, encoded CSV + manifest |
| `src/models.py` | model pipelines, CV, held-out evaluation, artefact saving |
| `src/explain.py` | SHAP + rule-based evidence + JSON report |
| `src/cli.py` | command line entry point |
| `src/ui/server.py` | Flask API and static file serving |
| `src/ui/static/` | HTML, CSS, JS for the browser UI |
| `run.sh` | venv wrapper and Nix `LD_LIBRARY_PATH` fix |

## 8. Reproducibility

- The seed (default 42) controls the train/test split and model initialisation;
  there is no random dataset generation.
- `data/ficheiro_final.csv` is the committed source of truth;
  `data/manifest.json` records its path, counts and feature list.
- `FEATURE_NAMES` and `VOCABULARIES` fix the schema;
  `artifacts/model.joblib` stores the feature list and training rows alongside
  the pipeline.
- Dependency versions are in `requirements.txt`; this run used Python 3.14,
  numpy 2.5, pandas 3.1, scikit-learn 1.9, shap 0.54, pefile 2024.8.26.

## 9. Limitations and using another corpus

Do not deploy this model as a malware detector. The corpus is small, its labels
are correlated with collection timestamps, and the UI's opcode columns are
empty placeholders.

To use different labelled data:

1. Replace `data/ficheiro_final.csv` with a CSV containing the 27 columns in
   `FEATURE_NAMES` plus `classification` and `sha256`, or extend the schema and
   retrain with a schema-version bump.
2. Use `encode_value` for categorical columns so training and inference agree;
   avoid per-run `factorize`.
3. Deduplicate by SHA-256 and split chronologically to avoid leakage from
   near-duplicate or same-batch samples.
4. Calibrate probabilities on a benign-heavy validation set and tune the
   decision threshold to a false-positive budget.
5. Add real opcode/behavioral features where static indicators are inconclusive,
   and route uncertain scores to a human reviewer.
