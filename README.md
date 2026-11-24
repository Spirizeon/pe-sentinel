# PE Sentinel — explainable PE malware classifier

Static, non-executing analysis of Windows PE files, with per-prediction evidence,
SHAP feature attribution, and an ASCII-styled web UI built with `ascii.rest`.

## Quick start (simplest path)

From this directory:

```bash
# 1. one-time setup
uv venv .venv
uv pip install --python .venv/bin/python -r requirements.txt

# 2. build the dataset, compare models, and explain the demo file
./run.sh run-all --n-benign 200 --n-malicious 200 --jobs 8

# 3. open the web UI
./run.sh ui
```

Then visit **http://127.0.0.1:8000**.

`data/` and `artifacts/` are already populated in this workspace, so you can
skip step 2 and go straight to `./run.sh ui`.

> `run.sh` handles the `LD_LIBRARY_PATH` needed by the PyPI wheels on this Nix
> host. It uses the `.venv` Python.

## Commands, one at a time

| Command | What it does |
| --- | --- |
| `./run.sh build-dataset --n-benign 200 --n-malicious 200 --jobs 8` | Extracts real benign PE features, generates synthetic malware-like rows, writes `data/dataset.csv` + `data/manifest.json` |
| `./run.sh train` | Compares 5 models with 5-fold CV, writes `artifacts/model.joblib` + `artifacts/metrics.json` |
| `./run.sh predict --target /home/berzi/Downloads/GeminiSetup.exe` | Writes a prediction + SHAP report to `artifacts/reports/target_report.json` |
| `./run.sh ui` | Starts the browser UI on port 8000 (`--port 9000` to change) |
| `./run.sh run-all` | Runs build-dataset → train → predict in one shot |

Useful flags: `--benign-root`, `--data-dir`, `--artifacts-dir`, `--seed`,
`--jobs`, `--target`. Run `./run.sh --help` or `./run.sh <command> --help` for
the full list.

## What you get

- `data/dataset.csv` — 64 static features, labels, source, split
- `data/manifest.json` — seed, counts, hashes, provenance
- `artifacts/model.joblib` — selected pipeline + training rows for SHAP
- `artifacts/metrics.json` — accuracy, F1, precision, recall, ROC-AUC, false
  positives, confusion matrix, inference time for every model
- `artifacts/reports/target_report.json` — prediction, probability, top SHAP
  attributions, and human-readable evidence
- Web UI — upload any PE, load the demo report, or view the model comparison

`GeminiSetup.exe` is treated as benign, excluded from training, and kept only in
the test split.

## Web UI

Open `./run.sh ui` → http://127.0.0.1:8000. The page has a four-card dashboard
that makes the project criteria visible: feature extraction, model comparison,
explainability, and evaluation. Upload a PE (or load the demo) to see the verdict,
SHAP attributions, rule-based evidence, proof badges, and the full 64-feature
vector. The metrics panel shows accuracy, F1, precision, recall, ROC-AUC,
confusion-matrix counts, false positives, and inference time for all models.
Uploads are parsed statically and deleted after analysis.

## Results from the committed run

201 real benign PEs + 200 synthetic malware-like rows; 320 train / 81 test; seed
42. Model selected by 5-fold CV F1: **random forest**.

| Model | CV F1 | Test accuracy | Test F1 | False positives | ms/sample |
| --- | ---: | ---: | ---: | ---: | ---: |
| majority baseline | 0.678 | 0.444 | 0.615 | 45 | 1.3 |
| logistic regression | 0.956 | 0.951 | 0.943 | 1 | 1.7 |
| random forest (selected) | 0.975 | 0.963 | 0.957 | 0 | 49.9 |
| extra trees | 0.969 | 0.963 | 0.957 | 0 | 49.4 |
| hist. gradient boosting | 0.965 | 0.988 | 0.986 | 0 | 2.7 |

`GeminiSetup.exe` (SHA-256 `3f071f…41cbd`) is predicted **benign** with
probability 0.397. Gradient boosting scored higher on this test split, but the
pre-declared selection rule is CV F1, so random forest was chosen.

**Honesty note:** no real malware was downloaded or executed. Malicious rows are
synthetic feature-space variants, so these metrics show that the pipeline works,
not real-world detection performance.

## Deploying to Render

`render.yaml` is the Blueprint Render reads; `render.json` is the same config in
JSON form for reference. Render's Blueprint format is YAML, so use `render.yaml`
when creating the service.

1. Push this repo to GitHub (already done at
   `https://github.com/Spirizeon/pe-sentinel`).
2. In Render, choose **New → Blueprint** and select that repository.
3. Render detects `render.yaml` and creates the `pe-sentinel` web service.
4. The health check is `/api/health`.

The committed `artifacts/` directory means no training step is needed at deploy
time. Uploads are still parsed statically and deleted after each request.

## Documentation

- [docs/HOW_IT_WORKS.md](docs/HOW_IT_WORKS.md) — pipeline architecture, feature
  schema, dataset construction, model selection, SHAP explanations, UI flow,
  and how to swap in real data.
- Feature meanings are also documented in code at
  `src/pe_features.py::FEATURE_DESCRIPTIONS`.
