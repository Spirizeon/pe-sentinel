# PE Sentinel — explainable PE malware classifier

Static, non-executing analysis of files, with per-prediction evidence, SHAP
feature attribution, and an ASCII-styled web UI built with `ascii.rest`. The
model is trained on the labelled `ficheiro_final.csv` corpus.

## Quick start (simplest path)

From this directory:

```bash
# 1. one-time setup
uv venv .venv
uv pip install --python .venv/bin/python -r requirements.txt

# 2. encode the labelled corpus, compare models, explain the demo file
./run.sh run-all

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
| `./run.sh build-dataset` | Encodes `data/ficheiro_final.csv` into `data/dataset.csv` + `data/manifest.json` |
| `./run.sh train` | Compares 5 models with 5-fold CV, writes `artifacts/model.joblib` + `artifacts/metrics.json` |
| `./run.sh predict --target /home/berzi/Downloads/GeminiSetup.exe` | Writes a prediction + SHAP report to `artifacts/reports/target_report.json` |
| `./run.sh ui` | Starts the browser UI on port 8000 (`--port 9000` to change) |
| `./run.sh run-all` | Runs build-dataset → train → predict in one shot |

Useful flags: `--csv` (alternate labelled corpus), `--data-dir`,
`--artifacts-dir`, `--seed`, `--target`. Run `./run.sh --help` or
`./run.sh <command> --help` for the full list.

## What you get

- `data/ficheiro_final.csv` — the labelled corpus (1,237 rows, PE and non-PE)
- `data/dataset.csv` — the same rows with 27 encoded features, labels and split;
  25 feed the model (`creation_time` and `Permissions` are reported only)
- `data/manifest.json` — source CSV, counts, seed, feature list and disclaimer
- `artifacts/model.joblib` — selected pipeline + training rows for SHAP
- `artifacts/metrics.json` — accuracy, F1, precision, recall, ROC-AUC, false
  positives, confusion matrix, inference time for every model
- `artifacts/reports/target_report.json` — prediction, probability, top SHAP
  attributions, and human-readable evidence
- Web UI — upload a file, load the demo report, or view the model comparison

Every corpus row is used (no synthetic rows); labels come from the
`classification` column. `GeminiSetup.exe` is **not** in the corpus: it is only
a demo upload target and its verdict has no ground truth attached.

## Web UI

Open `./run.sh ui` → http://127.0.0.1:8000. The page has a four-card dashboard
that makes the project criteria visible: feature extraction, model comparison,
explainability, and evaluation. Upload a file (or load the demo) to see the
verdict, SHAP attributions, rule-based evidence, proof badges, and the full
27-feature vector. The metrics panel shows accuracy, F1, precision, recall,
ROC-AUC, confusion-matrix counts, false positives, and inference time for all
models. The 27-feature vector marks the two collection-artifact columns as
excluded from the model. Uploads are parsed statically and deleted after analysis.

## Results from the committed run

`ficheiro_final.csv`: 1,237 labelled rows, 989 train / 248 test, seed 42. Model
selected by 5-fold CV F1: **histogram gradient boosting**.

| Model | CV F1 | Test accuracy | Test F1 | False positives | ms/sample |
| --- | ---: | ---: | ---: | ---: | ---: |
| majority baseline | 0.000 | 0.569 | 0.000 | 0 | 0.0025 |
| logistic regression | 0.939 | 0.952 | 0.944 | 6 | 0.0042 |
| random forest | 0.953 | 0.976 | 0.973 | 5 | 0.2035 |
| extra trees | 0.952 | 0.984 | 0.981 | 2 | 0.1910 |
| hist. gradient boosting (selected) | 0.957 | 0.980 | 0.977 | 4 | 0.0099 |

`GeminiSetup.exe` is predicted **benign** with probability 0.794 (i.e. 20.6%
malware). Its SHA-256 is `3f071f…41cbd`; the file is not in the corpus, so this
is only a demonstration of the explanation path.

**Honesty note:** `creation_time` and `Permissions` are reported but excluded
from the model. In `ficheiro_final.csv` every benign row is stamped 2025-04-24
and carries permission bits `777`, so both columns encoded the collection
environment and produced near-perfect but misleading scores. The remaining
metrics describe this corpus only, not real-world detection performance. A
production model would still need leakage-free sampling, chronological splits
and external validation.

## Deploying to Render

`render.yaml` is the Blueprint Render reads; `render.json` is the same config in
JSON form for reference. Render's Blueprint format is YAML, so use `render.yaml`
when creating the service.

1. Push this repo to GitHub (already done at
   `https://github.com/Spirizeon/pe-sentinel`).
2. In Render, choose **New → Blueprint** and select that repository.
3. Render detects `render.yaml` and creates the `pe-sentinel` web service.
4. The health check is `/api/health`.

The committed `artifacts/` and `data/` directories mean no training step is
needed at deploy time. Uploads are still parsed statically and deleted after
each request.

## Documentation

- [docs/HOW_IT_WORKS.md](docs/HOW_IT_WORKS.md) — pipeline architecture, feature
  schema, dataset encoding, model selection, SHAP explanations, UI flow,
  and limitations.
- Feature meanings and categorical vocabularies are documented in code at
  `src/pe_features.py`.
