"""Turn the labelled ``ficheiro_final.csv`` corpus into the training CSV.

The corpus is real labelled data: every row carries a ``classification`` label
and is used as-is (PE and non-PE files alike). No synthetic rows are generated.
Categorical columns are encoded with the shared vocabularies in
``pe_features.py`` so inference on a new file uses exactly the same schema.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pandas as pd
from sklearn.model_selection import train_test_split

from .pe_features import FEATURE_NAMES, MODEL_FEATURES, NON_MODEL_FEATURES, encode_value

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SOURCE_CSV = PROJECT_ROOT / "data" / "ficheiro_final.csv"
LABEL_COLUMN = "classification"
SEED = 42


def load_labelled_csv(csv_path: str | Path) -> pd.DataFrame:
    """Read the corpus and return a numeric frame with labels and metadata."""
    csv_path = Path(csv_path)
    if not csv_path.exists():
        raise FileNotFoundError(f"labelled corpus not found: {csv_path}")
    raw = pd.read_csv(csv_path, dtype=str, keep_default_na=False, encoding="utf-8-sig")
    missing = [name for name in [*FEATURE_NAMES, LABEL_COLUMN] if name not in raw.columns]
    if missing:
        raise RuntimeError(f"{csv_path} is missing required columns: {missing}")

    frame = pd.DataFrame(index=raw.index)
    for name in FEATURE_NAMES:
        frame[name] = raw[name].map(lambda value, column=name: encode_value(column, value))
    frame["label"] = pd.to_numeric(raw[LABEL_COLUMN], errors="coerce").fillna(0).astype(int)
    frame["source"] = "ficheiro_final.csv"
    frame["source_path"] = raw.get("filename", pd.Series([""] * len(raw))).astype(str).values
    frame["sha256"] = raw.get("sha256", pd.Series([""] * len(raw))).astype(str).values
    return frame


def build_dataset(
    out_dir: str | Path = "data",
    csv_path: str | Path = DEFAULT_SOURCE_CSV,
    test_size: float = 0.2,
    seed: int = SEED,
) -> dict[str, Any]:
    """Encode the labelled corpus, split it, and write dataset.csv + manifest.json."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    csv_path = Path(csv_path)

    frame = load_labelled_csv(csv_path)
    train_idx, test_idx = train_test_split(
        frame.index, test_size=test_size, random_state=seed, stratify=frame["label"]
    )
    frame["split"] = "train"
    frame.loc[test_idx, "split"] = "test"
    frame = frame.loc[list(train_idx) + list(test_idx)].reset_index(drop=True)

    csv_out = out_dir / "dataset.csv"
    frame.to_csv(csv_out, index=False)

    counts = frame["label"].value_counts()
    manifest = {
        "seed": seed,
        "source_csv": str(csv_path.resolve()),
        "row_count": int(len(frame)),
        "benign_count": int(counts.get(0, 0)),
        "malicious_count": int(counts.get(1, 0)),
        "split_counts": frame["split"].value_counts().to_dict(),
        "feature_count": len(FEATURE_NAMES),
        "features": FEATURE_NAMES,
        "model_feature_count": len(MODEL_FEATURES),
        "excluded_from_model": list(NON_MODEL_FEATURES),
        "disclaimer": (
            "Rows come from the labelled ficheiro_final.csv corpus (both PE and "
            "non-PE samples). Scores reflect that corpus only and are not "
            "estimates of real-world malware detection performance."
        ),
    }
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"[dataset] read {manifest['row_count']} labelled rows from {csv_path}")
    print(f"[dataset] wrote {csv_out} ({manifest['feature_count']} encoded features)")
    return manifest
