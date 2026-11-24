"""Local explanations with SHAP feature attribution plus rule-based evidence."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
import shap
from joblib import load
from sklearn.ensemble import ExtraTreesClassifier, HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression

from .pe_features import FEATURE_DESCRIPTIONS, FEATURE_NAMES, extract_features, human_evidence


def _prepared(pipeline: Any, frame: pd.DataFrame) -> np.ndarray:
    steps = list(pipeline.steps)[:-1]
    data: Any = frame
    for _, transformer in steps:
        data = transformer.transform(data)
    return np.asarray(data, dtype=float)


def _positive_shap(raw: Any, n_features: int) -> np.ndarray:
    array = np.asarray(raw, dtype=float)
    if array.ndim == 3 and array.shape[-1] == 2:
        array = array[:, :, 1]
    elif array.ndim == 2 and array.shape[0] == 2 and array.shape[1] == n_features:
        array = array[1:2, :]
    if array.ndim == 1:
        array = array.reshape(1, -1)
    return array[0]


def explain_file(
    model_path: str | Path,
    file_path: str | Path,
    out_path: str | Path | None = None,
    top_n: int = 12,
) -> dict[str, Any]:
    """Predict one file and write a JSON report with attributions and evidence."""
    bundle = load(model_path)
    pipeline = bundle["pipeline"]
    features_result = extract_features(file_path)
    features = features_result["features"]
    evidence = features_result["evidence"]
    row = pd.DataFrame([[float(features[n]) for n in FEATURE_NAMES]], columns=FEATURE_NAMES)
    x_prepared = _prepared(pipeline, row)
    probabilities = pipeline.predict_proba(row)[0]
    positive_idx = list(pipeline.classes_).index(1)
    probability = float(probabilities[positive_idx])
    prediction = int(probability >= 0.5)

    clf = pipeline.steps[-1][1]
    train_prepared = _prepared(pipeline, bundle["x_train"])
    try:
        if isinstance(clf, (RandomForestClassifier, ExtraTreesClassifier, HistGradientBoostingClassifier)):
            explainer = shap.TreeExplainer(clf)
            values = _positive_shap(explainer.shap_values(x_prepared), len(FEATURE_NAMES))
            expected = float(np.asarray(explainer.expected_value).reshape(-1)[-1])
        elif isinstance(clf, LogisticRegression):
            explainer = shap.LinearExplainer(clf, train_prepared)
            values = _positive_shap(explainer.shap_values(x_prepared), len(FEATURE_NAMES))
            expected = float(np.asarray(explainer.expected_value).reshape(-1)[-1])
        else:
            raise TypeError(f"No SHAP explainer configured for {type(clf).__name__}")
        explainer_kind = type(explainer).__name__
    except Exception as exc:  # keep prediction usable even if SHAP cannot run
        values = np.zeros(len(FEATURE_NAMES))
        expected = float("nan")
        explainer_kind = f"unavailable ({type(exc).__name__}: {exc})"

    order = np.argsort(-np.abs(values))[:top_n]
    attributions = []
    for idx in order:
        name = FEATURE_NAMES[idx]
        attributions.append({
            "feature": name,
            "value": round(float(row.iloc[0, idx]), 4),
            "shap_value": round(float(values[idx]), 5),
            "direction": "towards_malware" if values[idx] > 0 else "towards_benign",
            "description": FEATURE_DESCRIPTIONS.get(name, name),
        })

    report = {
        "file": str(Path(file_path).resolve()),
        "sha256": evidence["sha256"],
        "size_bytes": evidence["size_bytes"],
        "model": bundle["name"],
        "prediction": "malicious" if prediction == 1 else "benign",
        "malware_probability": round(probability, 6),
        "threshold": 0.5,
        "explainer": explainer_kind,
        "baseline_log_odds": None if np.isnan(expected) else round(expected, 5),
        "top_attributions": attributions,
        "feature_count": len(FEATURE_NAMES),
        "feature_schema": [
            {
                "name": name,
                "value": round(float(features.get(name, 0.0)), 4),
                "description": FEATURE_DESCRIPTIONS.get(name, name),
            }
            for name in FEATURE_NAMES
        ],
        "evidence": human_evidence(features),
        "raw_evidence": {
            "section_names": evidence.get("section_names", []),
            "imported_dlls": evidence.get("imported_dlls", []),
            "top_import_categories": evidence.get("top_import_categories", []),
            "string_indicators": evidence.get("string_indicators", {}),
            "overlay_bytes": evidence.get("overlay_bytes", 0),
            "notes": evidence.get("notes", []),
        },
        "interpretation_note": (
            "A positive SHAP value raises the model's malware score relative to the "
            "baseline; a negative value lowers it. Attributions explain this model "
            "on this synthetic dataset, not ground-truth maliciousness."
        ),
    }

    if out_path:
        out_path = Path(out_path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report
