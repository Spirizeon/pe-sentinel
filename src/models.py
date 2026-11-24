"""Model comparison, selection and evaluation."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from joblib import dump
from sklearn.dummy import DummyClassifier
from sklearn.ensemble import ExtraTreesClassifier, HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedKFold, cross_validate
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from .pe_features import FEATURE_NAMES


def make_pipelines(seed: int = 42) -> dict[str, Pipeline]:
    return {
        "majority_baseline": Pipeline([
            ("scale", StandardScaler()),
            ("clf", DummyClassifier(strategy="most_frequent")),
        ]),
        "logistic_regression": Pipeline([
            ("scale", StandardScaler()),
            ("clf", LogisticRegression(max_iter=3000, class_weight="balanced", random_state=seed)),
        ]),
        "random_forest": Pipeline([
            ("clf", RandomForestClassifier(
                n_estimators=300, min_samples_leaf=2, max_features="sqrt",
                class_weight="balanced_subsample", n_jobs=-1, random_state=seed,
            )),
        ]),
        "extra_trees": Pipeline([
            ("clf", ExtraTreesClassifier(
                n_estimators=300, min_samples_leaf=2, max_features="sqrt",
                class_weight="balanced_subsample", n_jobs=-1, random_state=seed,
            )),
        ]),
        "hist_gradient_boosting": Pipeline([
            ("clf", HistGradientBoostingClassifier(
                max_iter=200, learning_rate=0.08, max_leaf_nodes=15,
                l2_regularization=1.0, early_stopping=False, random_state=seed,
            )),
        ]),
    }


def _xy(frame: pd.DataFrame, split: str) -> tuple[pd.DataFrame, np.ndarray]:
    subset = frame[frame["split"] == split]
    return subset[FEATURE_NAMES].astype(float), subset["label"].astype(int).to_numpy()


def measure_inference_time(pipeline: Pipeline, x_test: pd.DataFrame, repeats: int = 3) -> dict[str, float]:
    """Wall-clock timing on this machine; includes only model.predict_proba."""
    timings: list[float] = []
    for _ in range(repeats):
        start = time.perf_counter()
        pipeline.predict_proba(x_test)
        timings.append(time.perf_counter() - start)
    batch = float(np.median(timings))
    n = max(1, len(x_test))
    single_start = time.perf_counter()
    for i in range(min(200, n)):
        pipeline.predict_proba(x_test.iloc[[i]])
    single = (time.perf_counter() - single_start) / min(200, n)
    return {
        "batch_seconds_median": round(batch, 6),
        "per_sample_ms_batch": round(1000 * batch / n, 4),
        "per_sample_ms_single": round(1000 * single, 4),
        "samples_timed": int(n),
    }


def train_and_evaluate(
    csv_path: str | Path,
    out_dir: str | Path,
    seed: int = 42,
    target_sha256: str | None = None,
) -> dict[str, Any]:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    frame = pd.read_csv(csv_path)
    x_train, y_train = _xy(frame, "train")
    x_test, y_test = _xy(frame, "test")
    if not len(x_train) or not len(x_test):
        raise RuntimeError("Train or test split is empty")

    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=seed)
    scoring = {"accuracy": "accuracy", "f1": "f1", "roc_auc": "roc_auc"}
    results: dict[str, Any] = {}

    for name, pipeline in make_pipelines(seed).items():
        print(f"[train] evaluating {name} ...")
        t0 = time.perf_counter()
        scores = cross_validate(pipeline, x_train, y_train, cv=cv, scoring=scoring, n_jobs=1)
        fit_seconds = time.perf_counter() - t0
        pipeline.fit(x_train, y_train)
        probabilities = pipeline.predict_proba(x_test)
        positive_col = list(pipeline.classes_).index(1)
        y_prob = probabilities[:, positive_col]
        y_pred = (y_prob >= 0.5).astype(int)
        tn, fp, fn, tp = confusion_matrix(y_test, y_pred, labels=[0, 1]).ravel()
        results[name] = {
            "cv": {
                "accuracy_mean": round(float(np.mean(scores["test_accuracy"])), 4),
                "accuracy_std": round(float(np.std(scores["test_accuracy"])), 4),
                "f1_mean": round(float(np.mean(scores["test_f1"])), 4),
                "f1_std": round(float(np.std(scores["test_f1"])), 4),
                "roc_auc_mean": round(float(np.mean(scores["test_roc_auc"])), 4),
            },
            "test": {
                "accuracy": round(float(accuracy_score(y_test, y_pred)), 4),
                "f1": round(float(f1_score(y_test, y_pred, zero_division=0)), 4),
                "precision": round(float(precision_score(y_test, y_pred, zero_division=0)), 4),
                "recall": round(float(recall_score(y_test, y_pred, zero_division=0)), 4),
                "roc_auc": round(float(roc_auc_score(y_test, y_prob)), 4),
                "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
                "false_positive_rate": round(float(fp / max(1, fp + tn)), 4),
                "false_positive_count": int(fp),
            },
            "fit_seconds": round(fit_seconds, 3),
            "inference": measure_inference_time(pipeline, x_test),
        }

    # Select on cross-validation F1, never on the test split.
    candidates = [k for k in results if k != "majority_baseline"]
    best_name = max(candidates, key=lambda k: results[k]["cv"]["f1_mean"])
    pipelines = make_pipelines(seed)
    best_pipeline = pipelines[best_name].fit(x_train, y_train)
    model_path = out_dir / "model.joblib"
    dump(
        {"pipeline": best_pipeline, "name": best_name, "features": FEATURE_NAMES,
         "seed": seed, "x_train": x_train, "train_columns": list(x_train.columns)},
        model_path,
    )

    report = {
        "best_model": best_name,
        "selection_criterion": "highest 5-fold cross-validated F1 on the training split",
        "target_sha256": target_sha256,
        "train_rows": int(len(x_train)),
        "test_rows": int(len(x_test)),
        "models": results,
        "model_path": str(model_path),
        "disclaimer": (
            "Scores are measured on a synthetic feature-space dataset. "
            "They are NOT estimates of real-world malware detection performance."
        ),
    }
    (out_dir / "metrics.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"[train] best model: {best_name} (CV F1={results[best_name]['cv']['f1_mean']:.4f})")
    print(f"[train] wrote {model_path} and {out_dir / 'metrics.json'}")
    return report
