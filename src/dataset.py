"""Build a deterministic, documented dataset for the demo classifier.

Important: only the benign rows come from real files. Malicious rows are
*synthetic feature-space variants* of benign PEs: no malware is downloaded,
generated or executed. They encode well-known static malware indicators so the
pipeline can be exercised end-to-end. Any metric produced from this dataset is
a demonstration of the machinery, not an estimate of real-world detection rate.
"""

from __future__ import annotations

import json
import os
import random
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from joblib import Parallel, delayed

from .pe_features import FEATURE_NAMES, extract_features, vectorize

DEFAULT_BENIGN_ROOT = Path(
    os.environ.get(
        "MALCLS_BENIGN_ROOT",
        "/home/berzi/.local/share/Steam/steamapps/common/Proton - Experimental/files/lib/wine",
    )
)

MAX_BENIGN_BYTES = 40 * 1024 * 1024
BENIGN_EXTS = {".exe", ".dll"}
SEED = 42


def collect_benign_paths(root: Path, limit: int, seed: int = SEED) -> list[Path]:
    """Deterministically sample real Windows PE files from a trusted tree."""
    candidates = sorted(
        p for p in root.rglob("*")
        if p.is_file()
        and p.suffix.lower() in BENIGN_EXTS
        and p.stat().st_size <= MAX_BENIGN_BYTES
    )
    rng = random.Random(seed)
    rng.shuffle(candidates)
    return candidates[:limit]


def _row_from_path(path: Path, label: int, split_hint: str = "") -> dict[str, Any]:
    result = extract_features(path)
    row: dict[str, Any] = dict(zip(FEATURE_NAMES, vectorize(result["features"])))
    row.update({
        "label": int(label),
        "source": "real_benign" if label == 0 else "synthetic_malicious",
        "source_path": str(path),
        "sha256": result["evidence"]["sha256"],
        "split_hint": split_hint,
    })
    return row


def _weak_benign_noise(row: dict[str, Any], rng: random.Random) -> None:
    """Give some benign rows realistic-looking but benign suspicious traits."""
    n = rng.randint(1, 3)
    choices = [
        ("import_network", 1, 4),
        ("import_crypto", 1, 3),
        ("str_url", 1, 2),
        ("str_ip", 1, 2),
        ("str_registry", 1, 3),
        ("import_file_ops", 1, 5),
        ("dep_disabled", 1, 1),
        ("import_sleep", 1, 2),
    ]
    for key, lo, hi in rng.sample(choices, n):
        row[key] = float(min(80.0, row.get(key, 0.0) + rng.randint(lo, hi)))


def _installer_benign_noise(row: dict[str, Any], rng: random.Random) -> None:
    """Model legitimate signed installers/updaters, a common benign look-alike.

    Installers embed URLs/IPs, create processes, touch the registry and carry
    large resource sections. Teaching this pattern avoids the naive rule
    'URLs or service APIs means malware'. Values are generic domain knowledge,
    not copied from the held-out target file.
    """
    row["is_signed"] = 1.0
    row["str_url"] = float(rng.randint(8, 90))
    row["str_ip"] = float(rng.randint(0, 35))
    row["str_registry"] = float(rng.randint(2, 20))
    row["str_path"] = float(rng.randint(1, 15))
    row["str_script_ext"] = float(rng.randint(0, 12))
    row["import_network"] = float(rng.randint(1, 10))
    row["import_persistence"] = float(rng.randint(0, 6))
    row["import_shell_exec"] = float(rng.randint(0, 5))
    row["import_file_ops"] = float(rng.randint(1, 12))
    row["import_native"] = float(rng.randint(0, 4))
    row["resource_count_log10"] = max(row["resource_count_log10"], float(rng.uniform(1.5, 4.0)))
    row["num_writable_sections"] = max(row["num_writable_sections"], float(rng.randint(1, 5)))
    row["has_overlay"] = 1.0
    row["overlay_ratio"] = max(row["overlay_ratio"], float(rng.uniform(0.0, 0.08)))


def _make_malicious(base: dict[str, Any], rng: random.Random, strength: str) -> dict[str, Any]:
    """Create a synthetic malware-like feature row from a benign feature row."""
    row = dict(base)
    row["label"] = 1
    row["source"] = "synthetic_malicious"
    row["source_path"] = base["source_path"] + " (feature-space variant)"
    row["sha256"] = base["sha256"]

    # Base jitter keeps the classes from being trivially separable.
    for key in ("file_size_log10", "total_raw_size_log10", "import_count_log10",
                "num_sections", "mean_section_entropy", "max_section_entropy",
                "resource_count_log10", "num_high_entropy_sections"):
        row[key] = float(max(0.0, row.get(key, 0.0) * rng.uniform(0.85, 1.2) + rng.gauss(0, 0.03)))

    patterns: list[str]
    if strength == "strong":
        patterns = rng.sample(
            ["packing", "rwx", "inject", "network", "persistence", "antidebug",
             "crypto", "shell", "overlay", "strings", "flags", "entrypoint"],
            k=rng.randint(5, 8),
        )
    elif strength == "medium":
        patterns = rng.sample(
            ["packing", "rwx", "inject", "network", "persistence", "antidebug",
             "crypto", "shell", "overlay", "strings", "flags"],
            k=rng.randint(3, 5),
        )
    else:  # weak / evasive: deliberately overlaps benign feature space
        patterns = rng.sample(
            ["inject", "network", "strings", "flags", "sleep", "dynamic_load"],
            k=rng.randint(1, 2),
        )

    for pattern in patterns:
        if pattern == "packing":
            row["num_high_entropy_sections"] = float(rng.randint(1, 4))
            row["max_section_entropy"] = min(8.0, max(row["max_section_entropy"], rng.uniform(7.3, 7.99)))
            row["mean_section_entropy"] = min(8.0, row["mean_section_entropy"] + rng.uniform(0.5, 1.5))
            row["num_suspicious_section_names"] = float(rng.randint(1, 3))
            row["num_empty_raw_sections"] = float(rng.randint(0, 2))
        elif pattern == "rwx":
            row["num_wx_sections"] = float(rng.randint(1, 3))
            row["num_rwx_sections"] = float(rng.randint(1, 2))
            row["num_writable_sections"] += rng.randint(1, 2)
        elif pattern == "inject":
            row["import_inject"] = float(rng.randint(2, 8))
            row["import_dynamic_load"] = float(max(row["import_dynamic_load"], rng.randint(2, 6)))
            row["import_native"] = float(max(row["import_native"], rng.randint(1, 4)))
        elif pattern == "network":
            row["import_network"] = float(rng.randint(2, 10))
            row["str_url"] = float(rng.randint(1, 8))
            row["str_ip"] = float(rng.randint(0, 4))
        elif pattern == "persistence":
            row["import_persistence"] = float(rng.randint(2, 8))
            row["str_registry"] = float(rng.randint(2, 12))
            row["str_path"] = float(rng.randint(1, 8))
        elif pattern == "antidebug":
            row["import_antidebug"] = float(rng.randint(2, 7))
            row["import_sleep"] = float(rng.randint(1, 5))
        elif pattern == "crypto":
            row["import_crypto"] = float(rng.randint(2, 10))
            row["str_base64"] = float(rng.randint(1, 6))
        elif pattern == "shell":
            row["import_shell_exec"] = float(rng.randint(1, 5))
            row["str_cmd"] = float(rng.randint(0, 3))
            row["str_powershell"] = float(rng.randint(1, 5))
        elif pattern == "overlay":
            row["overlay_ratio"] = float(rng.uniform(0.05, 0.45))
            row["has_overlay"] = 1.0
        elif pattern == "strings":
            row["str_script_ext"] = float(rng.randint(2, 10))
            row["str_url"] = float(rng.randint(1, 6))
            row["str_powershell"] = float(rng.randint(0, 4))
        elif pattern == "flags":
            row["dep_disabled"] = 1.0
            row["aslr_disabled"] = 1.0
            if rng.random() < 0.4:
                row["no_seh"] = 1.0
        elif pattern == "sleep":
            row["import_sleep"] = float(rng.randint(2, 6))
        elif pattern == "dynamic_load":
            row["import_dynamic_load"] = float(rng.randint(3, 8))
        elif pattern == "entrypoint":
            row["entrypoint_in_code"] = 0.0
            row["entrypoint_section_idx"] = float(rng.randint(1, 8))

    if rng.random() < 0.12:
        row["timestamp_anomaly"] = 1.0
    if rng.random() < 0.15:
        row["is_signed"] = 0.0

    for key in FEATURE_NAMES:
        value = float(row.get(key, 0.0))
        if not np.isfinite(value):
            value = 0.0
        row[key] = max(0.0, value)
    return row


def build_dataset(
    out_dir: str | Path,
    benign_root: str | Path = DEFAULT_BENIGN_ROOT,
    target: str | Path | None = None,
    n_benign: int = 900,
    n_malicious: int = 900,
    test_size: float = 0.2,
    seed: int = SEED,
    n_jobs: int = -1,
) -> dict[str, Any]:
    """Extract real benign features, synthesise malicious rows, write CSV + manifest."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    benign_root = Path(benign_root)
    target_path = Path(target).resolve() if target else None

    benign_paths = collect_benign_paths(benign_root, n_benign, seed=seed)
    if not benign_paths:
        raise RuntimeError(f"No PE files found under {benign_root}")
    print(f"[dataset] extracting {len(benign_paths)} benign PE files from {benign_root}")
    rows = Parallel(n_jobs=n_jobs, prefer="threads", verbose=0)(
        delayed(_row_from_path)(p, 0) for p in benign_paths
    )

    # Hold the user's file out of training entirely; it is only ever a test sample.
    if target_path:
        target_row = _row_from_path(target_path, 0, split_hint="test_target")
        rows = [r for r in rows if Path(r["source_path"]).resolve() != target_path]
    else:
        target_row = None

    rng = random.Random(seed)
    benign_pool = list(rows)
    malicious_rows = []
    for i in range(n_malicious):
        base = rng.choice(benign_pool)
        strength = "strong" if i < int(n_malicious * 0.55) else (
            "medium" if i < int(n_malicious * 0.85) else "weak"
        )
        malicious_rows.append(_make_malicious(base, rng, strength))

    # Add benign/realistic overlap so the classifier has to make real trade-offs.
    for row in benign_pool:
        draw = rng.random()
        if draw < 0.22:
            _installer_benign_noise(row, rng)
        elif draw < 0.40:
            _weak_benign_noise(row, rng)

    all_rows = benign_pool + malicious_rows
    frame = pd.DataFrame(all_rows, columns=FEATURE_NAMES + ["label", "source", "source_path", "sha256", "split_hint"])
    frame = frame.sample(frac=1.0, random_state=seed).reset_index(drop=True)

    n_test = max(1, int(len(frame) * test_size))
    frame["split"] = "train"
    frame.loc[frame.index[:n_test], "split"] = "test"

    if target_row is not None:
        target_df = pd.DataFrame([target_row], columns=frame.columns)
        target_df["split"] = "test"
        frame = pd.concat([frame, target_df], ignore_index=True)

    csv_path = out_dir / "dataset.csv"
    frame.to_csv(csv_path, index=False)

    manifest = {
        "seed": seed,
        "benign_root": str(benign_root),
        "benign_real_count": int((frame["source"] == "real_benign").sum()),
        "malicious_synthetic_count": int((frame["source"] == "synthetic_malicious").sum()),
        "target_file": str(target_path) if target_path else None,
        "target_sha256": target_row["sha256"] if target_row else None,
        "target_in_test_only": bool(target_row is not None),
        "split_counts": frame["split"].value_counts().to_dict(),
        "feature_count": len(FEATURE_NAMES),
        "features": FEATURE_NAMES,
        "disclaimer": (
            "Malicious rows are synthetic feature-space variants, not real malware. "
            "Metrics demonstrate pipeline behaviour only and do not generalise to real threats."
        ),
    }
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"[dataset] wrote {csv_path} ({len(frame)} rows, {len(FEATURE_NAMES)} features)")
    return manifest
