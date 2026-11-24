"""Command line entry point for the explainable PE classifier demo."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .dataset import DEFAULT_BENIGN_ROOT, SEED, build_dataset
from .explain import explain_file
from .models import train_and_evaluate

DEFAULT_TARGET = Path("/home/berzi/Downloads/GeminiSetup.exe")


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="malcls", description=__doc__)
    sub = p.add_subparsers(dest="command", required=True)

    def common(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("--data-dir", default="data", help="directory for dataset.csv / manifest.json")
        sp.add_argument("--artifacts-dir", default="artifacts", help="directory for model and reports")
        sp.add_argument("--target", default=str(DEFAULT_TARGET), help="PE file to hold out and explain")
        sp.add_argument("--benign-root", default=str(DEFAULT_BENIGN_ROOT))
        sp.add_argument("--n-benign", type=int, default=900)
        sp.add_argument("--n-malicious", type=int, default=900)
        sp.add_argument("--seed", type=int, default=SEED)
        sp.add_argument("--jobs", type=int, default=-1)

    common(sub.add_parser("build-dataset", help="extract real benign features + synthetic malicious rows"))
    train = sub.add_parser("train", help="compare models and save the best pipeline")
    train.add_argument("--data-dir", default="data")
    train.add_argument("--artifacts-dir", default="artifacts")
    train.add_argument("--seed", type=int, default=SEED)
    predict = sub.add_parser("predict", help="predict and explain one PE file")
    predict.add_argument("--artifacts-dir", default="artifacts")
    predict.add_argument("--target", default=str(DEFAULT_TARGET))
    predict.add_argument("--output", default=None)
    run = sub.add_parser("run-all", help="build dataset, train, evaluate, explain the target")
    common(run)
    ui = sub.add_parser("ui", help="launch the ascii.rest-styled web UI")
    ui.add_argument("--host", default=None, help="bind address (default: HOST env or 127.0.0.1)")
    ui.add_argument("--port", type=int, default=None, help="port (default: PORT env or 8000)")
    ui.add_argument("--artifacts-dir", default="artifacts")
    return p


def main() -> None:
    args = parser().parse_args()
    data_dir = Path(getattr(args, "data_dir", "data"))
    artifacts_dir = Path(getattr(args, "artifacts_dir", "artifacts"))

    if args.command in {"build-dataset", "run-all"}:
        manifest = build_dataset(
            out_dir=data_dir,
            benign_root=Path(args.benign_root),
            target=Path(args.target),
            n_benign=args.n_benign,
            n_malicious=args.n_malicious,
            seed=args.seed,
            n_jobs=args.jobs,
        )
        target_sha = manifest["target_sha256"]
    else:
        target_sha = None

    if args.command in {"train", "run-all"}:
        report = train_and_evaluate(
            csv_path=data_dir / "dataset.csv",
            out_dir=artifacts_dir,
            seed=args.seed,
            target_sha256=target_sha,
        )
        if args.command == "train":
            print(json.dumps({k: report[k] for k in ("best_model", "train_rows", "test_rows")}, indent=2))

    if args.command == "ui":
        from .ui.server import run_server
        run_server(host=args.host, port=args.port, artifacts_dir=artifacts_dir)
        return

    if args.command in {"predict", "run-all"}:
        out_path = Path(args.output) if getattr(args, "output", None) else artifacts_dir / "reports" / "target_report.json"
        result = explain_file(artifacts_dir / "model.joblib", Path(args.target), out_path=out_path)
        print(json.dumps({
            "file": result["file"],
            "prediction": result["prediction"],
            "malware_probability": result["malware_probability"],
            "model": result["model"],
            "top_attributions": result["top_attributions"][:5],
            "evidence": result["evidence"],
            "report": str(out_path),
        }, indent=2))


if __name__ == "__main__":
    main()
