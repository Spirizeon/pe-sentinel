"""Flask backend for the ascii.rest-styled PE classifier UI.

Uploaded files are only parsed statically. They are never executed, are stored
in a temporary file, and are deleted immediately after analysis.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, request, send_from_directory
from werkzeug.utils import secure_filename

from ..explain import explain_file

UI_DIR = Path(__file__).resolve().parent / "static"
DEFAULT_TARGET = Path("/home/berzi/Downloads/GeminiSetup.exe")
MAX_UPLOAD_BYTES = 100 * 1024 * 1024


def create_app(artifacts_dir: str | Path = "artifacts") -> Flask:
    artifacts_dir = Path(artifacts_dir).resolve()
    model_path = artifacts_dir / "model.joblib"
    app = Flask(__name__, static_folder=None)
    app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES

    @app.get("/")
    def index() -> Any:
        return send_from_directory(UI_DIR, "index.html")

    @app.get("/assets/<path:filename>")
    def assets(filename: str) -> Any:
        return send_from_directory(UI_DIR, filename)

    @app.get("/health")
    @app.get("/api/health")
    def health() -> Any:
        return jsonify({
            "model_ready": model_path.exists(),
            "model_path": str(model_path),
            "max_upload_mb": MAX_UPLOAD_BYTES // (1024 * 1024),
        })

    @app.get("/api/metrics")
    def metrics() -> Any:
        path = artifacts_dir / "metrics.json"
        if not path.exists():
            return jsonify({"error": "metrics.json not found; run training first"}), 404
        data = json.loads(path.read_text(encoding="utf-8"))
        return jsonify({
            "best_model": data["best_model"],
            "selection_criterion": data["selection_criterion"],
            "train_rows": data["train_rows"],
            "test_rows": data["test_rows"],
            "models": data["models"],
            "disclaimer": data["disclaimer"],
        })

    @app.get("/api/target-report")
    def target_report() -> Any:
        path = artifacts_dir / "reports" / "target_report.json"
        if not path.exists():
            return jsonify({"error": "target report not found; run predict first"}), 404
        return jsonify(json.loads(path.read_text(encoding="utf-8")))

    @app.post("/api/predict")
    def predict() -> Any:
        if not model_path.exists():
            return jsonify({"error": f"model not found at {model_path}; run ./run.sh train first"}), 503
        upload = request.files.get("file")
        if upload is None or not upload.filename:
            return jsonify({"error": "no file uploaded under form field 'file'"}), 400

        filename = secure_filename(upload.filename) or "sample.exe"
        suffix = Path(filename).suffix
        if suffix.lower() not in {".exe", ".dll", ".sys", ".bin", ".scr", ".msi"}:
            return jsonify({"error": "expected a Windows PE-like file (.exe/.dll/.sys/.bin/.scr/.msi)"}), 400

        with tempfile.TemporaryDirectory(prefix="malcls-upload-") as tmp:
            saved = Path(tmp) / filename
            upload.save(saved)
            if saved.stat().st_size == 0:
                return jsonify({"error": "uploaded file is empty"}), 400
            try:
                report = explain_file(model_path, saved)
            except Exception as exc:
                return jsonify({"error": f"analysis failed: {type(exc).__name__}: {exc}"}), 500
        report["uploaded_filename"] = filename
        return jsonify(report)

    return app


def run_server(
    host: str | None = None,
    port: int | None = None,
    artifacts_dir: str | Path = "artifacts",
) -> None:
    host = host or os.environ.get("HOST", "127.0.0.1")
    port = int(port or os.environ.get("PORT", "8000"))
    app = create_app(artifacts_dir)
    print(f"[ui] http://{host}:{port}  (ascii.rest CDN loaded in the browser)")
    app.run(host=host, port=port, debug=False)
