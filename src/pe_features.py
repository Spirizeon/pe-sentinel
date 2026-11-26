"""Feature schema and extraction aligned with ``data/ficheiro_final.csv``.

The model is trained on the labelled rows of that corpus, so inference must
encode files with the *same* 27 columns. Categorical values use fixed,
explicit vocabularies shared by the CSV loader and this extractor; no
``factorize`` step can change the meaning of a column between training and
prediction.

Files are never executed. PE headers are parsed with ``pefile`` and the remaining
values come from byte-level statistics. Some corpus columns (the opcode counts)
cannot be reproduced without a disassembler dependency, so they are emitted as
0.0 and documented as unavailable rather than guessed.
"""

from __future__ import annotations

import ast
import hashlib
import math
import re
from pathlib import Path
from typing import Any

import pefile

# Fixed feature order, identical to the column order used during training.
# Never reorder without retraining and bumping a schema version.
FEATURE_NAMES: list[str] = [
    "Non-Printable Exists",
    "Non-Printable Count",
    "Size",
    "Permissions",
    "Data Sections Count",
    "Entropy",
    "Packed Status",
    "Suspicious Functions Count",
    "header_match",
    "creation_time",
    "entropy",
    "unicode_strings",
    "packer",
    "rsrc",
    "digital_signature",
    "extension",
    "suspicious_strings",
    "suspicious_strings_found",
    "encoding",
    "suspicious_encoding",
    "num_text_sections",
    "num_custom_sections",
    "arch",
    "unique_instruction_count",
    "average_opcode_count",
    "total_instruction_count",
    "instruction_diversity_ratio",
]

FEATURE_DESCRIPTIONS: dict[str, str] = {
    "Non-Printable Exists": "file contains bytes outside the printable ASCII range",
    "Non-Printable Count": "number of bytes outside the printable ASCII range",
    "Size": "file size in bytes",
    "Permissions": "POSIX permission bits written as decimal octal digits (e.g. 777)",
    "Data Sections Count": "sections whose name contains 'data'",
    "Entropy": "Shannon entropy of the whole file in bits/byte",
    "Packed Status": "packer indicator raised from section names",
    "Suspicious Functions Count": "number of imported API names",
    "header_match": "PE header parsed successfully",
    "creation_time": "PE TimeDateStamp (Unix seconds)",
    "entropy": "second entropy column in the corpus (whole-file Shannon entropy)",
    "unicode_strings": "count of printable UTF-16 string runs",
    "packer": "packer family: Unknown / UPX / MinPack",
    "rsrc": "PE resource directory present",
    "digital_signature": "PE security directory present",
    "extension": "file extension category (ordinal)",
    "suspicious_strings": "at least one suspicious string indicator present",
    "suspicious_strings_found": "number of suspicious string indicators found",
    "encoding": "detected content type (ordinal)",
    "suspicious_encoding": "encoding flagged as suspicious (always false in the corpus)",
    "num_text_sections": "sections whose name contains '.text'",
    "num_custom_sections": "sections outside the common PE name allow-list",
    "arch": "architecture category (ordinal)",
    "unique_instruction_count": "unique opcodes (unavailable in this build; encoded as 0)",
    "average_opcode_count": "mean opcode count (unavailable in this build; encoded as 0)",
    "total_instruction_count": "total opcodes (unavailable in this build; encoded as 0)",
    "instruction_diversity_ratio": "opcode diversity (unavailable in this build; encoded as 0)",
}

# Shared vocabularies. Categories seen in the corpus are listed explicitly;
# anything else falls into a stable "other" bucket instead of being factorized.
YES_NO = {"yes": 1.0, "no": 0.0}
TRUE_FALSE = {"true": 1.0, "false": 0.0}
VOCABULARIES: dict[str, dict[str, float]] = {
    "Non-Printable Exists": YES_NO,
    "Packed Status": YES_NO,
    "header_match": TRUE_FALSE,
    "digital_signature": TRUE_FALSE,
    "suspicious_strings": TRUE_FALSE,
    "suspicious_encoding": TRUE_FALSE,
    "packer": {"unknown": 0.0, "upx": 1.0, "minpack": 2.0},
    "extension": {
        ".exe": 0.0, ".dll": 1.0, ".elf": 2.0, ".js": 3.0, ".bat": 4.0,
        ".ps1": 5.0, ".sh": 6.0, ".vbs": 7.0, ".zip": 8.0, ".msi": 9.0,
        ".other": 10.0,
    },
    "arch": {
        "x86": 0.0, "x86_64": 1.0, "not_pe": 2.0,
        "x86_protected": 3.0, "x86_64_protected": 4.0, "no_entry_section": 5.0,
    },
    "encoding": {
        "application/x-dosexec": 0.0, "application/x-executable": 1.0,
        "text/plain": 2.0, "other": 3.0,
    },
}
OTHER_BUCKET: dict[str, float] = {"extension": ".other", "encoding": "other"}

# Kept in the report schema but not fed to the model. Both columns encode how
# the corpus was collected rather than what a file does: every benign row is
# stamped 2025-04-24 and permission bits reflect the collection environment.
# They produce near-perfect CV scores and push out-of-range uploads (including
# the benign demo installer) toward "malicious".
NON_MODEL_FEATURES: tuple[str, ...] = ("creation_time", "Permissions")
MODEL_FEATURES: list[str] = [name for name in FEATURE_NAMES if name not in NON_MODEL_FEATURES]

COMMON_SECTION_NAMES = {".text", ".data", ".rdata", ".rsrc", ".reloc"}
SUSPICIOUS_INDICATORS = (
    "http://", "https://", "wget", "curl", "ren", "attrib", "dir", "route",
    "shutdown", "replace", "iex", "base64", "xor", "rdp", "arp", "powershell",
    "cmd", "echo", "runas", "get-module", "hidden",
)
_UTF16_RUN = re.compile(r"[\x20-\x7e]{4,}")


def encode_value(name: str, value: Any) -> float:
    """Encode one corpus value using the training/inference vocabulary."""
    if name not in FEATURE_NAMES:
        raise KeyError(f"unknown feature column: {name}")

    if name == "suspicious_strings_found" and isinstance(value, str):
        try:
            parsed = ast.literal_eval(value)
        except (ValueError, SyntaxError):
            parsed = []
        if isinstance(parsed, (list, tuple, set)):
            return float(len(parsed))
        if isinstance(parsed, (int, float)):
            return float(parsed)
        return 0.0

    text = str(value).strip()
    vocab = VOCABULARIES.get(name)
    if vocab is not None:
        key = text.lower()
        if name == "extension":
            key = key if key.startswith(".") else f".{key}"
        if key in vocab:
            return vocab[key]
        return vocab.get(OTHER_BUCKET.get(name, ""), 0.0)

    if not text:
        return 0.0
    try:
        number = float(text)
    except ValueError:
        return 0.0
    return number if math.isfinite(number) else 0.0


def decode_value(name: str, value: float) -> str:
    """Human-readable form of an encoded categorical value."""
    vocab = VOCABULARIES.get(name)
    if vocab is None:
        return f"{value:g}"
    for label, encoded in vocab.items():
        if encoded == value:
            return label
    return "unknown"


def vectorize(features: dict[str, float]) -> list[float]:
    """Convert a feature dict to the fixed numeric vector used by the model."""
    return [float(features.get(name, 0.0)) for name in FEATURE_NAMES]


def _entropy(data: bytes) -> float:
    """Shannon entropy in bits/byte."""
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in counts if c)


def _string_indicators(raw: bytes) -> tuple[int, int]:
    """Best-effort match for the corpus' suspicious-string columns."""
    ascii_text = raw.decode("latin-1", errors="ignore").lower()
    utf16_text = raw.decode("utf-16-le", errors="ignore").lower()
    found = [token for token in SUSPICIOUS_INDICATORS if token in ascii_text or token in utf16_text]
    return len(found), len(found)


def _empty_result(path: Path, raw: bytes, notes: list[str]) -> dict[str, Any]:
    features = {name: 0.0 for name in FEATURE_NAMES}
    features["Size"] = float(len(raw))
    features["Entropy"] = _entropy(raw)
    features["entropy"] = features["Entropy"]
    non_printable = sum(1 for byte in raw if byte < 32 or byte > 126)
    features["Non-Printable Count"] = float(non_printable)
    features["Non-Printable Exists"] = encode_value("Non-Printable Exists", "Yes" if non_printable else "No")
    features["Permissions"] = float(int(format(path.stat().st_mode & 0o777, "03o")))
    features["extension"] = encode_value("extension", path.suffix.lower() or ".unknown")
    features["arch"] = encode_value("arch", "not_pe")
    indicators, count = _string_indicators(raw)
    features["suspicious_strings"] = float(indicators > 0)
    features["suspicious_strings_found"] = float(count)
    evidence = {
        "path": str(path),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "size_bytes": len(raw),
        "notes": notes,
    }
    return {"features": features, "evidence": evidence}


def extract_features(path: str | Path) -> dict[str, Any]:
    """Extract the 27-column vector and supporting evidence from a file."""
    path = Path(path)
    raw = path.read_bytes()
    notes: list[str] = []

    try:
        pe = pefile.PE(data=raw, fast_load=False)
    except Exception as exc:  # non-PE inputs are still scored, with PE fields at 0
        notes.append(f"PE parse failed: {type(exc).__name__}: {exc}")
        return _empty_result(path, raw, notes)

    try:
        features = {name: 0.0 for name in FEATURE_NAMES}
        evidence: dict[str, Any] = {
            "path": str(path),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "size_bytes": len(raw),
            "section_names": [],
            "imported_dlls": [],
            "notes": notes,
        }

        features["Size"] = float(len(raw))
        features["Entropy"] = _entropy(raw)
        features["entropy"] = features["Entropy"]
        non_printable = sum(1 for byte in raw if byte < 32 or byte > 126)
        features["Non-Printable Count"] = float(non_printable)
        features["Non-Printable Exists"] = encode_value(
            "Non-Printable Exists", "Yes" if non_printable else "No"
        )
        features["Permissions"] = float(int(format(path.stat().st_mode & 0o777, "03o")))
        features["header_match"] = encode_value("header_match", True)
        features["creation_time"] = float(pe.FILE_HEADER.TimeDateStamp)
        features["extension"] = encode_value("extension", path.suffix.lower() or ".unknown")
        features["encoding"] = encode_value("encoding", "application/x-dosexec")

        machine = int(pe.FILE_HEADER.Machine)
        arch = "x86_64" if machine == 0x8664 else "x86"
        features["arch"] = encode_value("arch", arch)

        text_sections = custom_sections = data_sections = 0
        packer = "Unknown"
        for section in pe.sections:
            name = bytes(section.Name).rstrip(b"\x00").decode("latin-1", errors="replace")
            name_l = name.lower()
            text_sections += int(".text" in name_l)
            data_sections += int("data" in name_l)
            if name_l not in COMMON_SECTION_NAMES:
                custom_sections += 1
            if "upx" in name_l:
                packer = "UPX"
            elif "minpack" in name_l and packer == "Unknown":
                packer = "MinPack"
        features["num_text_sections"] = float(text_sections)
        features["num_custom_sections"] = float(custom_sections)
        features["Data Sections Count"] = float(data_sections)
        evidence["section_names"] = [
            bytes(section.Name).rstrip(b"\x00").decode("latin-1", errors="replace")
            for section in pe.sections
        ]

        features["packer"] = encode_value("packer", packer)
        features["Packed Status"] = encode_value("Packed Status", "Yes" if packer != "Unknown" else "No")
        features["rsrc"] = float(hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"))
        features["digital_signature"] = float(
            getattr(pe.OPTIONAL_HEADER.DATA_DIRECTORY[4], "VirtualAddress", 0) != 0
        )

        dlls: set[str] = set()
        api_count = 0
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dlls.add(entry.dll.decode("latin-1", errors="ignore").lower())
                api_count += len(entry.imports)
        features["Suspicious Functions Count"] = float(api_count)
        evidence["imported_dlls"] = sorted(dlls)

        unicode_runs = len(_UTF16_RUN.findall(raw.decode("utf-16-le", errors="ignore")))
        features["unicode_strings"] = float(unicode_runs)
        indicators, count = _string_indicators(raw)
        features["suspicious_strings"] = float(indicators > 0)
        features["suspicious_strings_found"] = float(count)

        notes.append("Opcode-count columns are unavailable here (no disassembler); encoded as 0.")
        notes.append(f"PE TimeDateStamp maps to creation_time {features['creation_time']:.0f}.")
    finally:
        pe.close()

    for key in FEATURE_NAMES:
        value = float(features.get(key, 0.0))
        features[key] = value if math.isfinite(value) else 0.0
    return {"features": features, "evidence": evidence}


def human_evidence(features: dict[str, float], top_n: int = 8) -> list[str]:
    """Short, rule-based statements backed by encoded feature values."""
    lines: list[str] = []
    size = features.get("Size", 0.0)
    if size:
        lines.append(f"file size is {int(size)} bytes")
    entropy = features.get("Entropy", 0.0)
    if entropy >= 7.0:
        lines.append(f"whole-file entropy is {entropy:.2f} bits/byte (possible packing)")
    if features.get("header_match", 0.0):
        lines.append(f"PE header parsed; architecture {decode_value('arch', features['arch'])}, "
                     f"extension {decode_value('extension', features['extension'])}")
    else:
        lines.append("no PE header parsed; PE-specific features set to zero")
    if features.get("packer", 0.0):
        lines.append(f"packer indicator: {decode_value('packer', features['packer'])}")
    sections = int(features.get("num_custom_sections", 0))
    if sections:
        lines.append(f"{sections} non-standard section name(s)")
    imports = int(features.get("Suspicious Functions Count", 0))
    if imports:
        lines.append(f"{imports} imported API name(s)")
    strings = int(features.get("suspicious_strings_found", 0))
    if strings:
        lines.append(f"{strings} suspicious string indicator(s)")
    if features.get("rsrc", 0.0):
        lines.append("PE resource directory present")
    if features.get("digital_signature", 0.0):
        lines.append("PE security directory present")
    if not lines:
        lines.append("no notable static indicators were observed")
    return lines[:top_n]
