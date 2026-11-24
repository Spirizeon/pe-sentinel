"""Reproducible static feature extraction for Windows PE files.

The extractor never executes the sample. It only parses PE metadata and counts
byte-level string indicators. All output is a fixed-width numeric vector plus a
human-readable evidence dictionary, which makes results auditable.
"""

from __future__ import annotations

import hashlib
import math
import re
from pathlib import Path
from typing import Any

import pefile

# ---------------------------------------------------------------------------
# Indicator vocabularies (kept explicit so the model can be audited)
# ---------------------------------------------------------------------------

SUSPICIOUS_SECTION_NAMES = (
    "upx", "aspack", "nsp", "petite", "themida", "vmp", "vmprotect",
    "cry", "crypt", "packed", "confuser", "enigma", "mpress", "rlpack",
    ".boot", "code",  # unusual code section names
)

API_CATEGORIES: dict[str, tuple[str, ...]] = {
    # Dual-use APIs such as OpenProcess/ReadProcessMemory/GetTickCount are
    # deliberately excluded: installers and games use them legitimately, and
    # including them produced false positives without adding real signal.
    "inject": (
        "virtualallocex", "writeprocessmemory", "createremotethread",
        "ntunmapviewofsection", "queueuserapc",
        "setthreadcontext", "createremotethreadex", "rtlcreateuserthread",
        "ntcreatethreadex",
    ),
    "antidebug": (
        "isdebuggerpresent", "checkremotedebuggerpresent", "outputdebugstring",
        "ntqueryinformationprocess", "ntsetinformationthread",
    ),
    "network": (
        "winhttpopen", "winhttpconnect", "winhttpsendrequest", "winhttpreaddata",
        "internetopen", "internetopenurl", "urldownloadtofile", "socket",
        "connect", "send", "recv", "wsastartup", "getaddrinfo", "httpopenrequest",
        "internetreadfile", "winhttpwritedata", "wsasend", "wsarecv",
    ),
    "crypto": (
        "cryptencrypt", "cryptdecrypt", "cryptgenkey", "crypthashdata",
        "bcryptencrypt", "bcryptdecrypt", "bcryptgenkey", "bcrypthash",
        "cryptstringtobinary", "cryptbinarytostring",
    ),
    "persistence": (
        "regsetvalueex", "regcreatekeyex", "createprocessasuser", "createservice",
        "changeserviceconfig", "startservice", "regsetvalue", "regopenkeyex",
        "writeeventlog", "createscheduledtask",
    ),
    "file_ops": (
        "createfilew", "createfilea", "deletefilew", "deletefilea", "copyfilew",
        "copyfilea", "movefilew", "movefilea", "findfirstfilew", "findnextfilew",
    ),
    "dynamic_load": ("loadlibrarya", "loadlibraryw", "loadlibraryexa",
                     "loadlibraryexw", "getprocaddress", "freelibrary"),
    "shell_exec": ("winexec", "shellexecute", "shellexecuteexw", "createprocessw",
                   "createprocessa", "createprocessinternalw", "system"),
    "privilege": ("adjusttokenprivileges", "openprocesstoken", "lookupprivilegevalue",
                  "setsecuritydescriptor", "duplicateTokenEx".lower(), "impersonateloggedonuser"),
    "sleep": ("sleep", "sleepEx".lower(), "ntDelayExecution".lower()),
    "native": ("ntqueryobject", "ntquerydirectoryobject", "ntdeletekey",
               "rtlgetversion", "ntcreatesection", "ntmapviewofsection"),
}

STRING_PATTERNS: dict[str, re.Pattern[str]] = {
    "url": re.compile(r"https?://[^\s\"'\x00<>]{6,}", re.IGNORECASE),
    "ip": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "registry": re.compile(r"(?:HKEY_[A-Z_]+|\\Software\\)", re.IGNORECASE),
    "path": re.compile(r"(?:[A-Za-z]:\\|%AppData%|%Temp%|%ProgramFiles%|%SystemRoot%)", re.IGNORECASE),
    "powershell": re.compile(r"(?:powershell|pwsh|-enc\b|frombase64string|invoke-expression|\bIEX\b)", re.IGNORECASE),
    "cmd_shell": re.compile(r"cmd\.exe", re.IGNORECASE),
    "script_ext": re.compile(r"\.(?:exe|dll|bat|cmd|vbs|ps1|js|hta|scr|jar)\b", re.IGNORECASE),
    "base64_blob": re.compile(r"[A-Za-z0-9+/]{60,}={0,2}"),
}

# Fixed feature order. Never reorder without retraining and bumping a version.
FEATURE_NAMES: list[str] = [
    "file_size_log10",
    "file_size_mb",
    "pe32plus",
    "machine_i386",
    "machine_amd64",
    "subsystem_gui",
    "subsystem_console",
    "timestamp_year",
    "timestamp_anomaly",
    "is_dll",
    "is_signed",
    "dep_disabled",
    "aslr_disabled",
    "no_seh",
    "high_entropy_va",
    "entrypoint_in_code",
    "entrypoint_section_idx",
    "num_sections",
    "num_writable_sections",
    "num_executable_sections",
    "num_wx_sections",
    "num_rwx_sections",
    "num_high_entropy_sections",
    "num_empty_raw_sections",
    "num_suspicious_section_names",
    "num_unknown_section_names",
    "max_section_entropy",
    "mean_section_entropy",
    "std_section_entropy",
    "total_raw_size_log10",
    "total_virtual_size_log10",
    "raw_virtual_ratio",
    "overlay_ratio",
    "has_overlay",
    "import_count_log10",
    "import_dll_count",
    "import_inject",
    "import_antidebug",
    "import_network",
    "import_crypto",
    "import_persistence",
    "import_file_ops",
    "import_dynamic_load",
    "import_shell_exec",
    "import_privilege",
    "import_sleep",
    "import_native",
    "export_count_log10",
    "has_exports",
    "resource_count_log10",
    "resource_size_ratio",
    "has_resources",
    "has_debug",
    "has_tls",
    "has_reloc",
    "str_url",
    "str_ip",
    "str_registry",
    "str_path",
    "str_powershell",
    "str_cmd",
    "str_script_ext",
    "str_base64",
    "parse_error",
]

FEATURE_DESCRIPTIONS: dict[str, str] = {
    "file_size_log10": "log10 of the file size in bytes",
    "file_size_mb": "file size in MiB",
    "pe32plus": "PE32+ (64-bit) optional header",
    "machine_i386": "target machine is x86",
    "machine_amd64": "target machine is x86-64",
    "subsystem_gui": "GUI subsystem",
    "subsystem_console": "console subsystem",
    "timestamp_year": "year derived from the PE TimeDateStamp",
    "timestamp_anomaly": "timestamp is implausible (pre-1990 or in the future)",
    "is_dll": "IMAGE_FILE_DLL characteristic set",
    "is_signed": "Authenticode security directory present",
    "dep_disabled": "IMAGE_DLLCHARACTERISTICS_NX_COMPAT is not set",
    "aslr_disabled": "IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE is not set",
    "no_seh": "IMAGE_DLLCHARACTERISTICS_NO_SEH is set",
    "high_entropy_va": "IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA is set",
    "entrypoint_in_code": "entry point RVA falls inside a named code section",
    "entrypoint_section_idx": "index of the section containing the entry point",
    "num_sections": "number of PE sections",
    "num_writable_sections": "sections with IMAGE_SCN_MEM_WRITE",
    "num_executable_sections": "sections with IMAGE_SCN_MEM_EXECUTE",
    "num_wx_sections": "sections writable and executable",
    "num_rwx_sections": "sections readable, writable and executable",
    "num_high_entropy_sections": "sections with Shannon entropy > 7.0 (packing indicator)",
    "num_empty_raw_sections": "sections with virtual size but no raw data",
    "num_suspicious_section_names": "section names matching known packer/crypter names",
    "num_unknown_section_names": "section names outside a common allow-list",
    "max_section_entropy": "highest per-section Shannon entropy",
    "mean_section_entropy": "mean per-section Shannon entropy",
    "std_section_entropy": "standard deviation of section entropy",
    "total_raw_size_log10": "log10 of the sum of section raw sizes",
    "total_virtual_size_log10": "log10 of the sum of section virtual sizes",
    "raw_virtual_ratio": "raw size divided by virtual size",
    "overlay_ratio": "bytes appended after the last section divided by file size",
    "has_overlay": "non-empty PE overlay present",
    "import_count_log10": "log10 of the number of imported API names",
    "import_dll_count": "number of distinct imported DLLs",
    "import_inject": "imports used for process injection / cross-process memory",
    "import_antidebug": "anti-debugging / timing APIs",
    "import_network": "networking and download APIs",
    "import_crypto": "cryptography APIs",
    "import_persistence": "registry/service persistence APIs",
    "import_file_ops": "file system manipulation APIs",
    "import_dynamic_load": "runtime DLL loading / address resolution APIs",
    "import_shell_exec": "process creation APIs",
    "import_privilege": "token and privilege manipulation APIs",
    "import_sleep": "sleep / delay APIs",
    "import_native": "low-level native/ntdll APIs",
    "export_count_log10": "log10 of the number of exported symbols",
    "has_exports": "export directory present",
    "resource_count_log10": "log10 of the number of resource entries",
    "resource_size_ratio": "resource directory size divided by file size",
    "has_resources": "resource directory present",
    "has_debug": "debug directory present",
    "has_tls": "TLS directory present",
    "has_reloc": "base relocation directory present",
    "str_url": "count of http(s) URLs in ASCII/UTF-16 strings",
    "str_ip": "count of dotted-quad IP addresses in strings",
    "str_registry": "count of registry key references in strings",
    "str_path": "count of filesystem path patterns in strings",
    "str_powershell": "count of PowerShell / encoded-command indicators",
    "str_cmd": "count of cmd.exe references",
    "str_script_ext": "count of executable/script file extensions in strings",
    "str_base64": "count of long base64-like blobs in strings",
    "parse_error": "PE parser raised an error for this file",
}

COMMON_SECTION_NAMES = {
    ".text", ".rdata", ".data", ".rsrc", ".reloc", ".bss", ".idata", ".edata",
    ".pdata", ".xdata", ".tls", ".CRT", ".git", ".debug", ".tfm", ".drectve",
    ".cormeta", ".sxdata", ".fvmeter", ".fptable", "cpadinfo", "malloc_h",
    ".text$mn", ".text$zz", ".rdata$r", ".data$r", ".rsrc$01", ".rsrc$02",
}

_COUNTER_KEYS = tuple(k for k in FEATURE_NAMES if k.startswith(("str_", "import_")))


def _entropy(data: bytes) -> float:
    """Shannon entropy in bits/byte."""
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in counts if c)


def _log10p1(value: float) -> float:
    return math.log10(max(0.0, float(value)) + 1.0)


def _count_resources(pe: pefile.PE) -> tuple[int, int]:
    """Count resource entries and sum leaf data sizes without assuming a layout."""
    root = getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None)
    if root is None:
        return 0, 0
    stack = [root]
    count = 0
    total_size = 0
    while stack:
        directory = stack.pop()
        struct = getattr(directory, "struct", None)
        if struct is not None:
            count += int(getattr(struct, "NumberOfNamedEntries", 0)) + int(
                getattr(struct, "NumberOfIdEntries", 0)
            )
        for entry in getattr(directory, "entries", []):
            subdir = getattr(entry, "directory", None)
            if subdir is not None:
                stack.append(subdir)
            data = getattr(entry, "data", None)
            if data is not None:
                data_struct = getattr(data, "struct", None)
                if data_struct is not None:
                    total_size += int(getattr(data_struct, "Size", 0))
    return count, total_size


def _string_counts(raw: bytes) -> dict[str, float]:
    text_ascii = raw.decode("latin-1", errors="ignore")
    try:
        text_utf16 = raw.decode("utf-16-le", errors="ignore")
    except Exception:
        text_utf16 = ""
    counts: dict[str, float] = {}
    for key, pattern in STRING_PATTERNS.items():
        n = len(pattern.findall(text_ascii)) + len(pattern.findall(text_utf16))
        if key == "ip":
            n = sum(
                1
                for match in pattern.findall(text_ascii) + pattern.findall(text_utf16)
                if all(0 <= int(part) <= 255 for part in match.split("."))
            )
        counts[key] = float(min(n, 200))
    return counts


def _empty_features() -> dict[str, float]:
    features = {name: 0.0 for name in FEATURE_NAMES}
    features["parse_error"] = 1.0
    return features


def extract_features(path: str | Path) -> dict[str, Any]:
    """Extract the fixed feature vector and supporting evidence from a PE file."""
    path = Path(path)
    raw = path.read_bytes()
    sha256 = hashlib.sha256(raw).hexdigest()
    features = _empty_features()
    evidence: dict[str, Any] = {
        "path": str(path),
        "sha256": sha256,
        "size_bytes": len(raw),
        "section_names": [],
        "imported_dlls": [],
        "top_import_categories": [],
        "string_indicators": {},
        "notes": [],
    }

    try:
        pe = pefile.PE(data=raw, fast_load=False)
        features["parse_error"] = 0.0
    except Exception as exc:  # malformed / non-PE input
        evidence["notes"].append(f"PE parse failed: {type(exc).__name__}: {exc}")
        return {"features": features, "evidence": evidence}

    try:
        file_header = pe.FILE_HEADER
        optional = pe.OPTIONAL_HEADER
        features["file_size_log10"] = _log10p1(len(raw))
        features["file_size_mb"] = len(raw) / (1024 * 1024)
        features["pe32plus"] = float(optional.Magic == 0x20B)
        features["machine_i386"] = float(file_header.Machine == 0x014C)
        features["machine_amd64"] = float(file_header.Machine == 0x8664)
        features["subsystem_gui"] = float(optional.Subsystem == 2)
        features["subsystem_console"] = float(optional.Subsystem == 3)
        features["is_dll"] = float(bool(file_header.Characteristics & 0x2000))

        stamp = int(file_header.TimeDateStamp)
        year = 1970 + (stamp // (365 * 24 * 3600))  # coarse, adequate for anomaly check
        features["timestamp_year"] = float(year)
        features["timestamp_anomaly"] = float(year < 1990 or year > 2026)
        evidence["notes"].append(f"PE TimeDateStamp roughly maps to year {year}")

        dll_chars = int(optional.DllCharacteristics)
        features["dep_disabled"] = float(not bool(dll_chars & 0x0100))
        features["aslr_disabled"] = float(not bool(dll_chars & 0x0040))
        features["no_seh"] = float(bool(dll_chars & 0x0400))
        features["high_entropy_va"] = float(bool(dll_chars & 0x0020))

        security_dir = optional.DATA_DIRECTORY[4]
        features["is_signed"] = float(security_dir.VirtualAddress != 0)

        sections = []
        entropies = []
        suspicious_names = 0
        unknown_names = 0
        wx = rwx = writable = executable = 0
        empty_raw = 0
        total_raw = total_virtual = 0
        ep = int(optional.AddressOfEntryPoint)
        ep_idx = -1

        for idx, section in enumerate(pe.sections):
            name_bytes = bytes(section.Name).rstrip(b"\x00")
            name = name_bytes.decode("latin-1", errors="replace")
            name_l = name.lower().strip()
            chars = int(section.Characteristics)
            raw_size = int(section.SizeOfRawData)
            vsize = int(section.Misc_VirtualSize)
            data = section.get_data()
            entropy = _entropy(data)
            entropies.append(entropy)
            total_raw += raw_size
            total_virtual += vsize

            is_w = bool(chars & 0x80000000)
            is_x = bool(chars & 0x20000000)
            is_r = bool(chars & 0x40000000)
            writable += int(is_w)
            executable += int(is_x)
            wx += int(is_w and is_x)
            rwx += int(is_r and is_w and is_x)
            if raw_size == 0 and vsize > 0:
                empty_raw += 1
            if any(token in name_l for token in SUSPICIOUS_SECTION_NAMES):
                suspicious_names += 1
            if name_l not in {n.lower() for n in COMMON_SECTION_NAMES}:
                unknown_names += 1
            if ep_idx < 0 and vsize and int(section.VirtualAddress) <= ep < int(section.VirtualAddress) + max(vsize, raw_size):
                ep_idx = idx

            sections.append({
                "name": name,
                "entropy": round(entropy, 3),
                "raw_size": raw_size,
                "virtual_size": vsize,
                "write": is_w,
                "execute": is_x,
                "read": is_r,
            })

        features["num_sections"] = float(len(sections))
        features["num_writable_sections"] = float(writable)
        features["num_executable_sections"] = float(executable)
        features["num_wx_sections"] = float(wx)
        features["num_rwx_sections"] = float(rwx)
        features["num_high_entropy_sections"] = float(sum(e > 7.0 for e in entropies))
        features["num_empty_raw_sections"] = float(empty_raw)
        features["num_suspicious_section_names"] = float(suspicious_names)
        features["num_unknown_section_names"] = float(unknown_names)
        features["max_section_entropy"] = max(entropies, default=0.0)
        features["mean_section_entropy"] = (sum(entropies) / len(entropies)) if entropies else 0.0
        features["std_section_entropy"] = (
            math.sqrt(sum((e - features["mean_section_entropy"]) ** 2 for e in entropies) / len(entropies))
            if entropies else 0.0
        )
        features["total_raw_size_log10"] = _log10p1(total_raw)
        features["total_virtual_size_log10"] = _log10p1(total_virtual)
        features["raw_virtual_ratio"] = total_raw / max(1, total_virtual)
        features["entrypoint_section_idx"] = float(max(ep_idx, 0))
        ep_is_code = False
        if ep_idx >= 0:
            ep_section = sections[ep_idx]
            ep_is_code = bool(ep_section["execute"])
        features["entrypoint_in_code"] = float(ep_is_code)

        overlay = pe.get_overlay()
        overlay_len = len(overlay) if overlay else 0
        features["overlay_ratio"] = overlay_len / max(1, len(raw))
        features["has_overlay"] = float(overlay_len > 0)

        # Imports
        dlls: set[str] = set()
        api_names: set[str] = set()
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                try:
                    dlls.add(entry.dll.decode("latin-1", errors="ignore").lower())
                except Exception:
                    pass
                for imp in entry.imports:
                    if imp.name:
                        api_names.add(bytes(imp.name).decode("latin-1", errors="ignore").lower())
        features["import_count_log10"] = _log10p1(len(api_names))
        features["import_dll_count"] = float(len(dlls))
        category_hits: dict[str, list[str]] = {}
        for category, apis in API_CATEGORIES.items():
            hits = sorted(name for name in api_names if name in apis)
            features[f"import_{category}"] = float(len(hits))
            if hits:
                category_hits[category] = hits

        # Exports / resources / misc directories
        exports = getattr(getattr(pe, "DIRECTORY_ENTRY_EXPORT", None), "symbols", [])
        features["export_count_log10"] = _log10p1(len(exports))
        features["has_exports"] = float(bool(exports))
        resource_count, resource_size = _count_resources(pe)
        features["resource_count_log10"] = _log10p1(resource_count)
        features["resource_size_ratio"] = resource_size / max(1, len(raw))
        features["has_resources"] = float(resource_count > 0)
        features["has_debug"] = float(hasattr(pe, "DIRECTORY_ENTRY_DEBUG"))
        features["has_tls"] = float(hasattr(pe, "DIRECTORY_ENTRY_TLS"))
        features["has_reloc"] = float(hasattr(pe, "DIRECTORY_ENTRY_BASERELOC"))

        string_counts = _string_counts(raw)
        for key, value in string_counts.items():
            features[f"str_{key}"] = value

        evidence["section_names"] = [s["name"] for s in sections]
        evidence["sections"] = sections
        evidence["imported_dlls"] = sorted(dlls)
        evidence["top_import_categories"] = [
            {"category": k, "count": len(v), "apis": v[:12]} for k, v in sorted(category_hits.items())
        ]
        evidence["string_indicators"] = {k: int(v) for k, v in string_counts.items()}
        evidence["imported_api_count"] = len(api_names)
        evidence["overlay_bytes"] = overlay_len
        evidence["resource_count"] = resource_count
    finally:
        pe.close()

    # Normalise any stray NaN/inf before handing to the model.
    for key in FEATURE_NAMES:
        value = features.get(key, 0.0)
        if not math.isfinite(float(value)):
            features[key] = 0.0
    return {"features": features, "evidence": evidence}


def vectorize(features: dict[str, float]) -> list[float]:
    """Convert a feature dict to the fixed numeric vector used by the model."""
    return [float(features.get(name, 0.0)) for name in FEATURE_NAMES]


def human_evidence(features: dict[str, float], top_n: int = 8) -> list[str]:
    """Produce short, human-readable statements backed by extracted values."""
    lines: list[str] = []
    if features.get("num_high_entropy_sections", 0) > 0:
        lines.append(f"{int(features['num_high_entropy_sections'])} section(s) have entropy > 7.0 (possible packing)")
    if features.get("num_rwx_sections", 0) > 0:
        lines.append(f"{int(features['num_rwx_sections'])} section(s) are readable/writable/executable")
    if features.get("num_suspicious_section_names", 0) > 0:
        lines.append(f"{int(features['num_suspicious_section_names'])} packer/crypter-like section name(s)")
    for category in ("inject", "antidebug", "network", "crypto", "persistence", "shell_exec", "dynamic_load"):
        value = int(features.get(f"import_{category}", 0))
        if value:
            lines.append(f"{value} import(s) in the {category} API category")
    if features.get("str_url", 0):
        lines.append(f"{int(features['str_url'])} embedded URL string(s)")
    if features.get("str_ip", 0):
        lines.append(f"{int(features['str_ip'])} embedded IP address(es)")
    if features.get("str_powershell", 0):
        lines.append(f"{int(features['str_powershell'])} PowerShell-related string indicator(s)")
    if features.get("timestamp_anomaly", 0):
        lines.append("implausible PE build timestamp")
    if features.get("aslr_disabled", 0):
        lines.append("ASLR/DYNAMIC_BASE flag not set")
    if features.get("dep_disabled", 0):
        lines.append("DEP/NX_COMPAT flag not set")
    if not lines:
        lines.append("no strong static malware indicators were observed")
    return lines[:top_n]
