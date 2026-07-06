from __future__ import annotations

import csv
import hashlib
import html
import json
import os
import re
import shutil
import sqlite3
import stat
import struct
import subprocess
import tarfile
import time
import zlib
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from dataclasses import asdict, dataclass
from pathlib import Path

from .file_analysis import (
    FileAnalysis,
    analyze_file,
    analyze_path,
    carve_embedded_files,
    entropy,
    error_analysis,
    extract_iocs,
    extract_strings,
    hash_bytes,
    hex_preview,
)
from .runtime import portable_data_dir
from .plugins import run_matching_plugins


SCAN_PROFILES = {
    "quick": {"deep": False, "timeout": 10, "max_file_mb": 64},
    "deep": {"deep": True, "timeout": 30, "max_file_mb": 256},
    "stego-focused": {"deep": True, "timeout": 30, "max_file_mb": 256},
    "malware-triage": {"deep": True, "timeout": 45, "max_file_mb": 512},
}

SIGMA_PATTERN = re.compile(r"(?im)^\s*(title|id|logsource|detection|condition)\s*:")


@dataclass(frozen=True)
class YaraMatch:
    rule: str
    path: str
    offsets: list[int]
    strings: list[str]
    severity: str


def validate_yara_rules(rule_path: str | Path) -> dict:
    path = Path(rule_path)
    if not path.exists():
        return {"valid": False, "error": "Rule file does not exist.", "engine": ""}
    yara = shutil.which("yara") or shutil.which("yara64")
    if yara:
        probe = subprocess.run([yara, str(path), str(path)], text=True, capture_output=True, timeout=15)
        if probe.returncode in {0, 1}:
            return {"valid": True, "error": "", "engine": yara}
        return {"valid": False, "error": (probe.stderr or probe.stdout).strip(), "engine": yara}
    text = path.read_text(encoding="utf-8", errors="ignore")
    rules = re.findall(r"\brule\s+([A-Za-z_][A-Za-z0-9_]*)", text)
    return {"valid": bool(rules), "rules": rules, "error": "" if rules else "No YARA rule declarations found.", "engine": "fallback"}


def analyze_path_isolated(
    target: str | Path,
    recursive: bool = True,
    profile: str = "deep",
    yara_rules: str = "",
    progress=None,
) -> list[FileAnalysis]:
    settings = SCAN_PROFILES.get(profile, SCAN_PROFILES["deep"])
    root = Path(target)
    files = [root] if root.is_file() else [p for p in (root.rglob("*") if recursive else root.glob("*")) if p.is_file()]
    results: list[FileAnalysis] = []
    total = max(1, len(files))
    for index, file_path in enumerate(files, start=1):
        try:
            guard_file_size(file_path, int(settings["max_file_mb"]))
            executor = ThreadPoolExecutor(max_workers=1)
            try:
                future = executor.submit(analyze_file, file_path, bool(settings["deep"]), yara_rules)
                analysis = future.result(timeout=int(settings["timeout"]))
                plugin_results = run_matching_plugins(file_path, timeout=int(settings["timeout"]))
                if plugin_results:
                    analysis.metadata["plugin_results"] = plugin_results
                    for plugin_result in plugin_results:
                        for finding in plugin_result.get("findings", []):
                            analysis.suspicious.append(f"Plugin {plugin_result.get('plugin')}: {finding}")
                        analysis.risk_score = min(100, analysis.risk_score + int(plugin_result.get("risk_delta", 0) or 0))
                results.append(analysis)
            finally:
                executor.shutdown(wait=False, cancel_futures=True)
        except TimeoutError:
            results.append(error_analysis(file_path, TimeoutError(f"Analyzer timed out after {settings['timeout']} seconds.")))
        except Exception as exc:
            results.append(error_analysis(file_path, exc))
        if progress:
            progress(int(index * 100 / total), str(file_path))
    return results


def scan_yara_details(target: str | Path, rule_path: str | Path) -> list[YaraMatch]:
    validation = validate_yara_rules(rule_path)
    if not validation.get("valid"):
        return []
    yara = shutil.which("yara") or shutil.which("yara64")
    target_path = Path(target)
    if yara:
        args = [yara, "-s", str(rule_path), str(target_path)]
        result = subprocess.run(args, text=True, capture_output=True, timeout=60)
        return _parse_yara_output(result.stdout, str(target_path))
    rule_names = validation.get("rules", [])
    haystack = target_path.read_bytes() if target_path.is_file() else b""
    strings = extract_strings(haystack)
    matches = []
    for rule in rule_names:
        if rule.lower().encode() in haystack.lower():
            offset = haystack.lower().find(rule.lower().encode())
            matches.append(YaraMatch(rule, str(target_path), [offset], [rule], "medium"))
    return matches


def entropy_timeline(path: str | Path, block_size: int = 4096) -> list[dict]:
    data = Path(path).read_bytes()
    return [{"offset": offset, "entropy": entropy(data[offset : offset + block_size])} for offset in range(0, len(data), block_size)]


def byte_histogram(path: str | Path) -> list[int]:
    counts = [0] * 256
    with Path(path).open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            for byte in chunk:
                counts[byte] += 1
    return counts


def virtual_hex_page(path: str | Path, offset: int = 0, rows: int = 64) -> dict:
    length = max(1, rows) * 16
    text = hex_preview(path, max(0, offset), length)
    size = Path(path).stat().st_size
    return {"path": str(path), "offset": max(0, offset), "rows": rows, "size": size, "text": text}


def search_case(case_dir: str | Path, query: str) -> list[dict]:
    needle = query.lower()
    db = Path(case_dir) / "case.db"
    if not db.exists():
        return []
    con = sqlite3.connect(db)
    con.row_factory = sqlite3.Row
    try:
        rows = con.execute("select * from evidence").fetchall()
    finally:
        con.close()
    results = []
    for row in rows:
        data = dict(row)
        searchable = " ".join(str(value) for value in data.values()).lower()
        path = Path(data.get("path", ""))
        if needle in searchable or (path.exists() and needle in _safe_file_search_blob(path)):
            results.append(data)
    return results


def import_immutable_evidence(case_dir: str | Path, source: str | Path, tags: list[str] | None = None, notes: str = "") -> dict:
    from .case_db import add_evidence_record, init_case_db

    root = Path(case_dir)
    init_case_db(root)
    source_path = Path(source)
    evidence_dir = root / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    digest = _hash_file(source_path)
    target = evidence_dir / f"{digest[:16]}_{source_path.name}"
    if not target.exists():
        shutil.copy2(source_path, target)
    try:
        target.chmod(stat.S_IREAD)
    except OSError:
        pass
    add_evidence_record(root, str(target), digest, target.stat().st_size, tags or ["immutable"], notes)
    _append_chain_log(root, f"immutable-import source={source_path} copy={target} sha256={digest}")
    return {"source": str(source_path), "copy": str(target), "sha256": digest, "read_only": True}


def export_case_bundle(case_dir: str | Path, output_path: str | Path, sign: bool = False) -> dict:
    root = Path(case_dir)
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(output, "w:gz") as archive:
        archive.add(root, arcname=root.name)
    digest = _hash_file(output)
    signature = ""
    if sign:
        from .file_analysis import sign_report

        signature = sign_report(output)
    return {"bundle": str(output), "sha256": digest, "signature": signature}


def import_case_bundle(bundle_path: str | Path, output_dir: str | Path) -> dict:
    bundle = Path(bundle_path)
    destination = Path(output_dir)
    destination.mkdir(parents=True, exist_ok=True)
    digest = _hash_file(bundle)
    with tarfile.open(bundle, "r:gz") as archive:
        _safe_extract_tar(archive, destination)
    return {"bundle": str(bundle), "output_dir": str(destination), "sha256": digest}


def inspect_raw_image(path: str | Path, sample_mb: int = 16) -> dict:
    file_path = Path(path)
    size = file_path.stat().st_size
    sample = file_path.read_bytes()[: sample_mb * 1024 * 1024]
    return {
        "path": str(file_path),
        "size": size,
        "sector_count_512": size // 512,
        "sample_hashes": hash_bytes(sample),
        "sample_iocs": extract_iocs(sample),
        "partitions_hint": _mbr_partitions(sample),
        "note": "RAW/DD image sampling is native; E01 requires an external ewfexport/libewf workflow.",
    }


def inspect_browser_artifact(path: str | Path) -> dict:
    file_path = Path(path)
    lower = file_path.name.lower()
    if lower in {"history", "places.sqlite", "downloads.sqlite"} or file_path.suffix.lower() in {".sqlite", ".db"}:
        return _inspect_browser_sqlite(file_path)
    return {"supported": False, "reason": "Not a recognized browser SQLite artifact."}


def inspect_windows_artifact(path: str | Path) -> dict:
    file_path = Path(path)
    suffix = file_path.suffix.lower()
    data = file_path.read_bytes()[:4096]
    if suffix == ".pf":
        strings = _utf16_strings(Path(path).read_bytes()[:128 * 1024])
        return {"type": "prefetch", "signature": data[:4].hex(), "version": int.from_bytes(data[:4], "little", signed=False), "executable_hint": strings[:5], "path_hints": [s for s in strings if "\\" in s][:25]}
    if suffix == ".evtx":
        return {"type": "event-log", "valid": data.startswith(b"ElfFile\x00"), "note": "Use external EVTX parser for full record decoding."}
    if suffix in {".automaticdestinations-ms", ".customdestinations-ms"}:
        strings = extract_strings(Path(path).read_bytes()[:1024 * 1024])
        return {"type": "jump-list", "ole_compound": data.startswith(bytes.fromhex("d0cf11e0a1b11ae1")), "strings": strings[:50]}
    if file_path.name.lower() in {"amcache.hve", "system", "software", "ntuser.dat", "usrclass.dat"}:
        strings = _utf16_strings(Path(path).read_bytes()[:1024 * 1024])
        artifact_type = "amcache" if file_path.name.lower() == "amcache.hve" else "registry-hive"
        return {"type": artifact_type, "signature": data[:4].decode("ascii", errors="ignore"), "valid": data.startswith(b"regf"), "strings": strings[:100]}
    if file_path.name.lower() == "srum.dat":
        return {"type": "srum", "sqlite": inspect_browser_artifact(file_path) if data.startswith(b"SQLite format 3\x00") else {}, "note": "SRUM is usually an ESE database; external esent parser recommended."}
    return {"type": "unknown", "supported": False}


def normalize_timeline(results: list[FileAnalysis]) -> list[dict]:
    events = []
    for item in results:
        for kind, timestamp in item.timestamps.items():
            if timestamp:
                events.append({"timestamp": timestamp, "kind": kind, "path": item.path, "risk": item.risk_score})
    return sorted(events, key=lambda event: event["timestamp"])


def export_timeline(events: list[dict], output_path: str | Path) -> None:
    path = Path(output_path)
    if path.suffix.lower() == ".json":
        path.write_text(json.dumps(events, indent=2), encoding="utf-8")
        return
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["timestamp", "kind", "path", "risk"])
        writer.writeheader()
        writer.writerows(events)


def validate_sigma_rule(path: str | Path) -> dict:
    text = Path(path).read_text(encoding="utf-8", errors="ignore")
    keys = sorted(set(match.group(1).lower() for match in SIGMA_PATTERN.finditer(text)))
    required = {"title", "detection", "condition"}
    return {"valid": required.issubset(keys), "keys": keys, "error": "" if required.issubset(keys) else "Missing Sigma title/detection/condition keys."}


def fuzzy_hash(path: str | Path) -> dict:
    file_path = Path(path)
    data = file_path.read_bytes()
    result = {"sha256": hashlib.sha256(data).hexdigest(), "blake2b_16": hashlib.blake2b(data, digest_size=16).hexdigest()}
    for tool in ("tlsh", "ssdeep"):
        exe = shutil.which(tool)
        if not exe:
            continue
        run = subprocess.run([exe, str(file_path)], text=True, capture_output=True, timeout=30)
        result[tool] = (run.stdout or run.stderr).strip()
    return result


def anomaly_score(path: str | Path) -> dict:
    data = Path(path).read_bytes()
    flags = []
    score = 0
    total_entropy = entropy(data)
    if total_entropy > 7.7:
        flags.append("Very high entropy; compression or encryption likely.")
        score += 25
    if len(data) > 128 and data[-128:].count(0) < 4 and entropy(data[-4096:]) > 7.5:
        flags.append("High-entropy tail/overlay.")
        score += 20
    if data.startswith(b"MZ"):
        pe_flags = pe_unpacking_hints(data)
        flags.extend(pe_flags)
        score += min(40, 10 * len(pe_flags))
    return {"score": min(100, score), "entropy": total_entropy, "flags": flags}


def authenticode_status(path: str | Path) -> dict:
    signtool = shutil.which("signtool")
    if signtool:
        run = subprocess.run([signtool, "verify", "/pa", "/v", str(path)], text=True, capture_output=True, timeout=45)
        return {"available": True, "valid": run.returncode == 0, "output": (run.stdout or run.stderr)[-4000:]}
    powershell = shutil.which("powershell") or shutil.which("pwsh")
    if powershell:
        escaped_path = str(path).replace("'", "''")
        command = f"Get-AuthenticodeSignature -LiteralPath '{escaped_path}' | ConvertTo-Json -Compress"
        run = subprocess.run([powershell, "-NoProfile", "-Command", command], text=True, capture_output=True, timeout=45)
        if run.returncode == 0 and run.stdout.strip():
            try:
                payload = json.loads(run.stdout)
            except json.JSONDecodeError:
                payload = {"raw": run.stdout.strip()}
            return {"available": True, "valid": payload.get("Status") == 0 or payload.get("Status") == "Valid", "details": payload}
    return {"available": False, "valid": False, "error": "signtool or PowerShell Authenticode support not available."}


def pe_unpacking_hints(data: bytes) -> list[str]:
    text = data.decode("latin1", errors="ignore").lower()
    flags = []
    for marker in ("upx0", "upx1", "aspack", "themida", "vmp0", "mpress"):
        if marker in text:
            flags.append(f"Packed/obfuscated PE marker found: {marker}")
    if b"\x00" * 512 in data[:4096]:
        flags.append("Large zeroed region near PE header.")
    return flags


def deobfuscate_script(path: str | Path) -> dict:
    text = Path(path).read_text(encoding="utf-8", errors="ignore")
    findings = []
    decoded = text
    for pattern in (r"(?i)frombase64string\(['\"]?([A-Za-z0-9+/=]{20,})", r"(?i)atob\(['\"]([A-Za-z0-9+/=]{20,})"):
        for match in re.finditer(pattern, text):
            blob = match.group(1)
            findings.append({"type": "base64-reference", "sample": blob[:80], "decoded": _decode_base64_preview(blob)})
    for label, func in (("gzip", _try_gzip_preview), ("zlib", _try_zlib_preview)):
        preview = func(text.encode("utf-8", errors="ignore"))
        if preview:
            findings.append({"type": f"{label}-decoded-preview", "decoded": preview})
    xor_hits = _xor_ascii_previews(Path(path).read_bytes()[:4096])
    findings.extend({"type": "xor-preview", **hit} for hit in xor_hits[:5])
    replacements = {"`": "", "^": "", "+": ""}
    for old, new in replacements.items():
        decoded = decoded.replace(old, new)
    return {"findings": findings, "normalized_preview": decoded[:4000]}


def carving_preview(path: str | Path, output_dir: str | Path | None = None) -> list[dict]:
    target = Path(path)
    data = target.read_bytes()
    signatures = [
        (b"\x89PNG\r\n\x1a\n", b"IEND\xaeB`\x82", "png"),
        (b"\xff\xd8\xff", b"\xff\xd9", "jpg"),
        (b"PK\x03\x04", b"PK\x05\x06", "zip"),
        (b"%PDF-", b"%%EOF", "pdf"),
        (b"MZ", b"PE\x00\x00", "pe"),
    ]
    previews = []
    for start_sig, end_sig, ext in signatures:
        start = 0
        while True:
            offset = data.find(start_sig, start)
            if offset == -1:
                break
            end = data.find(end_sig, offset + len(start_sig))
            size = (end + len(end_sig) - offset) if end != -1 else 0
            candidate = data[offset : offset + min(size or 4096, 1024 * 1024)]
            previews.append(
                {
                    "offset": offset,
                    "type": ext,
                    "size": size,
                    "confidence": "high" if size else "medium",
                    "sha256_sample": hashlib.sha256(candidate).hexdigest(),
                }
            )
            start = offset + 1
    if output_dir:
        carved = carve_embedded_files(target, output_dir)
        by_offset = {(item["offset"], item["type"]): item for item in carved}
        for preview in previews:
            preview.update(by_offset.get((preview["offset"], preview["type"]), {}))
    return previews


def workspace_dashboard(case_dir: str | Path, analysis_results: list[FileAnalysis] | None = None) -> dict:
    results = analysis_results or []
    iocs: dict[str, int] = {}
    for item in results:
        for kind, values in item.iocs.items():
            iocs[kind] = iocs.get(kind, 0) + len(values)
    newest = sorted((asdict(item) for item in results), key=lambda item: item.get("timestamps", {}).get("modified", 0), reverse=True)[:10]
    return {
        "newest_evidence": newest,
        "unresolved_high_risk": [asdict(item) for item in results if item.risk_score >= 70],
        "top_iocs": iocs,
        "timeline": normalize_timeline(results),
    }


def explain_finding(analysis: FileAnalysis) -> str:
    parts = [analysis.explanation]
    for flag in analysis.suspicious[:8]:
        parts.append(f"- {flag}")
    if analysis.signature_mismatch:
        parts.append("- Magic bytes do not match the extension, which often indicates disguise or accidental mislabeling.")
    if analysis.entropy > 7.7:
        parts.append("- Entropy is very high, so compressed, encrypted, packed, or random-looking content is likely.")
    return "\n".join(part for part in parts if part)


def write_report_template(results: list[FileAnalysis], output_path: str | Path, template: str = "executive") -> None:
    path = Path(output_path)
    dashboard = workspace_dashboard(path.parent, results)
    chart = _embedded_chart_html(results)
    if template == "technical":
        body = "<h1>Technical Appendix</h1>" + "".join(_analysis_html(item) for item in results)
    elif template == "chain-of-custody":
        body = "<h1>Chain Of Custody</h1>" + _timeline_html(normalize_timeline(results))
    elif template == "stego-only":
        body = "<h1>Stego Findings</h1>" + "".join(_analysis_html(item) for item in results if item.media or "stego" in item.explanation.lower())
    elif template == "malware-triage":
        body = "<h1>Malware Triage</h1>" + "".join(_analysis_html(item) for item in results if item.pe or item.script or item.risk_score >= 35)
    else:
        body = f"<h1>Executive Summary</h1><p>Files: {len(results)} High risk: {len(dashboard['unresolved_high_risk'])}</p>"
    body += chart
    path.write_text(f"<!doctype html><meta charset='utf-8'><title>ObscuraPrimus Report</title>{body}", encoding="utf-8")


def plugin_sdk_manifest(name: str, version: str = "1.0.0") -> dict:
    return {
        "schema": "obscuraprimus.analyzer-plugin.v1",
        "name": name,
        "version": version,
        "entry_point": f"{name}.py",
        "capabilities": ["analyze_file"],
        "timeouts": {"analyze_file_seconds": 30},
    }


def write_example_plugin(directory: str | Path, name: str = "example_plugin") -> dict:
    root = Path(directory)
    root.mkdir(parents=True, exist_ok=True)
    manifest = plugin_sdk_manifest(name)
    (root / "plugin.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    (root / f"{name}.py").write_text(
        "def analyze_file(path):\n"
        "    return {'path': str(path), 'findings': [], 'risk_delta': 0}\n",
        encoding="utf-8",
    )
    return manifest


def guard_file_size(path: str | Path, max_mb: int) -> None:
    size = Path(path).stat().st_size
    if size > max_mb * 1024 * 1024:
        raise ValueError(f"File exceeds analyzer memory guardrail: {size} bytes > {max_mb} MiB.")


def onboarding_sample_case(target_dir: str | Path | None = None) -> Path:
    root = Path(target_dir) if target_dir else portable_data_dir() / "sample-case"
    root.mkdir(parents=True, exist_ok=True)
    sample = root / "evidence" / "hello-url.txt"
    sample.parent.mkdir(parents=True, exist_ok=True)
    sample.write_text("Visit https://example.com and contact analyst@example.com\n", encoding="utf-8")
    import_immutable_evidence(root, sample, ["sample"], "First-run sample evidence")
    return root


def _parse_yara_output(output: str, path: str) -> list[YaraMatch]:
    matches: dict[str, YaraMatch] = {}
    for line in output.splitlines():
        if not line.strip():
            continue
        parts = line.split()
        rule = parts[0]
        current = matches.setdefault(rule, YaraMatch(rule, path, [], [], "medium"))
        offset_match = re.search(r"0x([0-9a-fA-F]+):", line)
        if offset_match:
            current.offsets.append(int(offset_match.group(1), 16))
        if "$" in line:
            current.strings.append(line.strip())
    return list(matches.values())


def _safe_file_search_blob(path: Path) -> str:
    try:
        data = path.read_bytes()[:1024 * 1024]
    except OSError:
        return ""
    return " ".join(extract_strings(data)[:200]).lower() + " " + json.dumps(extract_iocs(data)).lower()


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _append_chain_log(case_dir: Path, message: str) -> None:
    log = case_dir / "chain_of_custody.log"
    with log.open("a", encoding="utf-8") as handle:
        handle.write(f"{time.time():.3f} {message}\n")


def _mbr_partitions(data: bytes) -> list[dict]:
    if len(data) < 512 or data[510:512] != b"\x55\xaa":
        return []
    partitions = []
    for index in range(4):
        entry = data[446 + index * 16 : 446 + (index + 1) * 16]
        ptype = entry[4]
        if not ptype:
            continue
        start = struct.unpack("<I", entry[8:12])[0]
        sectors = struct.unpack("<I", entry[12:16])[0]
        partitions.append({"index": index + 1, "type": ptype, "start_lba": start, "sectors": sectors})
    return partitions


def _inspect_browser_sqlite(path: Path) -> dict:
    con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        tables = [row[0] for row in con.execute("select name from sqlite_master where type='table'").fetchall()]
        counts = {}
        for table in tables[:50]:
            try:
                counts[table] = con.execute(f"select count(*) from [{table}]").fetchone()[0]
            except sqlite3.Error:
                counts[table] = -1
    finally:
        con.close()
    browser_hint = "firefox" if "moz_places" in tables else "chromium" if "urls" in tables or "downloads" in tables else "sqlite"
    samples = {}
    sample_queries = {
        "urls": "select url, title, last_visit_time from urls limit 25",
        "moz_places": "select url, title, last_visit_date from moz_places limit 25",
        "downloads": "select * from downloads limit 10",
        "moz_cookies": "select host, name, path, expiry from moz_cookies limit 25",
        "cookies": "select host_key, name, path, expires_utc from cookies limit 25",
    }
    con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    try:
        for table, query in sample_queries.items():
            if table in tables:
                try:
                    samples[table] = [dict(row) for row in con.execute(query).fetchall()]
                except sqlite3.Error:
                    samples[table] = []
    finally:
        con.close()
    return {"supported": True, "browser_hint": browser_hint, "tables": tables, "counts": counts, "samples": samples}


def _decode_base64_preview(blob: str) -> str:
    import base64

    try:
        raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=False)
        return raw[:1000].decode("utf-8", errors="replace")
    except Exception:
        return ""


def _try_gzip_preview(data: bytes) -> str:
    import gzip

    start = data.find(b"\x1f\x8b")
    if start == -1:
        return ""
    try:
        return gzip.decompress(data[start:])[:1000].decode("utf-8", errors="replace")
    except Exception:
        return ""


def _try_zlib_preview(data: bytes) -> str:
    for marker in (b"\x78\x9c", b"\x78\xda", b"\x78\x01"):
        start = data.find(marker)
        if start == -1:
            continue
        try:
            return zlib.decompress(data[start:])[:1000].decode("utf-8", errors="replace")
        except Exception:
            continue
    return ""


def _xor_ascii_previews(data: bytes) -> list[dict]:
    hits = []
    for key in range(1, 256):
        decoded = bytes(byte ^ key for byte in data)
        printable = sum(32 <= byte <= 126 or byte in (9, 10, 13) for byte in decoded)
        if data and printable / len(data) > 0.85 and b" " in decoded:
            hits.append({"key": key, "preview": decoded[:300].decode("ascii", errors="ignore")})
    return hits


def _safe_extract_tar(archive: tarfile.TarFile, destination: Path) -> None:
    root = destination.resolve()
    for member in archive.getmembers():
        target = (destination / member.name).resolve()
        if root not in target.parents and target != root:
            raise ValueError("Unsafe path in case bundle.")
    archive.extractall(destination)


def _embedded_chart_html(results: list[FileAnalysis]) -> str:
    bars = "".join(
        f"<div title='{html.escape(Path(item.path).name)}' style='height:12px;width:{max(1,item.risk_score)}%;background:#2f6fed;margin:3px 0'></div>"
        for item in sorted(results, key=lambda result: result.risk_score, reverse=True)[:25]
    )
    return f"<h2>Risk Chart</h2><div>{bars}</div>"


def _utf16_strings(data: bytes) -> list[str]:
    return [match.group(0).decode("utf-16le", errors="ignore").rstrip("\x00") for match in re.finditer(rb"(?:[\x20-\x7e]\x00){4,}", data)]


def _analysis_html(item: FileAnalysis) -> str:
    return (
        "<section>"
        f"<h2>{html.escape(Path(item.path).name)}</h2>"
        f"<p>Risk: {item.risk_score} Type: {html.escape(item.magic_type)} SHA-256: {item.hashes.get('sha256','')}</p>"
        f"<pre>{html.escape(explain_finding(item))}</pre>"
        "</section>"
    )


def _timeline_html(events: list[dict]) -> str:
    rows = "".join(
        f"<tr><td>{event['timestamp']}</td><td>{html.escape(event['kind'])}</td><td>{html.escape(event['path'])}</td><td>{event['risk']}</td></tr>"
        for event in events
    )
    return f"<table><tr><th>Timestamp</th><th>Kind</th><th>Path</th><th>Risk</th></tr>{rows}</table>"
