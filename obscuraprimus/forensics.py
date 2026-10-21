from __future__ import annotations

import json
import math
import os
import subprocess
import sys
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from .file_analysis import _iter_scan_files
from .flac_codec import FlacCodecError, inspect_flac
from .png_codec import PngError, read_png
from .stego_engine import (
    MAX_COVER_BYTES,
    PREFIX_MAGIC,
    PREFIX_SIZE,
    _bits_to_bytes,
    _bmp_pixel_offset,
    _carrier_secret,
    _detect_cover_type,
    _read_container_from_region,
    _unpack_container,
)

SUPPORTED_SUFFIXES = {".bmp", ".png", ".wav", ".jpg", ".jpeg", ".flac"}


@dataclass(frozen=True)
class ForensicFinding:
    path: str
    cover_type: str
    status: str
    confidence: str
    details: str
    risk_score: int = 0
    entropy: float = 0.0
    lsb_one_ratio: float = 0.0


def scan_path(
    target: str,
    password: str = "",
    recursive: bool = True,
    stego_key: str = "",
    progress: Callable[[int, str], None] | None = None,
    cancel: Callable[[], bool] | None = None,
) -> list[ForensicFinding]:
    path = Path(target)
    if path.is_file():
        return [_scan_file_limited(path, password, stego_key)]
    findings: list[ForensicFinding] = []
    total = 0
    for candidate in _iter_scan_files(path, recursive):
        if cancel and cancel():
            break
        if candidate.suffix.lower() not in SUPPORTED_SUFFIXES:
            continue
        total += 1
        findings.append(_scan_file_limited(candidate, password, stego_key))
        if progress:
            progress(min(99, total), str(candidate))
    if progress:
        progress(100, str(path))
    return findings


def scan_file(path: Path, password: str = "", stego_key: str = "") -> ForensicFinding:
    cover_type = _detect_cover_type(str(path))
    try:
        if path.stat().st_size > MAX_COVER_BYTES:
            return ForensicFinding(
                str(path),
                cover_type,
                "skipped",
                "low",
                f"File exceeds forensic cover size limit ({MAX_COVER_BYTES:,} bytes).",
                0,
            )
        if cover_type == "bmp":
            data = path.read_bytes()
            start = _bmp_pixel_offset(data)
            return _scan_region(path, cover_type, data, start, len(data), password, stego_key)
        if cover_type == "wav":
            import wave

            with wave.open(str(path), "rb") as reader:
                frames = reader.readframes(reader.getnframes())
            return _scan_region(path, cover_type, frames, 0, len(frames), password, stego_key)
        if cover_type == "png":
            image = read_png(path)
            return _scan_region(path, cover_type, image.pixels, 0, len(image.pixels), password, stego_key)
        if cover_type == "flac":
            return _scan_flac(path, password)
        if cover_type == "jpg":
            return ForensicFinding(
                str(path),
                cover_type,
                "unsupported",
                "low",
                "JPEG-DCT is experimental and requires OBSCURAPRIMUS_JPEG_DCT_BACKEND; deep forensic scan is not implemented.",
                10,
            )
        return ForensicFinding(str(path), "unknown", "skipped", "low", "Unsupported file type.", 0)
    except (PngError, FlacCodecError, Exception) as exc:
        return ForensicFinding(str(path), cover_type, "error", "low", str(exc), 5)


def maybe_run_forensic_worker(argv: list[str] | None = None) -> bool:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] != "--obp-forensic-worker":
        return False
    if len(args) != 5:
        raise SystemExit("Usage: --obp-forensic-worker <path> <password> <stego-key> <output.json>")
    _, path, password, stego_key, output_path = args
    result = scan_file(Path(path), password, stego_key)
    Path(output_path).write_text(json.dumps(result.__dict__), encoding="utf-8")
    return True


def _scan_file_limited(path: Path, password: str, stego_key: str) -> ForensicFinding:
    fd, output_name = tempfile.mkstemp(prefix="obp-forensic-", suffix=".json")
    os.close(fd)
    output_path = Path(output_name)
    if getattr(sys, "frozen", False):
        command = [sys.executable, "--obp-forensic-worker", str(path), password, stego_key, str(output_path)]
    else:
        runner = (
            "import json,sys; from pathlib import Path; from obscuraprimus.forensics import scan_file; "
            "print(json.dumps(scan_file(Path(sys.argv[1]),sys.argv[2],sys.argv[3]).__dict__))"
        )
        command = [sys.executable, "-c", runner, str(path), password, stego_key]
    environment = os.environ.copy()
    if not getattr(sys, "frozen", False):
        root = str(Path(__file__).resolve().parents[1])
        pythonpath = environment.get("PYTHONPATH", "")
        environment["PYTHONPATH"] = root if not pythonpath else root + os.pathsep + pythonpath
    if getattr(sys, "frozen", False):
        command.extend([str(output_path)])
    try:
        completed = subprocess.run(command, text=True, capture_output=True, timeout=45, check=False, env=environment)
    except subprocess.TimeoutExpired:
        output_path.unlink(missing_ok=True)
        return ForensicFinding(str(path), _detect_cover_type(str(path)), "skipped", "low", "Forensic scan timed out after 45 seconds.", 0)
    try:
        if completed.returncode:
            detail = (completed.stderr or completed.stdout or "Forensic worker failed.").strip()
            return ForensicFinding(str(path), _detect_cover_type(str(path)), "error", "low", detail, 5)
        if getattr(sys, "frozen", False):
            result = json.loads(output_path.read_text(encoding="utf-8"))
        else:
            result = json.loads(completed.stdout)
        return ForensicFinding(**result)
    except (OSError, json.JSONDecodeError, TypeError) as exc:
        return ForensicFinding(str(path), _detect_cover_type(str(path)), "error", "low", str(exc), 5)
    finally:
        output_path.unlink(missing_ok=True)


def _scan_flac(path: Path, password: str) -> ForensicFinding:
    info = inspect_flac(path)
    entropy = 0.0
    ratio = 0.0
    if not info.get("valid_flac"):
        return ForensicFinding(str(path), "flac", "error", "low", "Invalid FLAC stream.", 5)
    if not info.get("obscuraprimus_payload"):
        return ForensicFinding(
            str(path),
            "flac",
            "clean",
            "medium",
            "No ObscuraPrimus FLAC APPLICATION metadata block was found.",
            0,
            entropy,
            ratio,
        )
    detail = "ObscuraPrimus FLAC APPLICATION metadata block found (discoverable container, not LSB stego)."
    score = 90
    if password:
        try:
            from .flac_codec import extract_container
            from .stego_engine import _unpack_container

            container = extract_container(path)
            metadata, _ = _unpack_container(container)
            filename = metadata.get("filename") or "(encrypted metadata)"
            detail += f" Container metadata parsed; filename={filename}; encrypted={metadata.get('encrypted')}."
            return ForensicFinding(str(path), "flac", "suspect", "high", detail, 100, entropy, ratio)
        except Exception as exc:
            detail += f" APPLICATION block present, but payload parsing failed with supplied password: {exc}"
            return ForensicFinding(str(path), "flac", "suspect", "medium", detail, score, entropy, ratio)
    return ForensicFinding(str(path), "flac", "suspect", "high", detail, score, entropy, ratio)


def _scan_region(path: Path, cover_type: str, data: bytes, start: int, stop: int, password: str, stego_key: str) -> ForensicFinding:
    sample = data[start : min(stop, start + 65536)]
    entropy = _entropy(sample)
    ratio = _lsb_one_ratio(sample)
    if stop - start < PREFIX_SIZE * 8:
        return ForensicFinding(str(path), cover_type, "clean", "low", "Too small for an ObscuraPrimus v2 prefix.", 0, entropy, ratio)
    prefix_indexes = range(start, start + PREFIX_SIZE * 8)
    prefix = _bits_to_bytes((data[i] & 1 for i in prefix_indexes), PREFIX_SIZE)
    if not prefix.startswith(PREFIX_MAGIC):
        score = _statistical_score(entropy, ratio)
        if score >= 20:
            details = "No ObscuraPrimus v2 prefix was found, but generic LSB statistics look unusually uniform."
            return ForensicFinding(str(path), cover_type, "anomaly", "low", details, score, entropy, ratio)
        return ForensicFinding(str(path), cover_type, "clean", "medium", "No ObscuraPrimus v2 prefix was found.", score, entropy, ratio)

    flags = prefix[4]
    payload_size = int.from_bytes(prefix[5:13], "big")
    adaptive = bool(flags & 1)
    spread = bool(flags & 2)
    score = 95 if payload_size > 0 else 75
    detail = (
        f"ObscuraPrimus v2 prefix found; payload={payload_size} bytes; adaptive={adaptive}; "
        f"spread={spread}; entropy={entropy:.3f}; lsb_one_ratio={ratio:.3f}."
    )

    if password:
        try:
            container = _read_container_from_region(data, start, stop, _carrier_secret(password, stego_key), None)
            metadata, _ = _unpack_container(container)
            filename = metadata.get("filename") or "(encrypted metadata)"
            detail += f" Container metadata parsed; filename={filename}; encrypted={metadata.get('encrypted')}."
            return ForensicFinding(str(path), cover_type, "suspect", "high", detail, 100, entropy, ratio)
        except Exception as exc:
            detail += f" Prefix is valid, but payload parsing failed with supplied password: {exc}"
            return ForensicFinding(str(path), cover_type, "suspect", "medium", detail, score, entropy, ratio)

    return ForensicFinding(str(path), cover_type, "suspect", "high", detail, score, entropy, ratio)


def write_report(findings: list[ForensicFinding], output_path: str) -> None:
    if output_path.lower().endswith(".json"):
        write_json_report(findings, output_path)
        return
    lines = ["path,cover_type,status,confidence,risk_score,entropy,lsb_one_ratio,details"]
    for finding in findings:
        lines.append(
            ",".join(
                [
                    _csv(finding.path),
                    _csv(finding.cover_type),
                    _csv(finding.status),
                    _csv(finding.confidence),
                    str(finding.risk_score),
                    f"{finding.entropy:.6f}",
                    f"{finding.lsb_one_ratio:.6f}",
                    _csv(finding.details),
                ]
            )
        )
    Path(output_path).write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_json_report(findings: list[ForensicFinding], output_path: str) -> None:
    payload = [finding.__dict__ for finding in findings]
    Path(output_path).write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def _csv(value: str) -> str:
    escaped = value.replace('"', '""')
    return f'"{escaped}"'


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    total = len(data)
    return -sum((count / total) * math.log2(count / total) for count in counts if count)


def _lsb_one_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    return sum(byte & 1 for byte in data) / len(data)


def _statistical_score(entropy: float, ratio: float) -> int:
    score = 0
    if entropy > 7.8:
        score += 10
    if 0.48 <= ratio <= 0.52:
        score += 10
    return score
