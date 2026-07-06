from __future__ import annotations

import os
import json
import math
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from .png_codec import PngError, read_png
from .stego_engine import (
    PREFIX_MAGIC,
    PREFIX_SIZE,
    _bits_to_bytes,
    _bmp_pixel_offset,
    _detect_cover_type,
    _read_container_from_region,
    _unpack_container,
    _carrier_secret,
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
        return [scan_file(path, password, stego_key)]
    findings: list[ForensicFinding] = []
    candidates = [candidate for candidate in (path.rglob("*") if recursive else path.glob("*")) if candidate.is_file() and candidate.suffix.lower() in SUPPORTED_SUFFIXES]
    total = max(1, len(candidates))
    for index, candidate in enumerate(candidates, start=1):
        if cancel and cancel():
            break
        if candidate.is_file() and candidate.suffix.lower() in SUPPORTED_SUFFIXES:
            findings.append(scan_file(candidate, password, stego_key))
        if progress:
            progress(int(index * 100 / total), str(candidate))
    return findings


def scan_file(path: Path, password: str = "", stego_key: str = "") -> ForensicFinding:
    cover_type = _detect_cover_type(str(path))
    try:
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
        if cover_type in {"jpg", "flac"}:
            return ForensicFinding(str(path), cover_type, "unsupported", "low", "Format recognized, but deep scanning is not implemented.", 10)
        return ForensicFinding(str(path), "unknown", "skipped", "low", "Unsupported file type.", 0)
    except Exception as exc:
        return ForensicFinding(str(path), cover_type, "error", "low", str(exc), 5)


def _scan_region(path: Path, cover_type: str, data: bytes, start: int, stop: int, password: str, stego_key: str) -> ForensicFinding:
    sample = data[start:min(stop, start + 65536)]
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
    detail = f"ObscuraPrimus v2 prefix found; payload={payload_size} bytes; adaptive={adaptive}; spread={spread}; entropy={entropy:.3f}; lsb_one_ratio={ratio:.3f}."

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
