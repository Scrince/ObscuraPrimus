from __future__ import annotations

import csv
import gzip
import hashlib
import html
import json
import math
import os
import re
import shutil
import sqlite3
import struct
import subprocess
import tarfile
import time
import urllib.error
import urllib.request
import zipfile
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .flac_codec import FlacCodecError, inspect_flac


MAGIC_SIGNATURES: tuple[tuple[bytes, str], ...] = (
    (b"\x89PNG\r\n\x1a\n", "PNG image"),
    (b"\xff\xd8\xff", "JPEG image"),
    (b"BM", "BMP image"),
    (b"RIFF", "RIFF/WAV or AVI"),
    (b"fLaC", "FLAC audio"),
    (b"PK\x03\x04", "ZIP/Office container"),
    (b"%PDF-", "PDF document"),
    (b"MZ", "Windows PE executable"),
    (b"7z\xbc\xaf\x27\x1c", "7z archive"),
    (b"\x1f\x8b", "gzip archive"),
)

EXTENSION_HINTS = {
    ".png": "PNG image",
    ".jpg": "JPEG image",
    ".jpeg": "JPEG image",
    ".bmp": "BMP image",
    ".wav": "RIFF/WAV or AVI",
    ".flac": "FLAC audio",
    ".zip": "ZIP/Office container",
    ".docx": "ZIP/Office container",
    ".xlsx": "ZIP/Office container",
    ".pptx": "ZIP/Office container",
    ".pdf": "PDF document",
    ".exe": "Windows PE executable",
    ".dll": "Windows PE executable",
    ".7z": "7z archive",
    ".gz": "gzip archive",
}

SCRIPT_EXTENSIONS = {".ps1", ".bat", ".cmd", ".js", ".vbs", ".py"}
CHUNK_SIZE = 1024 * 1024
ANALYSIS_FULL_READ_LIMIT = 64 * CHUNK_SIZE
CARVE_SIGNATURES: tuple[tuple[bytes, bytes, str], ...] = (
    (b"\x89PNG\r\n\x1a\n", b"IEND\xaeB`\x82", "png"),
    (b"\xff\xd8\xff", b"\xff\xd9", "jpg"),
    (b"PK\x03\x04", b"PK\x05\x06", "zip"),
    (b"%PDF-", b"%%EOF", "pdf"),
    (b"MZ", b"PE\x00\x00", "pe"),
)
IOC_PATTERNS = {
    "urls": re.compile(rb"https?://[^\s'\"<>]+", re.I),
    "emails": re.compile(rb"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", re.I),
    "ips": re.compile(rb"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"),
    "domains": re.compile(rb"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|ru|cn|info|biz)\b", re.I),
    "wallets": re.compile(rb"\b(?:bc1[ac-hj-np-z02-9]{25,90}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|0x[a-fA-F0-9]{40})\b"),
}


@dataclass
class FileAnalysis:
    path: str
    size: int
    extension: str
    magic_type: str
    extension_type: str
    signature_mismatch: bool
    hashes: dict[str, str]
    entropy: float
    entropy_map: list[dict]
    timestamps: dict[str, float]
    strings: list[str]
    iocs: dict[str, list[str]]
    metadata: dict
    container: dict
    media: dict
    pe: dict
    script: dict
    ads: list[str]
    duplicate_of: str = ""
    suspicious: list[str] = field(default_factory=list)
    risk_score: int = 0
    explanation: str = ""
    notes: str = ""
    tags: list[str] = field(default_factory=list)


def analyze_file(path: str | Path, deep: bool = True, yara_rules: str = "") -> FileAnalysis:
    file_path = Path(path)
    stat = file_path.stat()
    data = _read_analysis_bytes(file_path, stat.st_size)
    sampled = stat.st_size > len(data)
    magic_type = identify_magic(data)
    extension_type = EXTENSION_HINTS.get(file_path.suffix.lower(), "unknown")
    mismatch = bool(extension_type != "unknown" and magic_type != "unknown" and extension_type != magic_type)
    hashes = hash_file(file_path)
    entropy_map = entropy_blocks(data) if deep else []
    strings = extract_strings(data) if deep else []
    iocs = extract_iocs(data) if deep else {}
    metadata = extract_metadata(file_path, data)
    container = inspect_container(file_path, data)
    media = inspect_media(file_path, data)
    pe = inspect_pe(data) if magic_type == "Windows PE executable" else {}
    if file_path.suffix.lower() == ".msi":
        metadata["msi"] = inspect_msi(file_path, data)
    if file_path.suffix.lower() == ".lnk":
        metadata["lnk"] = inspect_lnk(data)
    if file_path.suffix.lower() in {".sqlite", ".sqlite3", ".db"}:
        metadata["sqlite"] = inspect_sqlite(file_path)
    script = inspect_script(file_path, data) if file_path.suffix.lower() in SCRIPT_EXTENSIONS else {}
    ads = detect_ads(file_path)
    suspicious = suspicious_path_flags(file_path)
    if sampled:
        suspicious.append(f"Large file sampled for deep parsing; first {len(data):,} of {stat.st_size:,} bytes inspected.")
    if mismatch:
        suspicious.append(f"Extension suggests {extension_type}, but magic bytes indicate {magic_type}.")
    if yara_rules:
        yara = run_yara(file_path, yara_rules)
        if yara:
            suspicious.append(f"YARA matches: {', '.join(yara)}")
            metadata["yara_matches"] = yara
    clamav = run_clamav(file_path)
    if clamav:
        suspicious.append(f"ClamAV: {clamav}")
        metadata["clamav"] = clamav
    analysis = FileAnalysis(
        path=str(file_path),
        size=stat.st_size,
        extension=file_path.suffix.lower(),
        magic_type=magic_type,
        extension_type=extension_type,
        signature_mismatch=mismatch,
        hashes=hashes,
        entropy=entropy_file(file_path),
        entropy_map=entropy_map,
        timestamps={"created": stat.st_ctime, "modified": stat.st_mtime, "accessed": stat.st_atime},
        strings=strings[:500],
        iocs=iocs,
        metadata=metadata,
        container=container,
        media=media,
        pe=pe,
        script=script,
        ads=ads,
        suspicious=suspicious,
    )
    analysis.risk_score = score_analysis(analysis)
    analysis.explanation = explain_analysis(analysis)
    return analysis


def analyze_path(
    target: str | Path,
    recursive: bool = True,
    profile: str = "deep",
    yara_rules: str = "",
    progress=None,
    cancel=None,
) -> list[FileAnalysis]:
    path = Path(target)
    deep = profile != "quick"
    files = [path] if path.is_file() else [p for p in (path.rglob("*") if recursive else path.glob("*")) if p.is_file()]
    results: list[FileAnalysis] = []
    seen_hashes: dict[str, str] = {}
    total = max(1, len(files))
    for index, file_path in enumerate(files, start=1):
        if cancel and cancel():
            break
        try:
            analysis = analyze_file(file_path, deep=deep, yara_rules=yara_rules)
            digest = analysis.hashes["sha256"]
            if digest in seen_hashes:
                analysis.duplicate_of = seen_hashes[digest]
                analysis.suspicious.append(f"Duplicate of {seen_hashes[digest]}")
            else:
                seen_hashes[digest] = analysis.path
            results.append(analysis)
        except Exception as exc:
            results.append(error_analysis(file_path, exc))
        if progress:
            progress(int(index * 100 / total), str(file_path))
    return results


def _read_analysis_bytes(path: Path, size: int) -> bytes:
    with path.open("rb") as handle:
        return handle.read(min(size, ANALYSIS_FULL_READ_LIMIT))


def build_case_dashboard(results: list[FileAnalysis]) -> dict:
    duplicate_groups: dict[str, list[str]] = {}
    ioc_counts: dict[str, int] = {}
    timeline = []
    for item in results:
        duplicate_groups.setdefault(item.hashes.get("sha256", ""), []).append(item.path)
        for kind, values in item.iocs.items():
            ioc_counts[kind] = ioc_counts.get(kind, 0) + len(values)
        if item.timestamps:
            timeline.append({"path": item.path, **item.timestamps})
    duplicates = {digest: paths for digest, paths in duplicate_groups.items() if digest and len(paths) > 1}
    return {
        "file_count": len(results),
        "high_risk": sum(1 for item in results if item.risk_score >= 70),
        "medium_risk": sum(1 for item in results if 35 <= item.risk_score < 70),
        "top_risks": [asdict(item) for item in sorted(results, key=lambda item: item.risk_score, reverse=True)[:10]],
        "duplicates": duplicates,
        "ioc_counts": ioc_counts,
        "timeline": sorted(timeline, key=lambda item: item.get("modified", 0)),
    }


def identify_magic(data: bytes) -> str:
    for magic, name in MAGIC_SIGNATURES:
        if data.startswith(magic):
            if magic == b"RIFF" and data[8:12] == b"WAVE":
                return "RIFF/WAV or AVI"
            return name
    return "unknown"


def hash_bytes(data: bytes) -> dict[str, str]:
    return {
        "md5": hashlib.md5(data, usedforsecurity=False).hexdigest(),
        "sha1": hashlib.sha1(data, usedforsecurity=False).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "sha512": hashlib.sha512(data).hexdigest(),
        "blake2b": hashlib.blake2b(data).hexdigest(),
    }


def hash_file(path: str | Path) -> dict[str, str]:
    md5 = hashlib.md5(usedforsecurity=False)
    sha1 = hashlib.sha1(usedforsecurity=False)
    sha256 = hashlib.sha256()
    sha512 = hashlib.sha512()
    blake2b = hashlib.blake2b()
    with Path(path).open("rb") as handle:
        while True:
            chunk = handle.read(CHUNK_SIZE)
            if not chunk:
                break
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
            sha512.update(chunk)
            blake2b.update(chunk)
    return {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
        "sha512": sha512.hexdigest(),
        "blake2b": blake2b.hexdigest(),
    }


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    total = len(data)
    return -sum((count / total) * math.log2(count / total) for count in counts if count)


def entropy_file(path: str | Path) -> float:
    counts = [0] * 256
    total = 0
    with Path(path).open("rb") as handle:
        while True:
            chunk = handle.read(CHUNK_SIZE)
            if not chunk:
                break
            total += len(chunk)
            for byte in chunk:
                counts[byte] += 1
    if not total:
        return 0.0
    return -sum((count / total) * math.log2(count / total) for count in counts if count)


def entropy_blocks(data: bytes, block_size: int = 4096) -> list[dict]:
    return [
        {"offset": offset, "size": len(data[offset : offset + block_size]), "entropy": entropy(data[offset : offset + block_size])}
        for offset in range(0, len(data), block_size)
    ]


def entropy_chart_data(path: str | Path, block_size: int = 4096) -> list[tuple[int, float]]:
    return [(entry["offset"], entry["entropy"]) for entry in entropy_blocks(_read_analysis_bytes(Path(path), Path(path).stat().st_size), block_size)]


def hex_preview(path: str | Path, offset: int = 0, length: int = 512) -> str:
    with Path(path).open("rb") as handle:
        handle.seek(max(0, offset))
        data = handle.read(length)
    lines = []
    for row_offset in range(0, len(data), 16):
        chunk = data[row_offset : row_offset + 16]
        hex_part = " ".join(f"{byte:02x}" for byte in chunk)
        ascii_part = "".join(chr(byte) if 32 <= byte <= 126 else "." for byte in chunk)
        lines.append(f"{offset + row_offset:08x}  {hex_part:<47}  {ascii_part}")
    return "\n".join(lines)


def search_hex(path: str | Path, needle: bytes) -> list[int]:
    if not needle:
        return []
    offsets = []
    overlap = max(0, len(needle) - 1)
    previous = b""
    absolute = 0
    with Path(path).open("rb") as handle:
        while True:
            chunk = handle.read(CHUNK_SIZE)
            if not chunk:
                return offsets
            haystack = previous + chunk
            search_start = 0
            base = absolute - len(previous)
            while True:
                found = haystack.find(needle, search_start)
                if found == -1:
                    break
                real_offset = base + found
                if real_offset >= 0 and (not offsets or offsets[-1] != real_offset):
                    offsets.append(real_offset)
                search_start = found + 1
            previous = haystack[-overlap:] if overlap else b""
            absolute += len(chunk)


def compare_files(left: str | Path, right: str | Path, max_diffs: int = 1000) -> dict:
    diffs = []
    offset = 0
    with Path(left).open("rb") as left_handle, Path(right).open("rb") as right_handle:
        while len(diffs) < max_diffs:
            left_chunk = left_handle.read(CHUNK_SIZE)
            right_chunk = right_handle.read(CHUNK_SIZE)
            if not left_chunk or not right_chunk:
                break
            for index, (left_byte, right_byte) in enumerate(zip(left_chunk, right_chunk)):
                if left_byte != right_byte:
                    diffs.append({"offset": offset + index, "left": left_byte, "right": right_byte})
                    if len(diffs) >= max_diffs:
                        break
            offset += min(len(left_chunk), len(right_chunk))
    left_size = Path(left).stat().st_size
    right_size = Path(right).stat().st_size
    return {
        "left": str(left),
        "right": str(right),
        "left_hashes": hash_file(left),
        "right_hashes": hash_file(right),
        "left_entropy": entropy_file(left),
        "right_entropy": entropy_file(right),
        "size_delta": left_size - right_size,
        "diff_count_sample": len(diffs),
        "diffs": diffs,
    }


def extract_strings(data: bytes, min_len: int = 4) -> list[str]:
    found = set()
    for match in re.finditer(rb"[\x20-\x7e]{%d,}" % min_len, data):
        found.add(match.group(0).decode("ascii", errors="ignore"))
    for match in re.finditer((rb"(?:[\x20-\x7e]\x00){%d,}" % min_len), data):
        found.add(match.group(0).decode("utf-16le", errors="ignore").rstrip("\x00"))
    return sorted(found)[:1000]


def extract_iocs(data: bytes) -> dict[str, list[str]]:
    output = {}
    for name, pattern in IOC_PATTERNS.items():
        values = sorted({m.group(0).decode("ascii", errors="ignore") for m in pattern.finditer(data)})
        if values:
            output[name] = values[:100]
    return output


def extract_metadata(path: Path, data: bytes) -> dict:
    suffix = path.suffix.lower()
    if data.startswith(b"\x89PNG"):
        return png_chunks(data)
    if data.startswith(b"BM") and len(data) >= 54:
        return bmp_metadata(data)
    if data.startswith(b"RIFF") and data[8:12] == b"WAVE":
        return wav_metadata(data)
    if data.startswith(b"fLaC"):
        try:
            return {"flac": inspect_flac(path)}
        except FlacCodecError as exc:
            return {"flac_error": str(exc)}
    if data.startswith(b"\xff\xd8"):
        return jpeg_metadata(data)
    if data.startswith(b"%PDF-"):
        return pdf_metadata(data)
    if suffix in {".docx", ".xlsx", ".pptx"} or data.startswith(b"PK\x03\x04"):
        return office_metadata(path)
    return {}


def inspect_container(path: Path, data: bytes) -> dict:
    suffix = path.suffix.lower()
    try:
        if zipfile.is_zipfile(path):
            with zipfile.ZipFile(path) as archive:
                entries = [{"name": info.filename, "size": info.file_size, "compressed": info.compress_size} for info in archive.infolist()[:500]]
                embedded = [info.filename for info in archive.infolist() if re.search(r"\.(exe|dll|js|vbs|ps1|bin|ole|pdf)$", info.filename, re.I)]
            return {"type": "zip", "entries": entries, "entry_count": len(entries), "embedded_candidates": embedded[:100]}
        if suffix in {".tar", ".tgz"} and tarfile.is_tarfile(path):
            with tarfile.open(path) as archive:
                members = archive.getmembers()
            return {"type": "tar", "entries": [{"name": m.name, "size": m.size} for m in members[:500]], "entry_count": len(members)}
        if data.startswith(b"\x1f\x8b"):
            with gzip.open(path, "rb") as handle:
                sample = handle.read(128)
            return {"type": "gzip", "sample_size": len(sample)}
        if data.startswith(b"7z\xbc\xaf\x27\x1c"):
            return {"type": "7z", "note": "7z signature detected; external 7z parser not bundled."}
    except Exception as exc:
        return {"error": str(exc)}
    return {}


def inspect_media(path: Path, data: bytes) -> dict:
    metadata = extract_metadata(path, data)
    if data.startswith(b"\x89PNG"):
        return {"png_chunks": metadata.get("chunks", []), "lsb_histogram": lsb_histogram(data)}
    if data.startswith(b"RIFF") and data[8:12] == b"WAVE":
        return {"riff_chunks": riff_chunks(data), "wav": metadata, "waveform": wav_waveform(data), "spectrogram": wav_spectrogram_summary(data)}
    if data.startswith(b"fLaC"):
        return {"flac": metadata.get("flac", {})}
    if data.startswith(b"\xff\xd8"):
        return {"jpeg": metadata}
    return {}


def png_chunks(data: bytes) -> dict:
    chunks = []
    offset = 8
    width = height = None
    while offset + 8 <= len(data):
        length = int.from_bytes(data[offset : offset + 4], "big")
        kind = data[offset + 4 : offset + 8].decode("latin1")
        chunk_data = data[offset + 8 : offset + 8 + length]
        chunks.append({"type": kind, "offset": offset, "length": length})
        if kind == "IHDR" and len(chunk_data) >= 8:
            width = int.from_bytes(chunk_data[:4], "big")
            height = int.from_bytes(chunk_data[4:8], "big")
        offset += 12 + length
        if kind == "IEND":
            break
    return {"width": width, "height": height, "chunks": chunks}


def bmp_metadata(data: bytes) -> dict:
    return {
        "file_size": int.from_bytes(data[2:6], "little"),
        "pixel_offset": int.from_bytes(data[10:14], "little"),
        "width": int.from_bytes(data[18:22], "little", signed=True),
        "height": int.from_bytes(data[22:26], "little", signed=True),
        "bits_per_pixel": int.from_bytes(data[28:30], "little"),
    }


def wav_metadata(data: bytes) -> dict:
    chunks = riff_chunks(data)
    fmt = next((c for c in chunks if c["id"] == "fmt "), None)
    info = {"riff_chunks": chunks}
    if fmt and fmt["offset"] + 24 <= len(data):
        offset = fmt["offset"] + 8
        info.update(
            {
                "audio_format": int.from_bytes(data[offset : offset + 2], "little"),
                "channels": int.from_bytes(data[offset + 2 : offset + 4], "little"),
                "sample_rate": int.from_bytes(data[offset + 4 : offset + 8], "little"),
                "bits_per_sample": int.from_bytes(data[offset + 14 : offset + 16], "little"),
            }
        )
    return info


def riff_chunks(data: bytes) -> list[dict]:
    chunks = []
    offset = 12
    while offset + 8 <= len(data):
        chunk_id = data[offset : offset + 4].decode("latin1", errors="replace")
        size = int.from_bytes(data[offset + 4 : offset + 8], "little")
        chunks.append({"id": chunk_id, "offset": offset, "size": size})
        offset += 8 + size + (size % 2)
    return chunks


def jpeg_metadata(data: bytes) -> dict:
    offset = 2
    segments = []
    quant_tables = 0
    exif = False
    while offset + 4 <= len(data):
        if data[offset] != 0xFF:
            offset += 1
            continue
        marker = data[offset + 1]
        if marker in {0xD9, 0xDA}:
            segments.append({"marker": f"FF{marker:02X}", "offset": offset})
            break
        length = int.from_bytes(data[offset + 2 : offset + 4], "big")
        payload = data[offset + 4 : offset + 2 + length]
        if marker == 0xDB:
            quant_tables += 1
        if marker == 0xE1 and payload.startswith(b"Exif\x00\x00"):
            exif = True
        segments.append({"marker": f"FF{marker:02X}", "offset": offset, "length": length})
        offset += 2 + length
    exif_data = parse_exif_from_jpeg(data)
    return {
        "segments": segments[:200],
        "quantization_tables": quant_tables,
        "has_exif": exif,
        "gps_possible": b"GPS" in data,
        "exif": exif_data,
    }


def pdf_metadata(data: bytes) -> dict:
    header = data[:32].splitlines()[0].decode("latin1", errors="ignore") if data else ""
    objects = pdf_objects(data)
    return {
        "header": header,
        "objects": len(objects),
        "object_index": objects[:200],
        "streams": data.count(b"stream"),
        "javascript": bool(re.search(rb"/(?:JS|JavaScript)\b", data)),
        "embedded_files": bool(re.search(rb"/EmbeddedFile\b|/Filespec\b", data)),
        "launch_actions": bool(re.search(rb"/Launch\b|/OpenAction\b", data)),
    }


def office_metadata(path: Path) -> dict:
    if not zipfile.is_zipfile(path):
        return {}
    relationships = []
    external_links = []
    embedded = []
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        for name in names:
            lower = name.lower()
            if lower.endswith(".rels"):
                try:
                    text = archive.read(name).decode("utf-8", errors="ignore")
                    relationships.append({"name": name, "external": "TargetMode=\"External\"" in text})
                    external_links.extend(re.findall(r'Target="([^"]+)"[^>]+TargetMode="External"', text))
                except Exception:
                    pass
            if "/embeddings/" in lower or lower.endswith("vbaproject.bin"):
                embedded.append(name)
    return {
        "office_container": any(name.startswith("word/") or name.startswith("xl/") or name.startswith("ppt/") for name in names),
        "macro_possible": any(name.lower().endswith("vbaproject.bin") for name in names),
        "relationships": relationships[:100],
        "external_links": external_links[:100],
        "embedded_objects": embedded[:100],
        "entries": names[:100],
    }


def inspect_pe(data: bytes) -> dict:
    if len(data) < 0x40 or not data.startswith(b"MZ"):
        return {}
    pe_offset = int.from_bytes(data[0x3C:0x40], "little")
    if pe_offset + 24 > len(data) or data[pe_offset : pe_offset + 4] != b"PE\x00\x00":
        return {"valid_pe": False}
    machine = int.from_bytes(data[pe_offset + 4 : pe_offset + 6], "little")
    sections = int.from_bytes(data[pe_offset + 6 : pe_offset + 8], "little")
    timestamp = int.from_bytes(data[pe_offset + 8 : pe_offset + 12], "little")
    optional_size = int.from_bytes(data[pe_offset + 20 : pe_offset + 22], "little")
    section_offset = pe_offset + 24 + optional_size
    section_list = []
    for index in range(sections):
        start = section_offset + index * 40
        if start + 40 > len(data):
            break
        name = data[start : start + 8].rstrip(b"\x00").decode("ascii", errors="replace")
        raw_size = int.from_bytes(data[start + 16 : start + 20], "little")
        raw_ptr = int.from_bytes(data[start + 20 : start + 24], "little")
        section_list.append({"name": name, "raw_size": raw_size, "entropy": entropy(data[raw_ptr : raw_ptr + raw_size])})
    optional_offset = pe_offset + 24
    magic = int.from_bytes(data[optional_offset : optional_offset + 2], "little") if optional_offset + 2 <= len(data) else 0
    data_dir_offset = optional_offset + (112 if magic == 0x20B else 96)
    directories = {}
    for index, name in enumerate(("export", "import", "resource", "exception", "certificate")):
        entry_offset = data_dir_offset + index * 8
        if entry_offset + 8 <= len(data):
            directories[name] = {
                "rva": int.from_bytes(data[entry_offset : entry_offset + 4], "little"),
                "size": int.from_bytes(data[entry_offset + 4 : entry_offset + 8], "little"),
            }
    return {
        "valid_pe": True,
        "machine": hex(machine),
        "sections": section_list,
        "section_count": sections,
        "timestamp": timestamp,
        "directories": directories,
        "authenticode_possible": directories.get("certificate", {}).get("size", 0) > 0,
        "imports_present": directories.get("import", {}).get("size", 0) > 0,
        "exports_present": directories.get("export", {}).get("size", 0) > 0,
        "resources_present": directories.get("resource", {}).get("size", 0) > 0,
    }


def inspect_script(path: Path, data: bytes) -> dict:
    text = data[:200000].decode("utf-8", errors="ignore")
    indicators = []
    for token in ("Invoke-Expression", "FromBase64String", "powershell -enc", "WScript.Shell", "eval(", "exec("):
        if token.lower() in text.lower():
            indicators.append(token)
    return {"extension": path.suffix.lower(), "indicators": indicators, "line_count": text.count("\n") + 1}


def detect_ads(path: Path) -> list[str]:
    if os.name != "nt":
        return []
    try:
        result = subprocess.run(["cmd", "/c", "dir", "/r", str(path)], capture_output=True, text=True, timeout=5)
    except Exception:
        return []
    streams = []
    for line in result.stdout.splitlines():
        if ":$DATA" in line and path.name in line:
            streams.append(line.strip())
    return streams


def suspicious_path_flags(path: Path) -> list[str]:
    flags = []
    name = path.name
    lower = name.lower()
    if re.search(r"\.(jpg|png|pdf|docx|txt)\.(exe|scr|bat|cmd|ps1|js|vbs)$", lower):
        flags.append("Double-extension filename.")
    if any(char in name for char in ("\u202e", "\u200f", "\u200e")):
        flags.append("Filename contains bidirectional control characters.")
    if lower.startswith("~") or lower.endswith(".tmp"):
        flags.append("Temporary-looking filename.")
    return flags


def run_yara(path: Path, rules: str) -> list[str]:
    executable = shutil.which("yara64") or shutil.which("yara")
    if not executable or not rules:
        return []
    try:
        result = subprocess.run([executable, rules, str(path)], capture_output=True, text=True, timeout=20)
    except Exception:
        return []
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def run_clamav(path: Path) -> str:
    executable = shutil.which("clamscan")
    if not executable:
        return ""
    try:
        result = subprocess.run([executable, "--no-summary", str(path)], capture_output=True, text=True, timeout=30)
    except Exception:
        return ""
    return result.stdout.strip()


def virustotal_lookup(sha256: str, api_key: str) -> dict:
    if not api_key:
        return {}
    request = urllib.request.Request(
        f"https://www.virustotal.com/api/v3/files/{sha256}",
        headers={"x-apikey": api_key},
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
        return {}


def load_hash_set(path: str | Path) -> set[str]:
    values = set()
    for line in Path(path).read_text(encoding="utf-8", errors="ignore").splitlines():
        token = line.strip().split()[0] if line.strip() else ""
        if re.fullmatch(r"[a-fA-F0-9]{32,128}", token):
            values.add(token.lower())
    return values


def classify_hashes(results: list[FileAnalysis], known_good: set[str] | None = None, known_bad: set[str] | None = None) -> None:
    known_good = known_good or set()
    known_bad = known_bad or set()
    for item in results:
        digest = item.hashes.get("sha256", "").lower()
        if digest in known_bad:
            item.suspicious.append("Known-bad hash match.")
            item.risk_score = max(item.risk_score, 95)
            item.explanation = explain_analysis(item)
        elif digest in known_good:
            item.suspicious.append("Known-good hash match.")


def carve_embedded_files(path: str | Path, output_dir: str | Path, max_items: int = 50) -> list[dict]:
    data = Path(path).read_bytes()
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    carved = []
    for start_magic, end_magic, extension in CARVE_SIGNATURES:
        start = 0
        while len(carved) < max_items:
            found = data.find(start_magic, start)
            if found == -1:
                break
            end = data.find(end_magic, found + len(start_magic))
            if end == -1:
                start = found + 1
                continue
            end += len(end_magic)
            blob = data[found:end]
            name = f"carved_{len(carved):03d}_{found:x}.{extension}"
            (output / name).write_bytes(blob)
            carved.append({"offset": found, "size": len(blob), "type": extension, "path": str(output / name)})
            start = end
    return carved


def pdf_objects(data: bytes) -> list[dict]:
    objects = []
    for match in re.finditer(rb"(\d+)\s+(\d+)\s+obj", data):
        objects.append({"object": int(match.group(1)), "generation": int(match.group(2)), "offset": match.start()})
    return objects


def parse_exif_from_jpeg(data: bytes) -> dict:
    offset = 2
    while offset + 4 <= len(data):
        if data[offset] != 0xFF:
            offset += 1
            continue
        marker = data[offset + 1]
        if marker in {0xDA, 0xD9}:
            break
        length = int.from_bytes(data[offset + 2 : offset + 4], "big")
        payload = data[offset + 4 : offset + 2 + length]
        if marker == 0xE1 and payload.startswith(b"Exif\x00\x00"):
            return parse_tiff_exif(payload[6:])
        offset += 2 + length
    return {}


def parse_tiff_exif(data: bytes) -> dict:
    if len(data) < 8:
        return {}
    endian = "little" if data[:2] == b"II" else "big" if data[:2] == b"MM" else ""
    if not endian:
        return {}
    first_ifd = int.from_bytes(data[4:8], endian)
    tags = parse_ifd(data, first_ifd, endian)
    gps_offset = tags.get("GPSInfoIFDPointer")
    gps = parse_ifd(data, gps_offset, endian) if isinstance(gps_offset, int) else {}
    return {"tags": tags, "gps": gps, "gps_decimal": gps_decimal(gps)}


EXIF_TAGS = {0x010F: "Make", 0x0110: "Model", 0x0132: "DateTime", 0x8769: "ExifIFDPointer", 0x8825: "GPSInfoIFDPointer"}
GPS_TAGS = {1: "GPSLatitudeRef", 2: "GPSLatitude", 3: "GPSLongitudeRef", 4: "GPSLongitude"}


def parse_ifd(data: bytes, offset: int, endian: str) -> dict:
    if not offset or offset + 2 > len(data):
        return {}
    count = int.from_bytes(data[offset : offset + 2], endian)
    tags = {}
    for index in range(count):
        entry = offset + 2 + index * 12
        if entry + 12 > len(data):
            break
        tag = int.from_bytes(data[entry : entry + 2], endian)
        typ = int.from_bytes(data[entry + 2 : entry + 4], endian)
        num = int.from_bytes(data[entry + 4 : entry + 8], endian)
        value_raw = data[entry + 8 : entry + 12]
        name = EXIF_TAGS.get(tag) or GPS_TAGS.get(tag) or hex(tag)
        tags[name] = exif_value(data, typ, num, value_raw, endian)
    return tags


def exif_value(data: bytes, typ: int, count: int, raw: bytes, endian: str):
    unit = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8}.get(typ, 1)
    total = unit * count
    payload = raw if total <= 4 else data[int.from_bytes(raw, endian) : int.from_bytes(raw, endian) + total]
    if typ == 2:
        return payload.rstrip(b"\x00").decode("latin1", errors="replace")
    if typ == 3:
        return [int.from_bytes(payload[i : i + 2], endian) for i in range(0, min(len(payload), total), 2)]
    if typ == 4:
        values = [int.from_bytes(payload[i : i + 4], endian) for i in range(0, min(len(payload), total), 4)]
        return values[0] if len(values) == 1 else values
    if typ == 5:
        values = []
        for i in range(0, min(len(payload), total), 8):
            den = int.from_bytes(payload[i + 4 : i + 8], endian) or 1
            values.append(int.from_bytes(payload[i : i + 4], endian) / den)
        return values
    return payload.hex()


def gps_decimal(gps: dict) -> dict:
    try:
        lat = gps["GPSLatitude"]
        lon = gps["GPSLongitude"]
        lat_value = lat[0] + lat[1] / 60 + lat[2] / 3600
        lon_value = lon[0] + lon[1] / 60 + lon[2] / 3600
        if gps.get("GPSLatitudeRef", "N").upper().startswith("S"):
            lat_value *= -1
        if gps.get("GPSLongitudeRef", "E").upper().startswith("W"):
            lon_value *= -1
        return {"latitude": lat_value, "longitude": lon_value}
    except Exception:
        return {}


def strip_jpeg_exif(input_path: str | Path, output_path: str | Path) -> None:
    data = Path(input_path).read_bytes()
    if not data.startswith(b"\xff\xd8"):
        Path(output_path).write_bytes(data)
        return
    output = bytearray(data[:2])
    offset = 2
    while offset + 4 <= len(data):
        if data[offset] != 0xFF:
            output.extend(data[offset:])
            break
        marker = data[offset + 1]
        if marker in {0xDA, 0xD9}:
            output.extend(data[offset:])
            break
        length = int.from_bytes(data[offset + 2 : offset + 4], "big")
        payload = data[offset + 4 : offset + 2 + length]
        if not (marker == 0xE1 and payload.startswith(b"Exif\x00\x00")):
            output.extend(data[offset : offset + 2 + length])
        offset += 2 + length
    Path(output_path).write_bytes(output)


def inspect_msi(path: Path, data: bytes) -> dict:
    return {
        "compound_file_signature": data.startswith(bytes.fromhex("D0CF11E0A1B11AE1")),
        "note": "MSI compound document detected; full table parsing requires an MSI/OLE backend.",
    }


def inspect_lnk(data: bytes) -> dict:
    clsid = bytes.fromhex("0114020000000000C000000000000046")
    valid = len(data) >= 76 and data[:4] == b"\x4c\x00\x00\x00" and data[4:20] == clsid
    flags = int.from_bytes(data[20:24], "little") if len(data) >= 24 else 0
    attrs = int.from_bytes(data[24:28], "little") if len(data) >= 28 else 0
    return {"valid_lnk": valid, "link_flags": hex(flags), "file_attributes": hex(attrs)}


def inspect_sqlite(path: Path) -> dict:
    con = None
    try:
        con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        rows = con.execute("select name, type from sqlite_master order by type, name").fetchall()
        return {"tables": [{"name": name, "type": typ} for name, typ in rows]}
    except Exception as exc:
        return {"error": str(exc)}
    finally:
        if con is not None:
            con.close()


def bit_plane_data(path: str | Path, plane: int = 0, max_bytes: int = 65536) -> dict:
    data = Path(path).read_bytes()[:max_bytes]
    return {"plane": plane, "bits": [(byte >> plane) & 1 for byte in data], "sample_size": len(data)}


def lsb_histogram(data: bytes) -> dict:
    if not data:
        return {"zero": 0, "one": 0}
    ones = sum(byte & 1 for byte in data)
    return {"zero": len(data) - ones, "one": ones, "one_ratio": ones / len(data)}


def wav_waveform(data: bytes, buckets: int = 256) -> list[dict]:
    chunks = riff_chunks(data)
    data_chunk = next((chunk for chunk in chunks if chunk["id"] == "data"), None)
    fmt = wav_metadata(data)
    if not data_chunk:
        return []
    start = data_chunk["offset"] + 8
    payload = data[start : start + data_chunk["size"]]
    sample_width = max(1, int(fmt.get("bits_per_sample", 16)) // 8)
    samples = []
    for i in range(0, len(payload) - sample_width + 1, sample_width):
        if sample_width == 1:
            value = payload[i] - 128
        elif sample_width == 2:
            value = int.from_bytes(payload[i : i + 2], "little", signed=True)
        else:
            value = int.from_bytes(payload[i : i + sample_width], "little", signed=True)
        samples.append(value)
    if not samples:
        return []
    step = max(1, len(samples) // buckets)
    return [{"bucket": idx // step, "min": min(samples[idx : idx + step]), "max": max(samples[idx : idx + step])} for idx in range(0, len(samples), step)][:buckets]


def wav_spectrogram_summary(data: bytes) -> list[dict]:
    waveform = wav_waveform(data, 64)
    return [{"bucket": item["bucket"], "amplitude": max(abs(item["min"]), abs(item["max"]))} for item in waveform]


def score_analysis(analysis: FileAnalysis) -> int:
    score = 0
    score += 30 if analysis.signature_mismatch else 0
    score += min(20, len(analysis.suspicious) * 10)
    score += 15 if analysis.entropy > 7.7 and analysis.size > 1024 else 0
    score += 15 if analysis.iocs else 0
    score += 20 if analysis.script.get("indicators") else 0
    score += 20 if analysis.metadata.get("macro_possible") else 0
    score += 10 if analysis.ads else 0
    score += 15 if analysis.pe.get("valid_pe") and analysis.extension not in {".exe", ".dll", ".sys"} else 0
    return min(100, score)


def explain_analysis(analysis: FileAnalysis) -> str:
    if analysis.risk_score >= 70:
        level = "High risk"
    elif analysis.risk_score >= 35:
        level = "Medium risk"
    elif analysis.risk_score > 0:
        level = "Low risk"
    else:
        level = "No obvious risk"
    reasons = []
    if analysis.signature_mismatch:
        reasons.append("file extension does not match magic bytes")
    if analysis.entropy > 7.7:
        reasons.append("high entropy")
    if analysis.iocs:
        reasons.append("IOCs found")
    if analysis.script.get("indicators"):
        reasons.append("script indicators found")
    if analysis.duplicate_of:
        reasons.append("duplicate file")
    if analysis.suspicious:
        reasons.extend(analysis.suspicious[:3])
    return f"{level}: " + (("; ".join(reasons)) if reasons else "no notable indicators found")


def error_analysis(path: Path, exc: Exception) -> FileAnalysis:
    return FileAnalysis(
        path=str(path),
        size=0,
        extension=path.suffix.lower(),
        magic_type="error",
        extension_type=EXTENSION_HINTS.get(path.suffix.lower(), "unknown"),
        signature_mismatch=False,
        hashes={},
        entropy=0,
        entropy_map=[],
        timestamps={},
        strings=[],
        iocs={},
        metadata={},
        container={},
        media={},
        pe={},
        script={},
        ads=[],
        suspicious=[str(exc)],
        risk_score=5,
        explanation=f"Analysis failed: {exc}",
    )


def write_analysis_report(results: list[FileAnalysis], output_path: str) -> None:
    suffix = Path(output_path).suffix.lower()
    if suffix == ".json":
        Path(output_path).write_text(json.dumps([asdict(item) for item in results], indent=2, sort_keys=True), encoding="utf-8")
    elif suffix == ".html":
        write_html_report(results, output_path)
    else:
        write_csv_report(results, output_path)


def sign_report(report_path: str | Path, gpg_exe: str = "", gpg_home: str = "") -> Path | None:
    from .signing import ensure_release_key, make_config, sign_file

    config = make_config(gpg_exe, gpg_home)
    if not config:
        return None
    ensure_release_key(config)
    return sign_file(report_path, config)


def write_csv_report(results: list[FileAnalysis], output_path: str) -> None:
    with Path(output_path).open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["path", "risk_score", "magic_type", "extension_type", "size", "sha256", "explanation"])
        for item in results:
            writer.writerow([item.path, item.risk_score, item.magic_type, item.extension_type, item.size, item.hashes.get("sha256", ""), item.explanation])


def write_html_report(results: list[FileAnalysis], output_path: str) -> None:
    rows = []
    for item in sorted(results, key=lambda result: result.risk_score, reverse=True):
        rows.append(
            "<tr>"
            f"<td>{html.escape(str(item.risk_score))}</td>"
            f"<td>{html.escape(item.path)}</td>"
            f"<td>{html.escape(item.magic_type)}</td>"
            f"<td>{html.escape(str(item.size))}</td>"
            f"<td>{html.escape(item.explanation)}</td>"
            "</tr>"
        )
    doc = (
        "<!doctype html><html><head><meta charset='utf-8'><title>ObscuraPrimus Analysis Report</title>"
        "<style>body{font-family:Segoe UI,Arial,sans-serif;margin:24px}table{border-collapse:collapse;width:100%}"
        "td,th{border:1px solid #ccc;padding:6px;text-align:left}th{background:#eee}</style></head><body>"
        f"<h1>ObscuraPrimus Analysis Report</h1><p>Files analyzed: {len(results)}</p>"
        "<table><thead><tr><th>Risk</th><th>Path</th><th>Type</th><th>Size</th><th>Explanation</th></tr></thead><tbody>"
        + "\n".join(rows)
        + "</tbody></table></body></html>"
    )
    Path(output_path).write_text(doc, encoding="utf-8")


def create_case(case_dir: str | Path, name: str = "case") -> Path:
    root = Path(case_dir)
    root.mkdir(parents=True, exist_ok=True)
    for child in ("evidence", "reports", "notes"):
        (root / child).mkdir(exist_ok=True)
    manifest = root / "manifest.json"
    if not manifest.exists():
        manifest.write_text(json.dumps({"name": name, "created": time.time(), "evidence": []}, indent=2), encoding="utf-8")
    append_audit(root, f"case-created {name}")
    return root


def add_evidence(case_dir: str | Path, file_path: str | Path, tags: list[str] | None = None, notes: str = "") -> dict:
    root = create_case(case_dir)
    analysis = analyze_file(file_path, deep=False)
    entry = {"path": str(file_path), "sha256": analysis.hashes["sha256"], "size": analysis.size, "tags": tags or [], "notes": notes, "added": time.time()}
    manifest_path = root / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["evidence"].append(entry)
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    append_audit(root, f"evidence-added {file_path} {analysis.hashes['sha256']}")
    try:
        from .case_db import add_evidence_record

        add_evidence_record(root, str(file_path), analysis.hashes["sha256"], analysis.size, tags or [], notes)
    except Exception:
        pass
    return entry


def append_audit(case_dir: str | Path, message: str) -> None:
    root = Path(case_dir)
    root.mkdir(parents=True, exist_ok=True)
    with (root / "audit.log").open("a", encoding="utf-8") as handle:
        handle.write(f"{time.time():.3f} {message}\n")
