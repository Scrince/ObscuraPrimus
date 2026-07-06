from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import os
import shutil
import subprocess


class JpegDctError(ValueError):
    pass


@dataclass(frozen=True)
class JpegInfo:
    path: str
    size: int
    has_soi: bool
    has_eoi: bool
    scan_count: int
    quantization_tables: int


def inspect_jpeg(path: str | Path) -> JpegInfo:
    data = Path(path).read_bytes()
    if len(data) < 4:
        return JpegInfo(str(path), len(data), False, False, 0, 0)
    scan_count = data.count(b"\xff\xda")
    quantization_tables = data.count(b"\xff\xdb")
    return JpegInfo(
        path=str(path),
        size=len(data),
        has_soi=data.startswith(b"\xff\xd8"),
        has_eoi=data.endswith(b"\xff\xd9"),
        scan_count=scan_count,
        quantization_tables=quantization_tables,
    )


def require_dct_backend() -> None:
    if backend_available():
        return
    raise JpegDctError(
        "JPEG DCT support requires an external coefficient-domain backend configured in "
        "OBSCURAPRIMUS_JPEG_DCT_BACKEND. Byte-level LSB mutation is intentionally disabled."
    )


def backend_available() -> bool:
    command = os.environ.get("OBSCURAPRIMUS_JPEG_DCT_BACKEND", "").strip()
    executable = command.split()[0] if command else ""
    return bool(executable and (Path(executable).exists() or shutil.which(executable)))


def embed_with_backend(cover_path: str | Path, output_path: str | Path, container_path: str | Path, password_seed: str = "") -> None:
    require_dct_backend()
    _run_backend(["embed", str(cover_path), str(container_path), str(output_path), password_seed])


def extract_with_backend(stego_path: str | Path, container_path: str | Path, password_seed: str = "") -> None:
    require_dct_backend()
    _run_backend(["extract", str(stego_path), str(container_path), password_seed])


def capacity_with_backend(path: str | Path) -> int:
    require_dct_backend()
    result = _run_backend(["capacity", str(path)], capture=True)
    try:
        return int(result.strip())
    except ValueError as exc:
        raise JpegDctError(f"JPEG DCT backend returned an invalid capacity: {result!r}") from exc


def _run_backend(args: list[str], capture: bool = False) -> str:
    command = os.environ.get("OBSCURAPRIMUS_JPEG_DCT_BACKEND", "").strip()
    if not command:
        raise JpegDctError("OBSCURAPRIMUS_JPEG_DCT_BACKEND is not configured.")
    result = subprocess.run([command, *args], text=True, capture_output=True, timeout=300)
    if result.returncode:
        raise JpegDctError((result.stderr or result.stdout or "JPEG DCT backend failed.").strip())
    return result.stdout if capture else ""
