from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path


class JpegDctError(ValueError):
    pass


SEED_ENV = "OBSCURAPRIMUS_JPEG_DCT_SEED"


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
    raise JpegDctError(backend_unavailable_message())


def backend_available() -> bool:
    parts = _backend_command_parts()
    executable = parts[0] if parts else ""
    return bool(executable and (Path(executable).exists() or shutil.which(executable)))


def backend_unavailable_message() -> str:
    return (
        "JPEG-DCT is an experimental optional backend (not a production carrier). "
        "Support is unavailable because OBSCURAPRIMUS_JPEG_DCT_BACKEND does not point "
        "to an installed coefficient-domain tool. Use BMP, PNG, WAV, or FLAC instead. "
        "Unsafe JPEG byte-level LSB mutation is intentionally disabled."
    )


def embed_with_backend(cover_path: str | Path, output_path: str | Path, container_path: str | Path, password_seed: str = "") -> None:
    require_dct_backend()
    _run_backend(["embed", str(cover_path), str(container_path), str(output_path)], seed=password_seed)


def extract_with_backend(stego_path: str | Path, container_path: str | Path, password_seed: str = "") -> None:
    require_dct_backend()
    _run_backend(["extract", str(stego_path), str(container_path)], seed=password_seed)


def capacity_with_backend(path: str | Path) -> int:
    require_dct_backend()
    result = _run_backend(["capacity", str(path)], capture=True)
    try:
        return int(result.strip())
    except ValueError as exc:
        raise JpegDctError(f"JPEG DCT backend returned an invalid capacity: {result!r}") from exc


def _run_backend(args: list[str], capture: bool = False, seed: str = "") -> str:
    command = _backend_command_parts()
    if not command:
        raise JpegDctError("OBSCURAPRIMUS_JPEG_DCT_BACKEND is not configured.")
    env = os.environ.copy()
    seed_path = None
    if seed:
        fd, seed_path = tempfile.mkstemp(prefix="obp-jpeg-seed-", suffix=".txt")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(seed)
            env[SEED_ENV] = seed_path
            env.pop("OBSCURAPRIMUS_JPEG_DCT_PASSWORD", None)
        except Exception:
            try:
                os.close(fd)
            except OSError:
                pass
            if seed_path:
                Path(seed_path).unlink(missing_ok=True)
            raise
    try:
        result = subprocess.run([*command, *args], text=True, capture_output=True, timeout=300, env=env)
    finally:
        if seed_path:
            try:
                Path(seed_path).unlink(missing_ok=True)
            except OSError:
                pass
    if result.returncode:
        raise JpegDctError((result.stderr or result.stdout or "JPEG DCT backend failed.").strip())
    return result.stdout if capture else ""


def _backend_command_parts() -> list[str]:
    command = os.environ.get("OBSCURAPRIMUS_JPEG_DCT_BACKEND", "").strip()
    if not command:
        return []
    parts = shlex.split(command, posix=not sys.platform.startswith("win"))
    if sys.platform.startswith("win"):
        parts = [_strip_matching_quotes(part) for part in parts]
    return parts


def _strip_matching_quotes(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        return value[1:-1]
    return value
