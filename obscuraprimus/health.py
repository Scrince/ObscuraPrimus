from __future__ import annotations

import shutil
import urllib.error
import urllib.request
from pathlib import Path

from .runtime import app_base_dir, portable_data_dir


def portable_health() -> dict:
    base = app_base_dir()
    data = portable_data_dir()
    return {
        "base_dir": str(base),
        "data_dir": str(data),
        "base_writable": _writable(base),
        "data_writable": _writable(data),
        "gpg_available": bool(shutil.which("gpg") or shutil.which("gpg.exe") or Path(r"C:\Program Files\Git\usr\bin\gpg.exe").exists()),
        "yara_available": bool(shutil.which("yara") or shutil.which("yara64")),
        "clamav_available": bool(shutil.which("clamscan")),
    }


def check_github_update(repo: str, current_version: str) -> dict:
    if not repo or "/" not in repo:
        return {"available": False, "error": "No GitHub repository configured."}
    url = f"https://api.github.com/repos/{repo}/releases/latest"
    try:
        with urllib.request.urlopen(url, timeout=10) as response:
            import json

            payload = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, ValueError):
        return {"available": False, "error": "Unable to check releases."}
    latest = str(payload.get("tag_name", "")).lstrip("v")
    return {"available": latest and latest != current_version, "latest": latest, "url": payload.get("html_url", "")}


def _writable(path: Path) -> bool:
    try:
        path.mkdir(parents=True, exist_ok=True)
        probe = path / ".write-test"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        return True
    except OSError:
        return False
