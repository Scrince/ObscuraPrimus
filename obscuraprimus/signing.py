from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .runtime import app_base_dir

RELEASE_SIGNING_IDENTITY = "ObscuraPrimus Release Signing (2026) <release@obscuraprimus.local>"
RELEASE_KEY_NAME = "ObscuraPrimus Release Signing"
RELEASE_KEY_COMMENT = "2026"
RELEASE_KEY_EMAIL = "release@obscuraprimus.local"
PASSPHRASE_ENV = "OBSCURAPRIMUS_GPG_PASSPHRASE"


@dataclass(frozen=True)
class SigningConfig:
    gpg_exe: str
    gpg_home: Path
    key_id: str = RELEASE_SIGNING_IDENTITY

    @property
    def gpg_home_arg(self) -> str:
        home = str(self.gpg_home.resolve())
        if self.gpg_exe.endswith(r"Git\usr\bin\gpg.exe") and re.match(r"^[A-Za-z]:\\", home):
            drive = home[0].lower()
            rest = home[3:].replace("\\", "/")
            return f"/{drive}/{rest}"
        return home


def default_gpg_home() -> Path:
    return app_base_dir() / ".gnupg-release"


def find_gpg(explicit: str = "") -> str:
    if explicit:
        return explicit if Path(explicit).exists() else shutil.which(explicit) or ""
    found = shutil.which("gpg") or shutil.which("gpg.exe")
    if found:
        return found
    candidate = Path(r"C:\Program Files\Git\usr\bin\gpg.exe")
    if candidate.exists():
        return str(candidate)
    candidate = Path(r"C:\Program Files\GnuPG\bin\gpg.exe")
    return str(candidate) if candidate.exists() else ""


def make_config(gpg_exe: str = "", gpg_home: str | Path = "", key_id: str | None = RELEASE_SIGNING_IDENTITY) -> SigningConfig | None:
    executable = find_gpg(gpg_exe)
    if not executable:
        return None
    home = Path(gpg_home) if gpg_home else default_gpg_home()
    home.mkdir(parents=True, exist_ok=True)
    _harden_gpg_home(home)
    return SigningConfig(executable, home, key_id or RELEASE_SIGNING_IDENTITY)


def ensure_release_key(config: SigningConfig) -> str:
    if _secret_key_exists(config):
        return release_fingerprint(config)
    passphrase = os.environ.get(PASSPHRASE_ENV, "")
    batch_lines = [
        "Key-Type: RSA",
        "Key-Length: 4096",
        "Key-Usage: sign",
        f"Name-Real: {RELEASE_KEY_NAME}",
        f"Name-Comment: {RELEASE_KEY_COMMENT}",
        f"Name-Email: {RELEASE_KEY_EMAIL}",
        "Expire-Date: 2y",
    ]
    if passphrase:
        batch_lines.append(f"Passphrase: {passphrase}")
    else:
        batch_lines.append("%no-protection")
    batch_lines.extend(["%commit", ""])
    batch = config.gpg_home / "gpg-keygen.batch"
    batch.write_text("\n".join(batch_lines), encoding="ascii")
    try:
        _run_gpg(config, "--batch", "--generate-key", str(batch))
    finally:
        batch.unlink(missing_ok=True)
    _harden_gpg_home(config.gpg_home)
    return release_fingerprint(config)


def export_public_key(config: SigningConfig, output_path: str | Path) -> Path:
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    result = _run_gpg(config, "--armor", "--export", config.key_id, capture=True)
    output.write_text(result.stdout, encoding="ascii")
    return output


def release_fingerprint(config: SigningConfig) -> str:
    result = _run_gpg(config, "--list-secret-keys", "--with-colons", config.key_id, capture=True, check=False)
    for line in result.stdout.splitlines():
        if line.startswith("fpr:"):
            return line.split(":")[9]
    return ""


def sign_file(path: str | Path, config: SigningConfig, output_path: str | Path = "") -> Path:
    target = Path(path)
    signature = Path(output_path) if output_path else target.with_suffix(target.suffix + ".asc")
    signature.unlink(missing_ok=True)
    args = [
        "--batch",
        "--yes",
        "--armor",
        "--detach-sign",
        "--local-user",
        config.key_id,
        "--output",
        str(signature),
        str(target),
    ]
    passphrase = os.environ.get(PASSPHRASE_ENV, "")
    if passphrase:
        args = [
            "--batch",
            "--yes",
            "--pinentry-mode",
            "loopback",
            "--passphrase-fd",
            "0",
            "--armor",
            "--detach-sign",
            "--local-user",
            config.key_id,
            "--output",
            str(signature),
            str(target),
        ]
        _run_gpg(config, *args, capture=True, input_text=passphrase + "\n")
    else:
        _run_gpg(config, *args)
    return signature


def _harden_gpg_home(home: Path) -> None:
    try:
        if os.name == "nt":
            return
        os.chmod(home, stat.S_IRWXU)
        for path in home.rglob("*"):
            mode = stat.S_IRUSR | stat.S_IWUSR
            if path.is_dir():
                mode = stat.S_IRWXU
            try:
                os.chmod(path, mode)
            except OSError:
                pass
    except OSError:
        pass


def _secret_key_exists(config: SigningConfig) -> bool:
    result = _run_gpg(config, "--list-secret-keys", "--with-colons", config.key_id, capture=True, check=False)
    return bool(result.stdout.strip())


def _run_gpg(
    config: SigningConfig,
    *args: str,
    capture: bool = False,
    check: bool = True,
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [config.gpg_exe, "--homedir", config.gpg_home_arg, *args],
        text=True,
        capture_output=capture or input_text is not None,
        check=check,
        input=input_text,
    )
