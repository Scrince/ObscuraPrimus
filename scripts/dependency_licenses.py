from __future__ import annotations

import importlib.metadata as metadata
from pathlib import Path


PROJECT_PACKAGES = ["PySide6", "cryptography", "pyinstaller"]


def main() -> int:
    lines = ["# Dependency Licenses", ""]
    for package in PROJECT_PACKAGES:
        try:
            dist = metadata.distribution(package)
        except metadata.PackageNotFoundError:
            continue
        license_name = dist.metadata.get("License-Expression") or dist.metadata.get("License") or "unknown"
        lines.append(f"- {dist.metadata['Name']} {dist.version}: {license_name}")
    output = Path("release") / "DEPENDENCY_LICENSES.md"
    output.parent.mkdir(exist_ok=True)
    output.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
