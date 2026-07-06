from __future__ import annotations

import importlib.metadata as metadata
import json
from pathlib import Path


PROJECT_PACKAGES = ["PySide6", "cryptography", "pyinstaller"]


def main() -> int:
    components = []
    for package in PROJECT_PACKAGES:
        try:
            dist = metadata.distribution(package)
        except metadata.PackageNotFoundError:
            continue
        components.append(
            {
                "name": dist.metadata["Name"],
                "version": dist.version,
                "license": dist.metadata.get("License-Expression") or dist.metadata.get("License") or "unknown",
                "summary": dist.metadata.get("Summary", ""),
            }
        )
    payload = {
        "bomFormat": "CycloneDX-lite",
        "specVersion": "1.0",
        "metadata": {"component": {"name": "ObscuraPrimus", "version": "1.0.0"}},
        "components": components,
    }
    output = Path("release") / "SBOM.json"
    output.parent.mkdir(exist_ok=True)
    output.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
