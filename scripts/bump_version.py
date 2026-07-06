from __future__ import annotations

import argparse
import re
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description="Bump ObscuraPrimus version metadata.")
    parser.add_argument("version", help="Version such as 1.1.0")
    parser.add_argument("--tag", action="store_true", help="Create a git tag after updating files")
    args = parser.parse_args()
    version = args.version
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise SystemExit("Version must use MAJOR.MINOR.PATCH, for example 1.1.0")

    version_tuple = tuple(int(part) for part in version.split("."))
    _replace(ROOT / "obscuraprimus" / "__init__.py", r'__version__ = "[^"]+"', f'__version__ = "{version}"')
    _replace(ROOT / "pyproject.toml", r'version = "[^"]+"', f'version = "{version}"')
    _replace(ROOT / "version_info.txt", r"filevers=\([^)]+\)", f"filevers=({version_tuple[0]}, {version_tuple[1]}, {version_tuple[2]}, 0)")
    _replace(ROOT / "version_info.txt", r"prodvers=\([^)]+\)", f"prodvers=({version_tuple[0]}, {version_tuple[1]}, {version_tuple[2]}, 0)")
    _replace(ROOT / "version_info.txt", r'StringStruct\("FileVersion", "[^"]+"\)', f'StringStruct("FileVersion", "{version}")')
    _replace(ROOT / "version_info.txt", r'StringStruct\("ProductVersion", "[^"]+"\)', f'StringStruct("ProductVersion", "{version}")')
    _replace(ROOT / "obscuraprimus" / "gui_main.py", r"ObscuraPrimus \d+\.\d+\.\d+", f"ObscuraPrimus {version}")

    changelog = ROOT / "CHANGELOG.md"
    text = changelog.read_text(encoding="utf-8")
    if f"## {version}" not in text:
        text = text.replace("# Changelog\n\n", f"# Changelog\n\n## {version} - Unreleased\n\n- Pending release notes.\n\n", 1)
        changelog.write_text(text, encoding="utf-8")

    if args.tag:
        subprocess.run(["git", "tag", f"v{version}"], cwd=ROOT, check=True)
    print(f"Bumped version metadata to {version}")
    return 0


def _replace(path: Path, pattern: str, replacement: str) -> None:
    text = path.read_text(encoding="utf-8")
    new_text = re.sub(pattern, replacement, text)
    if new_text == text:
        raise SystemExit(f"Pattern not found in {path}: {pattern}")
    path.write_text(new_text, encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
