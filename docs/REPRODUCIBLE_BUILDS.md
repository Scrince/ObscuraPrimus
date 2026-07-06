# Reproducible Build Notes

ObscuraPrimus releases are built as Windows single-file executables with PyInstaller.

## Recommended Environment

- Windows 11 x64
- Python 3.12.x for GitHub Actions releases
- PyInstaller 6.x
- PySide6 6.x
- cryptography 42.x or newer

The local desktop build may use a newer Python version, but official releases should pin the GitHub Actions Python version and dependency lockfile when exact byte-for-byte reproducibility becomes a release requirement.

## Local Release Build

```powershell
python -m pip install -r requirements.txt
powershell -ExecutionPolicy Bypass -File scripts\build_release.ps1 -Version 1.0.0
```

## Version Tags

```powershell
python scripts\bump_version.py 1.1.0 --tag
git push origin main --tags
```

Outputs:

- `dist\ObscuraPrimus.exe`
- `release\ObscuraPrimus-1.0.0-windows-x64\ObscuraPrimus.exe`
- `release\ObscuraPrimus-1.0.0-windows-x64.zip`
- `release\SHA256SUMS.txt`
- `release\SBOM.json`
- `release\DEPENDENCY_LICENSES.md`
- detached PGP signatures beside release artifacts when GPG is available

## PGP Release Signing

```powershell
powershell -ExecutionPolicy Bypass -File scripts\build_release.ps1 -Version 1.0.0
```

The release script uses GPG in the style of YellowSphere: detached ASCII-armored `.asc` signatures are generated for the executable, zip, and checksum manifest. If no release key exists, a local no-passphrase release key is created in `.gnupg-release` and the public key is exported to `docs\ObscuraPrimus_Release_Signing_2026_pubkey.asc`.

Verify the manifest:

```powershell
gpg --verify release\SHA256SUMS.txt.asc release\SHA256SUMS.txt
```

Current local release signing key fingerprint:

```text
323D 123C BF92 E8C9 62AA A846 3B4C CEFE CA58 0B4D
```

These PGP signatures provide release integrity. They do not replace Windows Authenticode publisher signing.

The same local GPG home can sign analysis reports generated with:

```powershell
python -m obscuraprimus analyze evidence --report report.html --sign-report
```
