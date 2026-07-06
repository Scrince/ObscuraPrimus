# ObscuraPrimus

ObscuraPrimus is a USB-portable steganography desktop app written in Python and PySide6. It hides files inside BMP images or WAV audio by writing encrypted and optionally compressed payload bits into least-significant carrier bits.

## Features

- Embed any secret file into BMP, PNG, or WAV cover files.
- Extract hidden files from ObscuraPrimus stego files.
- Optional zlib compression.
- Optional password encryption with AES-256-GCM.
- Optional XChaCha20-Poly1305 when the installed `cryptography` build exposes it.
- PBKDF2-HMAC-SHA256 key derivation with per-payload salt.
- Adaptive embedding mode that avoids carrier bytes near extreme values.
- Spread payload mode using password-seeded pseudo-random carrier ordering.
- Payload density presets: `maximum`, `balanced`, and `stealth`.
- Separate stego key for adaptive/spread carrier ordering.
- PBKDF2-HMAC-SHA256 or built-in `hashlib.scrypt` KDF.
- Encrypted metadata for password-protected payloads.
- SHA-256 payload checksum validation during extraction.
- Atomic extraction writes to avoid partial output files.
- Portable config and log files in `ObscuraPrimusData`.
- Forensic scanner for files or folders that may contain ObscuraPrimus payloads, with a sortable GUI table, CSV/JSON reports, risk scoring, and generic LSB anomaly checks.
- Full file analysis suite with magic-byte identification, hashes, entropy maps, safe hex preview/search, strings, IOCs, metadata, archive inspection, PE/script triage, duplicate detection, timeline fields, and case manifests.
- Report export to CSV, JSON, and HTML, with optional local GPG detached signatures.
- GUI and CLI workflows.
- Portable settings page with default options and high-contrast mode.
- Drag-and-drop file fields, progress bars, and status logs.

## Project Layout

- `app.py` - application entry point.
- `obscuraprimus/gui_main.py` - PySide6 interface.
- `obscuraprimus/stego_engine.py` - BMP/PNG/WAV bit-level embedding and extraction.
- `obscuraprimus/png_codec.py` - dependency-light lossless PNG reader/writer.
- `obscuraprimus/runtime.py` - portable config and logging paths.
- `obscuraprimus/forensics.py` - file/folder scanner.
- `obscuraprimus/file_analysis.py` - analysis suite core, reports, cases, and chain-of-custody helpers.
- `obscuraprimus/cli.py` - command-line interface.
- `obscuraprimus/carriers.py` - carrier codec registry.
- `obscuraprimus/jpeg_dct.py` - JPEG-DCT inspection/scaffold for a future codec backend.
- `obscuraprimus/crypto.py` - encryption and password key derivation.
- `obscuraprimus/compression.py` - zlib wrapper.
- `ObscuraPrimus.spec` - PyInstaller single-executable build spec.

## Install For Development

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python app.py
```

## Example Workflow

1. Open the app with `python app.py`.
2. In the Embed tab, choose a `.bmp`, `.png`, or `.wav` cover file.
3. Choose the secret file to hide.
4. Pick an output path such as `cover_obscura.bmp`.
5. Enable compression, encryption, and adaptive embedding as desired.
6. If encryption is enabled, enter a password.
7. Click **Embed File**.
8. In the Extract tab, choose the generated stego file.
9. Enter the same password if encryption was used.
10. Choose an output filename and click **Extract File**.

## CLI Workflow

```powershell
python -m obscuraprimus embed --cover cover.png --secret notes.zip --out stego.png --encryption AES-256-GCM --kdf scrypt --password "long passphrase" --stego-key "carrier key" --adaptive --spread --density stealth --verify
python -m obscuraprimus extract --cover stego.png --out recovered.zip --password "long passphrase" --stego-key "carrier key"
python -m obscuraprimus capacity --cover cover.wav --adaptive
python -m obscuraprimus scan C:\path\to\suspicious-folder --csv forensic-report.csv --json forensic-report.json
python -m obscuraprimus analyze C:\path\to\evidence --profile deep --report report.html --sign-report
python -m obscuraprimus analyze C:\path\to\evidence --case-dir C:\cases\demo
python -m obscuraprimus hex suspicious.bin --offset 0x200 --length 512
python -m obscuraprimus case C:\cases\demo --add suspicious.bin --tag malware-triage --notes "Initial intake"
python -m obscuraprimus case C:\cases\demo --fts example.com
python -m obscuraprimus case C:\cases\demo --finding "Suspicious payload" --finding-file suspicious.bin --finding-severity high
python -m obscuraprimus case C:\cases\demo --export-bundle C:\cases\demo.tgz --sign-bundle
```

## Forensic Mode

The Forensics tab and `scan` CLI command inspect BMP, PNG, and WAV files for ObscuraPrimus v2 payload prefixes. A scan can recurse through folders and optionally write CSV or JSON reports. Findings include a risk score, entropy estimate, LSB one-ratio, and generic LSB anomaly status when no ObscuraPrimus prefix is present. If you provide a password and optional stego key, the scanner will also try to parse protected payload metadata.

## File Analysis Suite

The Analysis tab and `analyze` CLI command are read-only and safe by design. They identify files by magic bytes, detect extension/signature mismatches, calculate MD5/SHA-1/SHA-256/SHA-512/BLAKE2 hashes, extract strings and IOCs, inspect common metadata and archives, score risk across all files, detect duplicates by SHA-256, and export analyst reports.

Supported built-in inspection includes PNG/BMP/WAV/JPEG/PDF/ZIP/Office/tar/gzip/7z-signature/PE/MSI/LNK/SQLite/script heuristics. JPEG EXIF/GPS metadata can be parsed and stripped. PDF inspection flags objects, streams, JavaScript, embedded files, and launch/open actions. Office inspection flags relationships, external links, macros, and embedded objects. YARA and ClamAV are used when their external binaries are installed.

Case workspaces include a manifest, SQLite `case.db`, and append-only audit log for evidence intake. Reports can be signed with the same local GPG release-signing pattern.

The case database stores files, findings, IOCs, tags, notes, timeline events, reports, chain-of-custody entries, and full-text search indexes. Findings support status, severity, owner, false-positive state, and report inclusion state.

Additional CLI utilities:

```powershell
python -m obscuraprimus carve suspicious.bin --out carved
python -m obscuraprimus carve suspicious.bin --out carved --preview
python -m obscuraprimus compare before.bin after.bin
python -m obscuraprimus exif-strip photo.jpg photo_no_exif.jpg
python -m obscuraprimus yara --rules rules.yar --target suspicious.bin
python -m obscuraprimus charts suspicious.bin --kind entropy
python -m obscuraprimus artifact History --kind browser
python -m obscuraprimus detect script.ps1 --kind deobfuscate
python -m obscuraprimus detect suspicious.exe --kind authenticode
python -m obscuraprimus timeline C:\path\to\evidence --out timeline.csv
python -m obscuraprimus plugin-sdk C:\cases\demo\plugins\example
python -m obscuraprimus health
python -m obscuraprimus plugins
python -m obscuraprimus update-check --repo The-Swarm-Corporation/ObscuraPrimus --current 1.0.0
```

## Version Bumps

```powershell
python scripts\bump_version.py 1.1.0
python scripts\bump_version.py 1.1.0 --tag
```

## Build A Portable Executable

From an activated virtual environment:

```powershell
python -m pip install -r requirements.txt
python -m PyInstaller --clean --noconfirm ObscuraPrimus.spec
```

The single portable executable will be created at:

```text
dist\ObscuraPrimus.exe
```

Or use the release script, which also creates a zip and checksums:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\build_release.ps1 -Version 1.0.0
```

The release script also creates detached ASCII-armored PGP signatures when GPG is available. By default it uses a local `.gnupg-release` keyring and exports the public key to:

```text
docs\ObscuraPrimus_Release_Signing_2026_pubkey.asc
```

Verify artifacts with:

```powershell
gpg --verify release\SHA256SUMS.txt.asc release\SHA256SUMS.txt
gpg --verify release\ObscuraPrimus-1.0.0-windows-x64.zip.asc release\ObscuraPrimus-1.0.0-windows-x64.zip
```

Release builds also include `SBOM.json` and `DEPENDENCY_LICENSES.md`.

An optional Inno Setup installer template is available at `installer/ObscuraPrimus.iss`.

Copy that executable to a USB drive along with any files you want to process. No installation is required on the target Windows machine beyond normal OS support for the bundled executable.

## Notes And Limits

- Supported built-in cover formats are BMP, PNG, WAV, and FLAC.
- PNG support is limited to non-interlaced 8-bit grayscale, RGB, grayscale-alpha, and RGBA images.
- JPEG support uses the `OBSCURAPRIMUS_JPEG_DCT_BACKEND` adapter contract for coefficient-domain embedding/extraction. Unsafe JPEG byte-level LSB mutation is intentionally disabled.
- FLAC support writes a valid FLAC APPLICATION metadata block and preserves audio frame bytes.
- Stego output should keep the same format as the cover file.
- Adaptive/spread mode is self-describing, but password-derived carrier ordering means the same password is needed when those modes are used with encryption.
- Wrong passwords or corrupted payloads are reported as extraction errors.
