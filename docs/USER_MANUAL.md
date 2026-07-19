# ObscuraPrimus User Manual

## Modes

- **Embed** hides a file inside BMP, PNG, WAV, or FLAC covers. JPEG is available when a coefficient-domain backend is configured.
- **Extract** recovers ObscuraPrimus payloads.
- **Forensics** scans files/folders for ObscuraPrimus and generic LSB signals.
- **Analysis** performs read-only file triage, reporting, safe hex preview, carving, comparison, and case intake.
- **Suite** collects advanced analyst tools: YARA validation/matches, Sigma validation, chart data, virtual hex pages, immutable evidence import, case search, artifact inspection, anomaly scoring, deobfuscation, sample cases, and plugin SDK creation.
- **Settings** manages portable defaults, health checks, analyzer plugins, and update checks.

## Safe Analysis

The Analysis tab never executes inspected files. It reads bytes, parses structures, extracts strings/IOCs, and writes reports only when requested.

Large files are handled with streaming hash, entropy, search, and comparison paths. Deep parsers inspect a bounded prefix when a file is too large for full in-memory parsing; reports include a note when sampling was used.

Third-party analyzer plugins run in a separate Python process with a timeout. A plugin crash, timeout, or invalid result is recorded as a plugin error instead of crashing the main application.

## Embed Presets

The Embed tab includes presets for common workflows:

- **Maximum privacy** enables compression, AES-256-GCM, scrypt, adaptive mode, spread mode, stealth density, and verify-after-embed.
- **Balanced** enables encryption, compression, adaptive/spread carrier ordering, balanced density, and verification.
- **Maximum capacity** keeps encryption and verification enabled while using maximum density.
- **No encryption** leaves payload encryption disabled and requires explicit confirmation before embedding.

The live security summary shows the selected encryption, KDF, density, carrier-ordering behavior, and verification status before the output file is written. Weak encryption passwords are blocked.

## Cases

Choose a case folder, then add selected evidence with tags and notes. ObscuraPrimus writes:

- `manifest.json`
- `case.db`
- `audit.log`

The SQLite case database stores files, findings, IOCs, tags, notes, timeline events, report records, chain-of-custody entries, and an FTS index for case-wide search.

## Deep Inspection

Analysis includes EXIF/GPS parsing, PDF object/action checks, Office relationships and macro indicators, archive entries, PE sections/data directories, MSI/LNK/SQLite inspection, script heuristics, IOC extraction, and optional YARA/ClamAV integrations.

## Carving And Compare

Use the Analysis tab buttons or CLI to carve embedded PNG/JPEG/ZIP/PDF/PE candidates and compare two files by hash, entropy, size, and byte differences.

## Suite Tools

The Suite tab includes interactive chart rendering for entropy/histogram data, a virtual hex viewer that reads the current page instead of loading huge files into memory, immutable evidence import, case dashboard counts, command shortcuts, and plugin SDK helpers.

Keyboard shortcuts:

- `Ctrl+E`: start embed
- `Ctrl+R`: start extraction
- `Ctrl+F`: start analysis
- `Ctrl+L`: focus the Suite command field

## Report Verification

Reports can be signed with the local GPG release key. Verify with:

```powershell
gpg --verify report.html.asc report.html
```

If the local release key does not exist, ObscuraPrimus creates it in `.gnupg-release` before signing and exports the matching public key to `docs\ObscuraPrimus_Release_Signing_2026_pubkey.asc` during release builds.

## External Tools

Optional integrations are used only if installed:

- `yara` or `yara64`
- `clamscan`
- GPG
- JPEG DCT backend configured with `OBSCURAPRIMUS_JPEG_DCT_BACKEND`
