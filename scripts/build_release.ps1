param(
    [string]$Version = "1.0.0",
    [string]$GpgExe = "",
    [string]$GpgHome = "",
    [string]$GpgKey = "ObscuraPrimus Release Signing (2026) <release@obscuraprimus.local>"
)

$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $PSScriptRoot
$ReleaseRoot = Join-Path $Root "release"
$ReleaseDir = Join-Path $ReleaseRoot "ObscuraPrimus-$Version-windows-x64"
$ExePath = Join-Path $Root "dist\ObscuraPrimus.exe"
$ZipPath = Join-Path $ReleaseRoot "ObscuraPrimus-$Version-windows-x64.zip"
$DocsDir = Join-Path $Root "docs"
$SbomPath = Join-Path $ReleaseRoot "SBOM.json"
$LicenseReportPath = Join-Path $ReleaseRoot "DEPENDENCY_LICENSES.md"

Set-Location $Root

python -m unittest discover -s tests
python -m compileall app.py obscuraprimus
python scripts\generate_sbom.py
python scripts\dependency_licenses.py
python -m PyInstaller --clean --noconfirm ObscuraPrimus.spec

if (!(Test-Path $ExePath)) {
    throw "Expected executable was not created: $ExePath"
}

if (Test-Path $ReleaseDir) {
    Remove-Item -Recurse -Force $ReleaseDir
}
New-Item -ItemType Directory -Force $ReleaseDir | Out-Null
Copy-Item $ExePath (Join-Path $ReleaseDir "ObscuraPrimus.exe") -Force
Copy-Item README.md, LICENSE, CHANGELOG.md $ReleaseDir -Force
Copy-Item $SbomPath, $LicenseReportPath $ReleaseDir -Force

$notes = @"
# ObscuraPrimus $Version

Windows portable release.

## Included

- ObscuraPrimus.exe
- ObscuraPrimus.exe.asc
- README.md
- LICENSE
- CHANGELOG.md
- SBOM.json
- SBOM.json.asc
- DEPENDENCY_LICENSES.md
- DEPENDENCY_LICENSES.md.asc

## Usage

Run ObscuraPrimus.exe from any local folder or USB drive.

Verify the zip or executable with the detached PGP signatures and the public
key in docs/ObscuraPrimus_Release_Signing_2026_pubkey.asc.
"@

$notes | Set-Content -Encoding UTF8 (Join-Path $ReleaseDir "RELEASE_NOTES.md")

$ChecksumPath = Join-Path $ReleaseRoot "SHA256SUMS.txt"

if (!$GpgExe) {
    $cmd = Get-Command gpg -ErrorAction SilentlyContinue
    if ($cmd) {
        $GpgExe = $cmd.Source
    } else {
        $candidate = "C:\Program Files\Git\usr\bin\gpg.exe"
        if (Test-Path $candidate) {
            $GpgExe = $candidate
        }
    }
}

$publicKey = Join-Path $DocsDir "ObscuraPrimus_Release_Signing_2026_pubkey.asc"
$pgpArgs = @("scripts\pgp_release.py")
if ($GpgExe) { $pgpArgs += @("--gpg-exe", $GpgExe) }
if ($GpgHome) { $pgpArgs += @("--gpg-home", $GpgHome) }
if ($GpgKey) { $pgpArgs += @("--key-id", $GpgKey) }
$pgpAvailable = $false
$ensureOutput = & python @pgpArgs "ensure-key" "--public-key" $publicKey
if ($LASTEXITCODE -eq 0) {
    $pgpAvailable = $true
    Write-Host "PGP signing key ready: $ensureOutput"
    & python @pgpArgs "sign" $ExePath $SbomPath $LicenseReportPath
    if ($LASTEXITCODE -ne 0) {
        throw "PGP signing failed for pre-zip artifacts"
    }
    Copy-Item "$ExePath.asc" (Join-Path $ReleaseDir "ObscuraPrimus.exe.asc") -Force
    Copy-Item "$SbomPath.asc" (Join-Path $ReleaseDir "SBOM.json.asc") -Force
    Copy-Item "$LicenseReportPath.asc" (Join-Path $ReleaseDir "DEPENDENCY_LICENSES.md.asc") -Force
} else {
    Write-Warning "GPG was not found; release artifacts were not PGP-signed."
}

if (Test-Path $ZipPath) {
    Remove-Item $ZipPath -Force
}
Compress-Archive -Path (Join-Path $ReleaseDir "*") -DestinationPath $ZipPath

if ($pgpAvailable) {
    & python @pgpArgs "sign" $ZipPath
    if ($LASTEXITCODE -ne 0) {
        throw "PGP signing failed for $ZipPath"
    }
}

$checksumTargets = @($ExePath, $ZipPath, $SbomPath, $LicenseReportPath)
if (Test-Path "$ExePath.asc") { $checksumTargets += "$ExePath.asc" }
if (Test-Path "$ZipPath.asc") { $checksumTargets += "$ZipPath.asc" }
if (Test-Path "$SbomPath.asc") { $checksumTargets += "$SbomPath.asc" }
if (Test-Path "$LicenseReportPath.asc") { $checksumTargets += "$LicenseReportPath.asc" }
Get-FileHash -Algorithm SHA256 $checksumTargets |
    ForEach-Object { "$($_.Hash.ToLower())  $([IO.Path]::GetFileName($_.Path))" } |
    Set-Content -Encoding ASCII $ChecksumPath

if ($pgpAvailable) {
    & python @pgpArgs "sign" $ChecksumPath
    if ($LASTEXITCODE -ne 0) {
        throw "PGP signing failed for $ChecksumPath"
    }
}

Write-Host "Release created:"
Write-Host "  $ReleaseDir"
Write-Host "  $ZipPath"
Write-Host "  $ChecksumPath"
