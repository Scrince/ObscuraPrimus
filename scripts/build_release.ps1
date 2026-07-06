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
- DEPENDENCY_LICENSES.md

## Usage

Run ObscuraPrimus.exe from any local folder or USB drive.

Verify the zip or executable with the detached PGP signatures and the public
key in docs/ObscuraPrimus_Release_Signing_2026_pubkey.asc.
"@

$notes | Set-Content -Encoding UTF8 (Join-Path $ReleaseDir "RELEASE_NOTES.md")

$ChecksumPath = Join-Path $ReleaseRoot "SHA256SUMS.txt"

if (!$GpgExe) {
    $candidate = "C:\Program Files\Git\usr\bin\gpg.exe"
    if (Test-Path $candidate) {
        $GpgExe = $candidate
    } else {
        $cmd = Get-Command gpg -ErrorAction SilentlyContinue
        if ($cmd) { $GpgExe = $cmd.Source }
    }
}

if ($GpgExe) {
    $previousErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    if (!$GpgHome) {
        $GpgHome = Join-Path $Root ".gnupg-release"
    }
    New-Item -ItemType Directory -Force $GpgHome | Out-Null
    $resolvedGpgHome = (Resolve-Path $GpgHome).Path
    if ($GpgExe -like "*\Git\usr\bin\gpg.exe" -and $resolvedGpgHome -match "^([A-Za-z]):\\(.*)$") {
        $drive = $Matches[1].ToLowerInvariant()
        $rest = $Matches[2] -replace "\\", "/"
        $gpgHomeArg = "/$drive/$rest"
    } else {
        $gpgHomeArg = $resolvedGpgHome
    }
    $secretKeys = & $GpgExe --homedir $gpgHomeArg --list-secret-keys --with-colons $GpgKey 2>$null
    if (!$secretKeys) {
        $batch = Join-Path $ReleaseRoot "gpg-keygen.batch"
        @"
Key-Type: RSA
Key-Length: 4096
Key-Usage: sign
Name-Real: ObscuraPrimus Release Signing
Name-Comment: 2026
Name-Email: release@obscuraprimus.local
Expire-Date: 2y
%no-protection
%commit
"@ | Set-Content -Encoding ASCII $batch
        & $GpgExe --homedir $gpgHomeArg --batch --generate-key $batch
        Remove-Item $batch -Force
    }

    $publicKey = Join-Path $DocsDir "ObscuraPrimus_Release_Signing_2026_pubkey.asc"
    New-Item -ItemType Directory -Force $DocsDir | Out-Null
    & $GpgExe --homedir $gpgHomeArg --armor --export $GpgKey | Set-Content -Encoding ASCII $publicKey

    foreach ($artifact in @($ExePath, $SbomPath, $LicenseReportPath)) {
        $sig = "$artifact.asc"
        if (Test-Path $sig) { Remove-Item $sig -Force }
        & $GpgExe --homedir $gpgHomeArg --batch --yes --armor --detach-sign --local-user $GpgKey --output $sig $artifact
        if ($LASTEXITCODE -ne 0) {
            $ErrorActionPreference = $previousErrorActionPreference
            throw "GPG signing failed for $artifact"
        }
    }
    Copy-Item "$ExePath.asc" (Join-Path $ReleaseDir "ObscuraPrimus.exe.asc") -Force
    Copy-Item "$SbomPath.asc" (Join-Path $ReleaseDir "SBOM.json.asc") -Force
    Copy-Item "$LicenseReportPath.asc" (Join-Path $ReleaseDir "DEPENDENCY_LICENSES.md.asc") -Force
    $ErrorActionPreference = $previousErrorActionPreference
} else {
    Write-Warning "GPG was not found; release artifacts were not PGP-signed."
}

if (Test-Path $ZipPath) {
    Remove-Item $ZipPath -Force
}
Compress-Archive -Path (Join-Path $ReleaseDir "*") -DestinationPath $ZipPath

if ($GpgExe) {
    $previousErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    $sig = "$ZipPath.asc"
    if (Test-Path $sig) { Remove-Item $sig -Force }
    & $GpgExe --homedir $gpgHomeArg --batch --yes --armor --detach-sign --local-user $GpgKey --output $sig $ZipPath
    if ($LASTEXITCODE -ne 0) {
        $ErrorActionPreference = $previousErrorActionPreference
        throw "GPG signing failed for $ZipPath"
    }
    $ErrorActionPreference = $previousErrorActionPreference
}

$checksumTargets = @($ExePath, $ZipPath, $SbomPath, $LicenseReportPath)
if (Test-Path "$ExePath.asc") { $checksumTargets += "$ExePath.asc" }
if (Test-Path "$ZipPath.asc") { $checksumTargets += "$ZipPath.asc" }
if (Test-Path "$SbomPath.asc") { $checksumTargets += "$SbomPath.asc" }
if (Test-Path "$LicenseReportPath.asc") { $checksumTargets += "$LicenseReportPath.asc" }
Get-FileHash -Algorithm SHA256 $checksumTargets |
    ForEach-Object { "$($_.Hash.ToLower())  $([IO.Path]::GetFileName($_.Path))" } |
    Set-Content -Encoding ASCII $ChecksumPath

if ($GpgExe) {
    $previousErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    $sig = "$ChecksumPath.asc"
    if (Test-Path $sig) { Remove-Item $sig -Force }
    & $GpgExe --homedir $gpgHomeArg --batch --yes --armor --detach-sign --local-user $GpgKey --output $sig $ChecksumPath
    if ($LASTEXITCODE -ne 0) {
        $ErrorActionPreference = $previousErrorActionPreference
        throw "GPG signing failed for $ChecksumPath"
    }
    $ErrorActionPreference = $previousErrorActionPreference
}

Write-Host "Release created:"
Write-Host "  $ReleaseDir"
Write-Host "  $ZipPath"
Write-Host "  $ChecksumPath"
