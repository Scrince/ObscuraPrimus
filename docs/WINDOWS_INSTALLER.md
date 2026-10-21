# Windows installer

Installs the Windows x64 application package.

Installer: `release/windows/ObscuraPrimus-Setup-1.0.0.exe`

SHA-256: `fbc9e1ca5e65015636f680e74a86f70d309d68e20bf8657365fe0d06d3e56a9a`

Detached OpenPGP signature: `release/windows/ObscuraPrimus-Setup-1.0.0.exe.asc`

This is a detached OpenPGP release signature, not a Windows Authenticode signature.

Public key: `docs/ObscuraPrimus_Release_Signing_2026_pubkey.asc`
Fingerprint: `323D123CBF92E8C962AAA8463B4CCEFECA580B4D`

Compare the fingerprint above before importing the key. From the project root:

```powershell
gpg --show-keys docs/ObscuraPrimus_Release_Signing_2026_pubkey.asc
gpg --import docs/ObscuraPrimus_Release_Signing_2026_pubkey.asc
gpg --verify release/windows/ObscuraPrimus-Setup-1.0.0.exe.asc release/windows/ObscuraPrimus-Setup-1.0.0.exe
gpg --verify release/windows/SHA256SUMS.asc release/windows/SHA256SUMS
```
