from __future__ import annotations

import os
import hashlib
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

try:
    from cryptography.hazmat.primitives.ciphers.aead import XChaCha20Poly1305
except ImportError:  
    XChaCha20Poly1305 = None


PBKDF2_ITERATIONS = 390_000

PBKDF2_MIN_ITERATIONS = 100_000
PBKDF2_MAX_ITERATIONS = 1_000_000
SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1
SALT_SIZE = 16
AES_NONCE_SIZE = 12
XCHACHA_NONCE_SIZE = 24
KEY_SIZE = 32


class CryptoError(ValueError):
    pass


def _require_pbkdf2_iterations(iterations: int) -> int:
    """Reject out-of-range iteration counts (no silent re-derivation with different N)."""
    try:
        value = int(iterations)
    except (TypeError, ValueError) as exc:
        raise CryptoError("Invalid PBKDF2 iteration count.") from exc
    if value < PBKDF2_MIN_ITERATIONS or value > PBKDF2_MAX_ITERATIONS:
        raise CryptoError(
            f"Unsupported PBKDF2 iteration count: {value} "
            f"(allowed range {PBKDF2_MIN_ITERATIONS}–{PBKDF2_MAX_ITERATIONS})."
        )
    return value


@dataclass(frozen=True)
class EncryptionResult:
    ciphertext: bytes
    salt: bytes
    nonce: bytes
    iterations: int
    kdf: str = "PBKDF2-HMAC-SHA256"


def is_xchacha_available() -> bool:
    return XChaCha20Poly1305 is not None


def derive_key(password: str, salt: bytes, iterations: int = PBKDF2_ITERATIONS, kdf: str = "PBKDF2-HMAC-SHA256") -> bytes:
    if not password:
        raise CryptoError("A password is required for encryption.")
    if kdf == "scrypt":
        return hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=SCRYPT_N,
            r=SCRYPT_R,
            p=SCRYPT_P,
            dklen=KEY_SIZE,
        )
    if kdf != "PBKDF2-HMAC-SHA256":
        raise CryptoError(f"Unsupported KDF: {kdf}")
    safe_iterations = _require_pbkdf2_iterations(iterations)
    pbkdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=safe_iterations,
    )
    return pbkdf.derive(password.encode("utf-8"))


def encrypt(
    data: bytes,
    password: str,
    algorithm: str = "AES-256-GCM",
    kdf: str = "PBKDF2-HMAC-SHA256",
    associated_data: bytes | None = None,
) -> EncryptionResult:
    salt = os.urandom(SALT_SIZE)
    iterations = PBKDF2_ITERATIONS
    key = derive_key(password, salt, iterations, kdf)

    if algorithm == "AES-256-GCM":
        nonce = os.urandom(AES_NONCE_SIZE)
        ciphertext = AESGCM(key).encrypt(nonce, data, associated_data)
    elif algorithm == "XChaCha20-Poly1305":
        if XChaCha20Poly1305 is None:
            raise CryptoError("XChaCha20-Poly1305 is not available in this cryptography build.")
        nonce = os.urandom(XCHACHA_NONCE_SIZE)
        ciphertext = XChaCha20Poly1305(key).encrypt(nonce, data, associated_data)
    else:
        raise CryptoError(f"Unsupported encryption algorithm: {algorithm}")

    return EncryptionResult(ciphertext=ciphertext, salt=salt, nonce=nonce, iterations=iterations, kdf=kdf)


def decrypt(
    ciphertext: bytes,
    password: str,
    algorithm: str,
    salt: bytes,
    nonce: bytes,
    iterations: int,
    kdf: str = "PBKDF2-HMAC-SHA256",
    associated_data: bytes | None = None,
) -> bytes:
    try:
        # Validate iterations before deriving so out-of-range files fail explicitly.
        if kdf == "PBKDF2-HMAC-SHA256":
            iterations = _require_pbkdf2_iterations(iterations)
        key = derive_key(password, salt, iterations, kdf)
        if algorithm == "AES-256-GCM":
            return AESGCM(key).decrypt(nonce, ciphertext, associated_data)
        if algorithm == "XChaCha20-Poly1305":
            if XChaCha20Poly1305 is None:
                raise CryptoError("XChaCha20-Poly1305 is not available in this cryptography build.")
            return XChaCha20Poly1305(key).decrypt(nonce, ciphertext, associated_data)
    except InvalidTag as exc:
        raise CryptoError("Decryption failed. The password may be wrong or the payload is corrupted.") from exc

    raise CryptoError(f"Unsupported encryption algorithm: {algorithm}")
