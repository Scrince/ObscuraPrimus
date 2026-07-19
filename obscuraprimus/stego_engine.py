from __future__ import annotations

import json
import hashlib
import math
import os
import random
import tempfile
import struct
import wave
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .compression import compress_data, decompress_data
from .crypto import CryptoError, decrypt, encrypt
from .flac_codec import embed_container as embed_flac_container, extract_container as extract_flac_container, metadata_capacity as flac_metadata_capacity
from .jpeg_dct import (
    JpegDctError,
    backend_available as jpeg_backend_available,
    backend_unavailable_message as jpeg_backend_unavailable_message,
    capacity_with_backend as jpeg_capacity_with_backend,
    embed_with_backend as jpeg_embed_with_backend,
    extract_with_backend as jpeg_extract_with_backend,
)
from .png_codec import PngImage, read_png, write_png


MAGIC = b"OBP1"
HEADER_LEN_SIZE = 4
PREFIX_MAGIC = b"OPX2"
PREFIX_SIZE = 29
SEED_SIZE = 16
PAYLOAD_AAD = b"ObscuraPrimus:v2:payload"
METADATA_AAD = b"ObscuraPrimus:v2:metadata"
DENSITY_CODES = {"maximum": 0, "balanced": 1, "stealth": 2}
DENSITY_NAMES = {value: key for key, value in DENSITY_CODES.items()}
DENSITY_STRIDES = {"maximum": 1, "balanced": 2, "stealth": 4}
ProgressCallback = Callable[[int, str], None]


class StegoError(ValueError):
    pass


class UnsupportedCoverError(StegoError):
    pass


class CapacityError(StegoError):
    pass


class PayloadIntegrityError(StegoError):
    pass


@dataclass(frozen=True)
class EmbedOptions:
    compress: bool = True
    encryption: str = "None"
    password: str = ""
    adaptive: bool = False
    spread: bool = False
    verify_after_embed: bool = False
    stego_key: str = ""
    kdf: str = "PBKDF2-HMAC-SHA256"
    density: str = "maximum"


@dataclass(frozen=True)
class ExtractionResult:
    filename: str
    data: bytes
    metadata: dict


def embed_file(
    cover_path: str,
    secret_path: str,
    output_path: str,
    options: EmbedOptions,
    progress: ProgressCallback | None = None,
) -> None:
    _progress(progress, 3, "Reading secret file...")
    secret_file = Path(secret_path)
    payload = secret_file.read_bytes()
    checksum = _sha256_hex(payload)
    metadata = {
        "filename": secret_file.name,
        "compressed": bool(options.compress),
        "encrypted": options.encryption != "None",
        "algorithm": options.encryption,
        "salt": "",
        "nonce": "",
        "iterations": 0,
        "original_size": len(payload),
        "sha256": checksum,
        "adaptive": bool(options.adaptive),
        "spread": bool(options.spread),
        "kdf": options.kdf,
        "density": _normalize_density(options.density),
    }
    private_metadata = {
        "filename": secret_file.name,
        "original_size": len(payload),
        "sha256": checksum,
    }

    if options.compress:
        _progress(progress, 10, "Compressing payload...")
        payload = compress_data(payload)

    if options.encryption != "None":
        _progress(progress, 18, f"Encrypting payload with {options.encryption}...")
        result = encrypt(payload, options.password, options.encryption, options.kdf, PAYLOAD_AAD)
        payload = result.ciphertext
        private_result = encrypt(
            json.dumps(private_metadata, separators=(",", ":"), sort_keys=True).encode("utf-8"),
            options.password,
            options.encryption,
            options.kdf,
            METADATA_AAD,
        )
        metadata.update(
            {
                "filename": "",
                "original_size": 0,
                "sha256": "",
                "salt": result.salt.hex(),
                "nonce": result.nonce.hex(),
                "iterations": result.iterations,
                "kdf": result.kdf,
                "private_metadata": private_result.ciphertext.hex(),
                "private_salt": private_result.salt.hex(),
                "private_nonce": private_result.nonce.hex(),
                "private_iterations": private_result.iterations,
                "private_kdf": private_result.kdf,
            }
        )

    container = _pack_container(metadata, payload)
    cover_type = _detect_cover_type(cover_path)
    _ensure_cover_type_available(cover_type)
    _progress(progress, 25, f"Embedding into {cover_type.upper()} cover...")

    if cover_type == "bmp":
        _embed_bmp(cover_path, output_path, container, options, progress)
    elif cover_type == "wav":
        _embed_wav(cover_path, output_path, container, options, progress)
    elif cover_type == "png":
        _embed_png(cover_path, output_path, container, options, progress)
    elif cover_type == "jpg":
        _embed_jpeg_dct(cover_path, output_path, container, options, progress)
    elif cover_type == "flac":
        # FLAC stores the container in a discoverable APPLICATION metadata block
        # (not LSB stego). Require AEAD encryption so the payload is not plaintext.
        if options.encryption == "None" or not options.password:
            raise StegoError(
                "FLAC embedding requires encryption with a password. "
                "The payload is stored in a visible APPLICATION metadata block."
            )
        _embed_flac(cover_path, output_path, container)
    else:
        raise UnsupportedCoverError("Unsupported cover file. Use BMP, PNG, or WAV.")

    if options.verify_after_embed:
        _progress(progress, 95, "Verifying embedded payload...")
        extracted = extract_bytes(output_path, options.password, secret_file.name, stego_key=options.stego_key)
        if extracted.data != secret_file.read_bytes():
            raise PayloadIntegrityError("Verify-after-embed failed. Extracted bytes did not match the source secret.")

    _progress(progress, 100, f"Embedded {secret_file.name} into {Path(output_path).name}.")


def extract_file(
    cover_path: str,
    output_dir: str,
    password: str = "",
    output_name: str | None = None,
    stego_key: str = "",
    progress: ProgressCallback | None = None,
) -> ExtractionResult:
    result = extract_bytes(cover_path, password, output_name, stego_key, progress)
    filename = _safe_filename(output_name or result.filename)
    output_path = Path(output_dir) / filename
    _atomic_write(output_path, result.data)
    _progress(progress, 100, f"Extracted hidden file to {output_path}.")
    return ExtractionResult(filename=filename, data=result.data, metadata=result.metadata)


def extract_bytes(
    cover_path: str,
    password: str = "",
    output_name: str | None = None,
    stego_key: str = "",
    progress: ProgressCallback | None = None,
) -> ExtractionResult:
    cover_type = _detect_cover_type(cover_path)
    _ensure_cover_type_available(cover_type)
    _progress(progress, 5, f"Scanning {cover_type.upper()} cover...")

    if cover_type == "bmp":
        container = _extract_bmp(cover_path, password, stego_key, progress)
    elif cover_type == "wav":
        container = _extract_wav(cover_path, password, stego_key, progress)
    elif cover_type == "png":
        container = _extract_png(cover_path, password, stego_key, progress)
    elif cover_type == "jpg":
        container = _extract_jpeg_dct(cover_path, password, stego_key, progress)
    elif cover_type == "flac":
        container = extract_flac_container(cover_path)
    else:
        raise UnsupportedCoverError("Unsupported cover file. Use BMP, PNG, or WAV.")

    _progress(progress, 65, "Parsing hidden payload...")
    metadata, payload = _unpack_container(container)

    if metadata.get("encrypted"):
        _progress(progress, 75, f"Decrypting payload with {metadata.get('algorithm')}...")
        try:
            payload = _decrypt_with_aad_fallback(
                payload,
                password,
                metadata["algorithm"],
                bytes.fromhex(metadata["salt"]),
                bytes.fromhex(metadata["nonce"]),
                int(metadata["iterations"]),
                metadata.get("kdf", "PBKDF2-HMAC-SHA256"),
                primary_aad=PAYLOAD_AAD,
                # Legacy containers may lack the kdf field and used aad=None.
                allow_legacy_null_aad="kdf" not in metadata,
            )
        except CryptoError as exc:
            raise StegoError("Decryption failed. The password may be wrong or the payload is corrupted.") from exc
        private_blob = metadata.get("private_metadata")
        if private_blob:
            try:
                private_data = _decrypt_with_aad_fallback(
                    bytes.fromhex(private_blob),
                    password,
                    metadata["algorithm"],
                    bytes.fromhex(metadata["private_salt"]),
                    bytes.fromhex(metadata["private_nonce"]),
                    int(metadata["private_iterations"]),
                    metadata.get("private_kdf", metadata.get("kdf", "PBKDF2-HMAC-SHA256")),
                    primary_aad=METADATA_AAD,
                    allow_legacy_null_aad="private_kdf" not in metadata and "kdf" not in metadata,
                )
            except CryptoError as exc:
                raise StegoError("Decryption failed. The password may be wrong or the payload is corrupted.") from exc
            metadata.update(json.loads(private_data.decode("utf-8")))

    if metadata.get("compressed"):
        _progress(progress, 85, "Decompressing payload...")
        expected = metadata.get("original_size")
        try:
            expected_int = int(expected) if expected not in (None, "") else None
        except (TypeError, ValueError):
            expected_int = None
        try:
            payload = decompress_data(payload, expected_size=expected_int)
        except ValueError as exc:
            raise StegoError(str(exc)) from exc

    expected_hash = metadata.get("sha256")
    if expected_hash and _sha256_hex(payload) != expected_hash:
        raise PayloadIntegrityError("Checksum validation failed. The extracted payload is corrupted.")

    filename = _safe_filename(output_name or metadata.get("filename") or "extracted.bin")
    return ExtractionResult(filename=filename, data=payload, metadata=metadata)


# Container format overhead: magic + u32 header length + typical min metadata JSON.
# Reserved so capacity estimates match what embed can actually pack.
_CONTAINER_FORMAT_OVERHEAD = len(MAGIC) + HEADER_LEN_SIZE + 256


def estimate_capacity(cover_path: str, adaptive: bool = False, spread: bool = False, density: str = "maximum") -> int:
    cover_type = _detect_cover_type(cover_path)
    _ensure_cover_type_available(cover_type)
    if cover_type == "bmp":
        carriers = _bmp_carrier_count(cover_path, adaptive, density)
        raw_bytes = carriers // 8
    elif cover_type == "wav":
        carriers = _wav_carrier_count(cover_path, adaptive, density)
        raw_bytes = carriers // 8
    elif cover_type == "png":
        carriers = _png_carrier_count(cover_path, adaptive, density)
        raw_bytes = carriers // 8
    elif cover_type == "jpg":
        raw_bytes = max(0, jpeg_capacity_with_backend(cover_path))
    elif cover_type == "flac":
        raw_bytes = max(0, flac_metadata_capacity(cover_path))
    else:
        raise UnsupportedCoverError(_supported_cover_message())
    # Subtract container framing so near-limit embeds do not over-promise.
    return max(0, raw_bytes - _CONTAINER_FORMAT_OVERHEAD)


def estimate_distortion(cover_path: str, payload_bytes: int, adaptive: bool = False, density: str = "maximum") -> dict:
    carriers = estimate_capacity(cover_path, adaptive, density=density)
    changed = min(payload_bytes, carriers) * 4
    return {
        "capacity_bytes": carriers,
        "payload_bytes": payload_bytes,
        "estimated_lsb_changes": changed,
        "estimated_change_ratio": 0.0 if carriers == 0 else changed / max(1, carriers * 8),
    }


def _decrypt_with_aad_fallback(
    ciphertext: bytes,
    password: str,
    algorithm: str,
    salt: bytes,
    nonce: bytes,
    iterations: int,
    kdf: str,
    *,
    primary_aad: bytes,
    allow_legacy_null_aad: bool,
) -> bytes:
    """
    Decrypt with versioned AAD. Current format always uses primary_aad.
    Only when the container looks legacy (missing kdf fields) do we also try aad=None.
    """
    candidates: list[bytes | None] = [primary_aad]
    if allow_legacy_null_aad:
        candidates.append(None)
    last_error: CryptoError | None = None
    for aad in candidates:
        try:
            return decrypt(
                ciphertext,
                password,
                algorithm,
                salt,
                nonce,
                iterations,
                kdf,
                aad,
            )
        except CryptoError as exc:
            last_error = exc
            continue
    assert last_error is not None
    raise last_error


def _pack_container(metadata: dict, payload: bytes) -> bytes:
    header = json.dumps(metadata, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return MAGIC + struct.pack(">I", len(header)) + header + payload


def _unpack_container(container: bytes) -> tuple[dict, bytes]:
    if len(container) < len(MAGIC) + HEADER_LEN_SIZE or not container.startswith(MAGIC):
        raise StegoError("No ObscuraPrimus payload was found in this file.")
    header_len = struct.unpack(">I", container[len(MAGIC) : len(MAGIC) + HEADER_LEN_SIZE])[0]
    header_start = len(MAGIC) + HEADER_LEN_SIZE
    header_end = header_start + header_len
    if header_end > len(container):
        raise StegoError("Hidden payload header is incomplete or corrupted.")
    try:
        metadata = json.loads(container[header_start:header_end].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise StegoError("Hidden payload header is corrupted.") from exc
    return metadata, container[header_end:]


def _embed_bmp(
    cover_path: str,
    output_path: str,
    container: bytes,
    options: EmbedOptions,
    progress: ProgressCallback | None,
) -> None:
    data = bytearray(Path(cover_path).read_bytes())
    pixel_offset = _bmp_pixel_offset(data)
    _write_bits(data, pixel_offset, len(data), container, options, progress, 25, 92)
    _atomic_write(Path(output_path), bytes(data))


def _extract_bmp(cover_path: str, password: str, stego_key: str, progress: ProgressCallback | None) -> bytes:
    data = Path(cover_path).read_bytes()
    pixel_offset = _bmp_pixel_offset(data)
    return _read_container_from_region(data, pixel_offset, len(data), _carrier_secret(password, stego_key), progress)


def _embed_wav(
    cover_path: str,
    output_path: str,
    container: bytes,
    options: EmbedOptions,
    progress: ProgressCallback | None,
) -> None:
    with wave.open(cover_path, "rb") as reader:
        params = reader.getparams()
        frames = bytearray(reader.readframes(reader.getnframes()))

    _write_bits(frames, 0, len(frames), container, options, progress, 25, 92)

    def write_output(temp_path: Path) -> None:
        with wave.open(str(temp_path), "wb") as writer:
            writer.setparams(params)
            writer.writeframes(frames)

    _atomic_write_with(Path(output_path), write_output)


def _extract_wav(cover_path: str, password: str, stego_key: str, progress: ProgressCallback | None) -> bytes:
    with wave.open(cover_path, "rb") as reader:
        frames = reader.readframes(reader.getnframes())
    return _read_container_from_region(frames, 0, len(frames), _carrier_secret(password, stego_key), progress)


def _embed_png(
    cover_path: str,
    output_path: str,
    container: bytes,
    options: EmbedOptions,
    progress: ProgressCallback | None,
) -> None:
    image = read_png(cover_path)
    pixels = bytearray(image.pixels)
    _write_bits(pixels, 0, len(pixels), container, options, progress, 25, 92)
    _atomic_write_with(Path(output_path), lambda temp_path: write_png(image.with_pixels(bytes(pixels)), temp_path))


def _extract_png(cover_path: str, password: str, stego_key: str, progress: ProgressCallback | None) -> bytes:
    image = read_png(cover_path)
    return _read_container_from_region(image.pixels, 0, len(image.pixels), _carrier_secret(password, stego_key), progress)


def _embed_jpeg_dct(
    cover_path: str,
    output_path: str,
    container: bytes,
    options: EmbedOptions,
    progress: ProgressCallback | None,
) -> None:
    fd, temp_name = tempfile.mkstemp(prefix="obp-jpeg-container-", suffix=".bin")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(container)
        _atomic_write_with(
            Path(output_path),
            lambda temp_path: jpeg_embed_with_backend(
                cover_path,
                temp_path,
                temp_name,
                _carrier_secret(options.password, options.stego_key),
            ),
        )
        _progress(progress, 85, "JPEG DCT backend completed coefficient-domain embedding.")
    except JpegDctError as exc:
        raise UnsupportedCoverError(str(exc)) from exc
    finally:
        try:
            os.unlink(temp_name)
        except OSError:
            pass


def _embed_flac(cover_path: str, output_path: str, container: bytes) -> None:
    _atomic_write_with(Path(output_path), lambda temp_path: embed_flac_container(cover_path, temp_path, container))


def _extract_jpeg_dct(cover_path: str, password: str, stego_key: str, progress: ProgressCallback | None) -> bytes:
    fd, temp_name = tempfile.mkstemp(prefix="obp-jpeg-container-", suffix=".bin")
    os.close(fd)
    try:
        jpeg_extract_with_backend(cover_path, temp_name, _carrier_secret(password, stego_key))
        _progress(progress, 55, "JPEG DCT backend extracted coefficient-domain payload.")
        return Path(temp_name).read_bytes()
    except JpegDctError as exc:
        raise UnsupportedCoverError(str(exc)) from exc
    finally:
        try:
            os.unlink(temp_name)
        except OSError:
            pass


def _write_bits(
    mutable: bytearray,
    start: int,
    stop: int,
    container: bytes,
    options: EmbedOptions,
    progress: ProgressCallback | None,
    start_percent: int,
    end_percent: int,
) -> None:
    prefix_indexes = list(range(start, min(start + PREFIX_SIZE * 8, stop)))
    if len(prefix_indexes) < PREFIX_SIZE * 8:
        raise StegoError("Cover file is too small to contain an ObscuraPrimus payload.")

    payload_start = start + PREFIX_SIZE * 8
    seed_salt = os.urandom(SEED_SIZE)
    flags = 0
    if options.adaptive:
        flags |= 1
    if options.spread:
        flags |= 2
    density = _normalize_density(options.density)
    flags |= DENSITY_CODES[density] << 2
    carrier_indexes = _carrier_indexes(
        mutable,
        payload_start,
        stop,
        options.adaptive,
        options.spread,
        _carrier_secret(options.password, options.stego_key),
        seed_salt,
        density,
    )
    prefix = PREFIX_MAGIC + bytes([flags]) + struct.pack(">Q", len(container)) + seed_salt
    stream = container
    required_bits = len(stream) * 8
    if required_bits > len(carrier_indexes):
        capacity = len(carrier_indexes) // 8
        raise CapacityError(f"Payload is too large for this cover. Exact capacity is {capacity:,} bytes.")

    for bit_index, bit in enumerate(_iter_bits(prefix)):
        carrier = prefix_indexes[bit_index]
        mutable[carrier] = (mutable[carrier] & 0xFE) | bit

    last_percent = -1
    for bit_index, bit in enumerate(_iter_bits(stream)):
        carrier = carrier_indexes[bit_index]
        mutable[carrier] = (mutable[carrier] & 0xFE) | bit
        percent = start_percent + math.floor((bit_index + 1) * (end_percent - start_percent) / required_bits)
        if percent != last_percent and percent % 5 == 0:
            _progress(progress, percent, "Writing hidden bits...")
            last_percent = percent


def _read_container_from_region(
    data: bytes,
    start: int,
    stop: int,
    password: str,
    progress: ProgressCallback | None,
) -> bytes:
    prefix_indexes = list(range(start, min(start + PREFIX_SIZE * 8, stop)))
    if len(prefix_indexes) < PREFIX_SIZE * 8:
        raise StegoError("Cover file is too small to contain an ObscuraPrimus payload.")

    prefix = _bits_to_bytes((data[i] & 1 for i in prefix_indexes), PREFIX_SIZE)
    if not prefix.startswith(PREFIX_MAGIC):
        return _read_legacy_container_from_region(data, start, stop, progress)
    flags = prefix[4]
    adaptive = bool(flags & 1)
    spread = bool(flags & 2)
    density = DENSITY_NAMES.get((flags >> 2) & 0b11, "maximum")
    size_bytes = prefix[5:13]
    seed_salt = prefix[13:29]
    payload_size = struct.unpack(">Q", size_bytes)[0]
    payload_start = start + PREFIX_SIZE * 8
    carrier_indexes = _carrier_indexes(data, payload_start, stop, adaptive, spread, password, seed_salt, density)
    required_bits = payload_size * 8
    if payload_size <= 0 or required_bits > len(carrier_indexes):
        raise StegoError("No valid ObscuraPrimus payload size was found.")

    payload_bits = (data[i] & 1 for i in carrier_indexes[:required_bits])
    payload = _bits_to_bytes(payload_bits, payload_size)
    _progress(progress, 60, "Hidden bits recovered.")
    return payload


def _read_legacy_container_from_region(
    data: bytes,
    start: int,
    stop: int,
    progress: ProgressCallback | None,
) -> bytes:
    prefix_indexes = list(range(start, min(start + 9 * 8, stop)))
    prefix = _bits_to_bytes((data[i] & 1 for i in prefix_indexes), 9)
    adaptive = bool(prefix[0] & 1)
    payload_size = struct.unpack(">Q", prefix[1:])[0]
    payload_start = start + 9 * 8
    carrier_indexes = _carrier_indexes(data, payload_start, stop, adaptive, False, "", b"\0" * SEED_SIZE, "maximum")
    required_bits = payload_size * 8
    if payload_size <= 0 or required_bits > len(carrier_indexes):
        raise StegoError("No valid ObscuraPrimus payload size was found.")
    payload_bits = (data[i] & 1 for i in carrier_indexes[:required_bits])
    payload = _bits_to_bytes(payload_bits, payload_size)
    _progress(progress, 60, "Legacy hidden bits recovered.")
    return payload


def _carrier_indexes(
    data: bytes | bytearray,
    start: int,
    stop: int,
    adaptive: bool,
    spread: bool,
    password: str,
    seed_salt: bytes,
    density: str = "maximum",
) -> list[int]:
    if not adaptive:
        indexes = list(range(start, stop))
    else:
        indexes = []
        for index in range(start, stop):
            value = data[index]
            if 8 <= value <= 247:
                indexes.append(index)
    stride = DENSITY_STRIDES[_normalize_density(density)]
    if stride > 1:
        indexes = indexes[::stride]
    if spread or adaptive:
        rng = random.Random(_carrier_seed(password, seed_salt))
        rng.shuffle(indexes)
    return indexes


def _carrier_seed(password: str, salt: bytes) -> int:
    seed = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 120_000, dklen=32)
    return int.from_bytes(seed, "big")


def _carrier_secret(password: str, stego_key: str = "") -> str:
    return stego_key or password


def _normalize_density(density: str) -> str:
    return density if density in DENSITY_CODES else "maximum"


def _iter_bits(data: bytes):
    for byte in data:
        for shift in range(7, -1, -1):
            yield (byte >> shift) & 1


def _bits_to_bytes(bits, expected_len: int) -> bytes:
    output = bytearray()
    current = 0
    count = 0
    for bit in bits:
        current = (current << 1) | bit
        count += 1
        if count == 8:
            output.append(current)
            if len(output) == expected_len:
                return bytes(output)
            current = 0
            count = 0
    raise StegoError("Hidden payload ended unexpectedly.")


def _detect_cover_type(path: str) -> str:
    suffix = Path(path).suffix.lower()
    if suffix == ".bmp":
        return "bmp"
    if suffix == ".wav":
        return "wav"
    if suffix == ".png":
        return "png"
    if suffix in {".jpg", ".jpeg"}:
        return "jpg"
    if suffix == ".flac":
        return "flac"
    return "unknown"


def _ensure_cover_type_available(cover_type: str) -> None:
    if cover_type == "unknown":
        raise UnsupportedCoverError(_supported_cover_message())
    if cover_type == "jpg" and not jpeg_backend_available():
        raise UnsupportedCoverError(jpeg_backend_unavailable_message())


def _supported_cover_message() -> str:
    formats = "BMP, PNG, WAV, or FLAC"
    if jpeg_backend_available():
        formats = "BMP, PNG, WAV, FLAC, or JPEG"
    return f"Unsupported cover file. Use {formats}."


def _bmp_pixel_offset(data: bytes | bytearray) -> int:
    if len(data) < 54 or data[:2] != b"BM":
        raise StegoError("The selected BMP file is invalid.")
    offset = struct.unpack("<I", data[10:14])[0]
    if offset >= len(data):
        raise StegoError("The selected BMP file has an invalid pixel offset.")
    return offset


def _bmp_carrier_count(path: str, adaptive: bool, density: str = "maximum") -> int:
    data = Path(path).read_bytes()
    offset = _bmp_pixel_offset(data)
    if not adaptive:
        return len(_carrier_indexes(data, offset + PREFIX_SIZE * 8, len(data), False, False, "", b"\0" * SEED_SIZE, density))
    return len(_carrier_indexes(data, offset + PREFIX_SIZE * 8, len(data), True, False, "", b"\0" * SEED_SIZE, density))


def _wav_carrier_count(path: str, adaptive: bool, density: str = "maximum") -> int:
    with wave.open(path, "rb") as reader:
        frames = reader.readframes(reader.getnframes())
    if not adaptive:
        return len(_carrier_indexes(frames, PREFIX_SIZE * 8, len(frames), False, False, "", b"\0" * SEED_SIZE, density))
    return len(_carrier_indexes(frames, PREFIX_SIZE * 8, len(frames), True, False, "", b"\0" * SEED_SIZE, density))


def _png_carrier_count(path: str, adaptive: bool, density: str = "maximum") -> int:
    image = read_png(path)
    if not adaptive:
        return len(_carrier_indexes(image.pixels, PREFIX_SIZE * 8, len(image.pixels), False, False, "", b"\0" * SEED_SIZE, density))
    return len(_carrier_indexes(image.pixels, PREFIX_SIZE * 8, len(image.pixels), True, False, "", b"\0" * SEED_SIZE, density))


def _safe_filename(filename: str) -> str:
    base = os.path.basename(filename.strip()) or "extracted.bin"
    return "".join(ch if ch not in '<>:"/\\|?*' else "_" for ch in base)


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, path)
    except Exception:
        try:
            os.unlink(temp_name)
        except OSError:
            pass
        raise


def _atomic_write_with(path: Path, writer: Callable[[Path], None]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    os.close(fd)
    temp_path = Path(temp_name)
    try:
        writer(temp_path)
        with temp_path.open("r+b") as handle:
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
    except Exception:
        try:
            temp_path.unlink()
        except OSError:
            pass
        raise


def _progress(progress: ProgressCallback | None, value: int, message: str) -> None:
    if progress:
        progress(value, message)
