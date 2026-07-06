from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass, replace
from pathlib import Path


PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


class PngError(ValueError):
    pass


@dataclass(frozen=True)
class PngImage:
    width: int
    height: int
    bit_depth: int
    color_type: int
    compression: int
    filter_method: int
    interlace: int
    pixels: bytes
    chunks_before_idat: list[tuple[bytes, bytes]]
    chunks_after_idat: list[tuple[bytes, bytes]]

    def with_pixels(self, pixels: bytes) -> "PngImage":
        return replace(self, pixels=pixels)


def read_png(path: str | Path) -> PngImage:
    raw = Path(path).read_bytes()
    if not raw.startswith(PNG_SIGNATURE):
        raise PngError("The selected PNG file is invalid.")

    offset = len(PNG_SIGNATURE)
    ihdr = None
    idat_parts: list[bytes] = []
    before: list[tuple[bytes, bytes]] = []
    after: list[tuple[bytes, bytes]] = []
    seen_idat = False

    while offset < len(raw):
        if offset + 8 > len(raw):
            raise PngError("PNG chunk table is truncated.")
        length = struct.unpack(">I", raw[offset : offset + 4])[0]
        chunk_type = raw[offset + 4 : offset + 8]
        data_start = offset + 8
        data_end = data_start + length
        crc_end = data_end + 4
        if crc_end > len(raw):
            raise PngError("PNG chunk data is truncated.")
        data = raw[data_start:data_end]
        expected_crc = struct.unpack(">I", raw[data_end:crc_end])[0]
        actual_crc = zlib.crc32(chunk_type + data) & 0xFFFFFFFF
        if expected_crc != actual_crc:
            raise PngError(f"PNG chunk {chunk_type.decode('latin1')} has an invalid CRC.")

        if chunk_type == b"IHDR":
            ihdr = data
            before.append((chunk_type, data))
        elif chunk_type == b"IDAT":
            seen_idat = True
            idat_parts.append(data)
        elif chunk_type == b"IEND":
            after.append((chunk_type, data))
            break
        elif seen_idat:
            after.append((chunk_type, data))
        else:
            before.append((chunk_type, data))
        offset = crc_end

    if ihdr is None or not idat_parts:
        raise PngError("PNG is missing IHDR or IDAT data.")

    width, height, bit_depth, color_type, compression, filter_method, interlace = struct.unpack(">IIBBBBB", ihdr)
    if bit_depth != 8 or color_type not in {0, 2, 4, 6}:
        raise PngError("PNG support is limited to 8-bit grayscale, RGB, grayscale-alpha, or RGBA images.")
    if compression != 0 or filter_method != 0 or interlace != 0:
        raise PngError("Interlaced PNG files are not supported.")

    channels = _channels_for_color_type(color_type)
    stride = width * channels
    inflated = zlib.decompress(b"".join(idat_parts))
    expected = height * (stride + 1)
    if len(inflated) != expected:
        raise PngError("PNG image data has an unexpected size.")

    pixels = _unfilter_scanlines(inflated, width, height, channels)
    return PngImage(width, height, bit_depth, color_type, compression, filter_method, interlace, pixels, before, after)


def write_png(image: PngImage, path: str | Path) -> None:
    channels = _channels_for_color_type(image.color_type)
    stride = image.width * channels
    if len(image.pixels) != stride * image.height:
        raise PngError("PNG pixel buffer size does not match dimensions.")

    scanlines = bytearray()
    for row in range(image.height):
        start = row * stride
        scanlines.append(0)
        scanlines.extend(image.pixels[start : start + stride])

    compressed = zlib.compress(bytes(scanlines), 9)
    output = bytearray(PNG_SIGNATURE)
    for chunk_type, data in image.chunks_before_idat:
        if chunk_type != b"IDAT":
            output.extend(_chunk(chunk_type, data))
    output.extend(_chunk(b"IDAT", compressed))
    for chunk_type, data in image.chunks_after_idat:
        if chunk_type not in {b"IDAT"}:
            output.extend(_chunk(chunk_type, data))
    if not any(chunk_type == b"IEND" for chunk_type, _ in image.chunks_after_idat):
        output.extend(_chunk(b"IEND", b""))
    Path(path).write_bytes(output)


def _unfilter_scanlines(data: bytes, width: int, height: int, channels: int) -> bytes:
    stride = width * channels
    output = bytearray(height * stride)
    source = 0
    for row in range(height):
        filter_type = data[source]
        source += 1
        scanline = bytearray(data[source : source + stride])
        source += stride
        prior_start = (row - 1) * stride
        current_start = row * stride
        for col in range(stride):
            left = scanline[col - channels] if col >= channels else 0
            up = output[prior_start + col] if row > 0 else 0
            up_left = output[prior_start + col - channels] if row > 0 and col >= channels else 0
            if filter_type == 0:
                value = scanline[col]
            elif filter_type == 1:
                value = (scanline[col] + left) & 0xFF
            elif filter_type == 2:
                value = (scanline[col] + up) & 0xFF
            elif filter_type == 3:
                value = (scanline[col] + ((left + up) // 2)) & 0xFF
            elif filter_type == 4:
                value = (scanline[col] + _paeth(left, up, up_left)) & 0xFF
            else:
                raise PngError(f"Unsupported PNG filter type: {filter_type}")
            scanline[col] = value
            output[current_start + col] = value
    return bytes(output)


def _paeth(left: int, up: int, up_left: int) -> int:
    estimate = left + up - up_left
    left_distance = abs(estimate - left)
    up_distance = abs(estimate - up)
    up_left_distance = abs(estimate - up_left)
    if left_distance <= up_distance and left_distance <= up_left_distance:
        return left
    if up_distance <= up_left_distance:
        return up
    return up_left


def _channels_for_color_type(color_type: int) -> int:
    if color_type == 0:
        return 1
    if color_type == 2:
        return 3
    if color_type == 4:
        return 2
    if color_type == 6:
        return 4
    raise PngError(f"Unsupported PNG color type: {color_type}")


def _chunk(chunk_type: bytes, data: bytes) -> bytes:
    crc = zlib.crc32(chunk_type + data) & 0xFFFFFFFF
    return struct.pack(">I", len(data)) + chunk_type + data + struct.pack(">I", crc)
