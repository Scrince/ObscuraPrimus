from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path


APPLICATION_BLOCK = 2
OBP_APP_ID = b"OBP1"


class FlacCodecError(ValueError):
    pass


@dataclass(frozen=True)
class FlacBlock:
    offset: int
    block_type: int
    is_last: bool
    length: int
    data_offset: int


def inspect_flac(path: str | Path) -> dict:
    data = Path(path).read_bytes()
    blocks = _metadata_blocks(data)
    return {
        "valid_flac": data.startswith(b"fLaC"),
        "metadata_blocks": [
            {"type": block.block_type, "last": block.is_last, "length": block.length, "offset": block.offset}
            for block in blocks
        ],
        "audio_frame_offset": _audio_frame_offset(blocks),
        "obscuraprimus_payload": any(_block_payload(data, block).startswith(OBP_APP_ID) for block in blocks if block.block_type == APPLICATION_BLOCK),
    }


def embed_container(input_path: str | Path, output_path: str | Path, container: bytes) -> None:
    data = bytearray(Path(input_path).read_bytes())
    blocks = _metadata_blocks(data)
    if not blocks:
        raise FlacCodecError("The selected FLAC file does not contain valid metadata blocks.")
    for block in blocks:
        if block.block_type == APPLICATION_BLOCK and _block_payload(data, block).startswith(OBP_APP_ID):
            raise FlacCodecError("This FLAC file already contains an ObscuraPrimus APPLICATION block.")
    last = blocks[-1]
    data[last.offset] = data[last.offset] & 0x7F
    payload = OBP_APP_ID + container
    if len(payload) > 0xFFFFFF:
        raise FlacCodecError("Payload is too large for a single FLAC APPLICATION metadata block.")
    header = bytes([0x80 | APPLICATION_BLOCK]) + len(payload).to_bytes(3, "big")
    insertion = last.offset + 4 + last.length
    output = bytes(data[:insertion]) + header + payload + bytes(data[insertion:])
    Path(output_path).write_bytes(output)


def extract_container(path: str | Path) -> bytes:
    data = Path(path).read_bytes()
    for block in _metadata_blocks(data):
        if block.block_type != APPLICATION_BLOCK:
            continue
        payload = _block_payload(data, block)
        if payload.startswith(OBP_APP_ID):
            return payload[len(OBP_APP_ID) :]
    raise FlacCodecError("No ObscuraPrimus FLAC APPLICATION block was found.")


def metadata_capacity(path: str | Path) -> int:
    _metadata_blocks(Path(path).read_bytes())
    return 0xFFFFFF - len(OBP_APP_ID)


def _metadata_blocks(data: bytes | bytearray) -> list[FlacBlock]:
    if not data.startswith(b"fLaC"):
        raise FlacCodecError("The selected file is not a valid FLAC stream.")
    blocks: list[FlacBlock] = []
    offset = 4
    while offset + 4 <= len(data):
        header = data[offset]
        block_type = header & 0x7F
        is_last = bool(header & 0x80)
        length = int.from_bytes(data[offset + 1 : offset + 4], "big")
        data_offset = offset + 4
        if data_offset + length > len(data):
            raise FlacCodecError("The FLAC metadata block table is truncated.")
        blocks.append(FlacBlock(offset, block_type, is_last, length, data_offset))
        offset = data_offset + length
        if is_last:
            return blocks
    raise FlacCodecError("The FLAC metadata block table has no final block.")


def _block_payload(data: bytes | bytearray, block: FlacBlock) -> bytes:
    return bytes(data[block.data_offset : block.data_offset + block.length])


def _audio_frame_offset(blocks: list[FlacBlock]) -> int:
    if not blocks:
        return 0
    last = blocks[-1]
    return last.data_offset + last.length
