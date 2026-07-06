from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .jpeg_dct import backend_available
from .stego_engine import estimate_capacity


@dataclass(frozen=True)
class CarrierCodec:
    name: str
    extensions: tuple[str, ...]
    lossless: bool
    implemented: bool
    notes: str

    def matches(self, path: str | Path) -> bool:
        return Path(path).suffix.lower() in self.extensions

    def capacity(self, path: str | Path, adaptive: bool = False, spread: bool = False) -> int:
        if not self.implemented:
            raise NotImplementedError(self.notes)
        return estimate_capacity(str(path), adaptive, spread)


CODECS = (
    CarrierCodec("BMP", (".bmp",), True, True, "Raw bitmap carrier bytes."),
    CarrierCodec("PNG", (".png",), True, True, "Lossless 8-bit non-interlaced PNG pixel carrier bytes."),
    CarrierCodec("WAV", (".wav",), True, True, "PCM audio frame carrier bytes."),
    CarrierCodec("JPEG-DCT", (".jpg", ".jpeg"), False, backend_available(), "Requires OBSCURAPRIMUS_JPEG_DCT_BACKEND coefficient-domain backend."),
    CarrierCodec("FLAC", (".flac",), True, True, "FLAC APPLICATION metadata block carrier that preserves audio frames."),
)


def codec_for_path(path: str | Path) -> CarrierCodec | None:
    for codec in CODECS:
        if codec.matches(path):
            return codec
    return None
