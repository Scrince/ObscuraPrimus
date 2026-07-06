import zlib


def compress_data(data: bytes, level: int = 9) -> bytes:
    return zlib.compress(data, level)


def decompress_data(data: bytes) -> bytes:
    return zlib.decompress(data)
