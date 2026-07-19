import zlib

# Hard cap on decompressed size to mitigate zip-bomb style payloads.
DEFAULT_MAX_DECOMPRESSED_BYTES = 64 * 1024 * 1024  # 64 MiB


def compress_data(data: bytes, level: int = 9) -> bytes:
    return zlib.compress(data, level)


def decompress_data(
    data: bytes,
    *,
    max_length: int | None = None,
    expected_size: int | None = None,
) -> bytes:
    """
    Decompress zlib data with a hard output size limit.

    If expected_size is provided (from trusted metadata after integrity checks),
    it is used as the cap when smaller than the default maximum.
    """
    limit = DEFAULT_MAX_DECOMPRESSED_BYTES if max_length is None else int(max_length)
    if limit < 0:
        raise ValueError("max_length must be non-negative")
    if expected_size is not None:
        try:
            expected = int(expected_size)
        except (TypeError, ValueError) as exc:
            raise ValueError("expected_size must be an integer") from exc
        if expected < 0:
            raise ValueError("expected_size must be non-negative")
        # Allow a small slack for metadata mistakes, but never above the hard cap.
        limit = min(limit, max(expected, 0) + 64)

    # Streaming inflate so we can stop early on bombs.
    decompressor = zlib.decompressobj()
    try:
        output = decompressor.decompress(data, max_length=limit + 1)
    except zlib.error as exc:
        raise ValueError(f"Decompression failed: {exc}") from exc

    if len(output) > limit:
        raise ValueError(
            f"Decompressed payload exceeds size limit ({limit} bytes)."
        )
    if decompressor.unconsumed_tail or not decompressor.eof:
        # More output would be produced — treat as oversize/corrupt.
        try:
            extra = decompressor.decompress(b"", max_length=1)
        except zlib.error:
            extra = b""
        if extra or decompressor.unconsumed_tail or not decompressor.eof:
            raise ValueError(
                f"Decompressed payload exceeds size limit ({limit} bytes)."
            )
    return output
