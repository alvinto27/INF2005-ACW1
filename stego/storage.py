"""Share disk-space checks between the library and web application."""

import shutil
from os import PathLike


DISK_SPACE_RESERVE_BYTES = 3 * 1024**3
_PNG_OUTPUT_SLACK_BYTES = 1024**2
_PNG_DEFLATE_BLOCK_BYTES = 16_383
_PNG_DEFLATE_BLOCK_OVERHEAD_BYTES = 5


def _check_free_space(
    path: str | bytes | PathLike[str],
    required_bytes: int,
    reserve_bytes: int,
    error_message: str,
) -> None:
    """Require the specified extra bytes and reserve on the path's filesystem."""
    if required_bytes < 0 or reserve_bytes < 0:
        raise ValueError("disk-space requirements must be non-negative")
    if shutil.disk_usage(path).free < reserve_bytes + required_bytes:
        raise ValueError(error_message)


def _png_output_size_bound(
    decoded_bytes: int,
    height: int,
    source_file_size: int,
) -> int:
    """Bound one PNG, including scanlines, Deflate blocks, chunks, and slack.

    The source file size bounds retained ancillary chunks. Output checks require
    twice this bound because the encoded PNG and final PNG coexist during a
    rewrite.
    """
    if decoded_bytes < 0 or height < 1 or source_file_size < 0:
        raise ValueError("PNG size inputs must be non-negative and height must be positive")
    scanline_bytes = decoded_bytes + height
    block_count = (
        scanline_bytes + _PNG_DEFLATE_BLOCK_BYTES - 1
    ) // _PNG_DEFLATE_BLOCK_BYTES
    return (
        scanline_bytes
        + block_count * _PNG_DEFLATE_BLOCK_OVERHEAD_BYTES
        + source_file_size
        + _PNG_OUTPUT_SLACK_BYTES
    )
