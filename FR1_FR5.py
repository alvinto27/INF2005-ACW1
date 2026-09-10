"""PNG loading and least-significant-bit image embedding functions."""

from os import PathLike

import numpy as np
from PIL import Image


class UnSupportedFileType(Exception):
    """Raised when an input file is not a supported image type."""


def load_png_from_path(image_path: str | bytes | PathLike[str]) -> np.ndarray:
    """Load a PNG file as a copied RGB uint8 array."""
    if not isinstance(image_path, (str, bytes, PathLike)):
        raise TypeError("image_path must be a filesystem path")

    try:
        with Image.open(image_path) as image:
            if image.format != "PNG":
                raise UnSupportedFileType(
                    f"Unsupported file type: {image.format or 'unknown'}"
                )

            image.load()
            if image.width < 1 or image.height < 1:
                raise ValueError("Image dimensions must be greater than zero")

            image_array = np.array(image.convert("RGB"), dtype=np.uint8, copy=True)
            if image_array.ndim != 3 or image_array.shape[2] != 3:
                raise ValueError("Decoded image must have three colour channels")

            return image_array

    except UnSupportedFileType:
        raise

    except (OSError, ValueError) as error:
        raise ValueError("Unreadable or corrupted PNG image") from error


def embed_image_payload(img_array: np.ndarray, payload: bytes) -> np.ndarray:
    """Embed payload bits into a copy of the image array's channel values."""
    if not isinstance(img_array, np.ndarray):
        raise TypeError("img_array must be a numpy array")

    if img_array.dtype != np.uint8:
        raise TypeError("img_array must have dtype uint8")

    if not isinstance(payload, bytes):
        raise TypeError("payload must be bytes")

    payload_bits = np.unpackbits(np.frombuffer(payload, dtype=np.uint8))
    flat_img = img_array.flatten()
    if payload_bits.size > flat_img.size:
        raise ValueError("payload is too large for the image capacity")

    flat_img[:payload_bits.size] &= np.uint8(0xFE)
    flat_img[:payload_bits.size] |= payload_bits
    return flat_img.reshape(img_array.shape)


def ascii_to_binary(message: str) -> str:
    """Convert an ASCII string to its eight-bit binary representation."""
    if not isinstance(message, str):
        raise TypeError("message must be a string")

    try:
        return "".join(f"{byte:08b}" for byte in message.encode("ascii"))
    except UnicodeEncodeError as error:
        raise ValueError("message must contain ASCII characters") from error
