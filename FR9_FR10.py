import hashlib

# FR9 - HASH VERIFICATION
def calculate_media_hash(media_bytes: bytes) -> str:
    """
    Calculate SHA-256 hash of the supplied media bytes.
    """

    if not isinstance(media_bytes, bytes):
        raise TypeError("media_bytes must be bytes")

    return hashlib.sha256(media_bytes).hexdigest()


def verify_media_hash(
    media_bytes: bytes,
    expected_hash: str,
) -> bool:
    """
    Compare the current media hash with the hash
    stored in the signed payload.
    """

    if not isinstance(media_bytes, bytes):
        raise TypeError("media_bytes must be bytes")

    if not isinstance(expected_hash, str):
        raise TypeError("expected_hash must be a string")


    current_hash = calculate_media_hash(media_bytes)

    return current_hash == expected_hash

# FR10 - VERDICT GENERATION
def generate_verdict(
    signature_valid: bool,
    hash_valid: bool,
) -> tuple[bool, str]:
    """
    Generate the final verification result.

    Returns:
        (True, "Authentic")
        (False, "Tampered")
        (False, "Signature Invalid")
    """

    if not signature_valid:
        return False, "Signature Invalid"

    if not hash_valid:
        return False, "Tampered"

    return True, "Authentic"