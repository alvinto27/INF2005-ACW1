"""Encode and verify carriers, and provide file wrappers.

The protocol functions here work on a ``CarrierSource``. They decide which
carrier units change and in what order the protocol steps run; the carrier
backend only supplies units. Public file wrappers open the matching media
backend and use its media code and context.
"""

import os
import secrets
import tempfile
from abc import ABC, abstractmethod
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import datetime, timezone
from math import gcd
from os import PathLike, fspath
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import numpy as np

from .bootstrap import (
    BootstrapFields,
    bootstrap_span,
    encode_bootstrap_aad,
    parse_bootstrap,
    serialize_bootstrap,
)
from .bits import (
    _require_bytes,
    _validate_carrier_units,
    _validate_lsb_count,
    _validate_media_code,
    _validate_non_negative_integer,
    bit_sequence_to_bytes,
    read_lsb_bits,
)
from .carrier import (
    DEFAULT_CHUNK_BYTES,
    ArrayCarrier,
    CarrierSource,
    _PackedByteRangeReader,
    _packed_lsb_range_transform,
)
from .constants import (
    AEAD_NONCE_SIZE,
    BOOTSTRAP_LSB_COUNT,
    BOOTSTRAP_START_UNIT,
    GCM_TAG_SIZE,
    MEDIA_ID_SIZE,
    MEDIA_PREFIXES,
    NONCE_SIZE,
    PROTOCOL_VERSION,
    RSA_SIGNATURE_SIZE,
    SESSION_KEY_SIZE,
)
from .crypto import (
    _sign_digest,
    _verify_digest,
    display_rsa_public_key_fingerprint,
    open_with_private_key,
    seal_to_public_key,
    validate_rsa_private_key,
    validate_rsa_public_key,
)
from .layout import (
    EmbeddingLayout,
    MaskedMediaHasher,
    build_embedding_layout,
    encode_signing_input_prefix,
    max_user_payload_length,
    minimum_carrier_units,
    preserved_bit_count,
)
from .media import PngCarrier, UnSupportedFileType, WavCarrier
from .packet import (
    PayloadFileRecord,
    PayloadRecord,
    _payload_record_segments,
    parse_payload_from_reader,
    serialized_record_length,
)


def _validate_carrier_source(source: CarrierSource) -> CarrierSource:
    """Check that source is a carrier backend."""
    if not isinstance(source, CarrierSource):
        raise TypeError("source must be a CarrierSource")
    return source


def _new_masked_hasher(media_code: int, layout: EmbeddingLayout, fixed_byte_count: int = 0) -> MaskedMediaHasher:
    """Make a masked media hasher for the layout and fixed-byte stream."""
    return MaskedMediaHasher(
        media_code,
        layout.lsb_count,
        layout.total_units,
        layout.start_unit,
        layout.footprint,
        layout.bootstrap_span,
        fixed_byte_count,
    )


def _hash_carrier_source(source: CarrierSource, media_code: int, layout: EmbeddingLayout) -> bytes:
    """Compute the masked media hash in one bounded pass over the carrier."""
    hasher = _new_masked_hasher(media_code, layout, source.fixed_byte_count)
    for units, fixed_bytes in source.iter_chunks_with_fixed_bytes():
        hasher.update(units, fixed_bytes)
    return hasher.digest()


class _Staging(ABC):
    """Store private payload bytes behind a common bounded-range interface."""

    @property
    @abstractmethod
    def size(self) -> int:
        """Return the number of staged bytes."""

    @abstractmethod
    def write(self, chunk: bytes) -> None:
        """Append one byte chunk."""

    @abstractmethod
    def read_range(self, offset: int, length: int) -> bytes:
        """Read a bounded byte range."""

    @abstractmethod
    def release(
        self,
        destination: Path | None = None,
        *,
        offset: int = 0,
        length: int | None = None,
    ) -> bytes | None:
        """Release authenticated bytes or atomically publish the staged file."""

    @abstractmethod
    def discard(self) -> None:
        """Close and remove staged data."""


class _MemoryStaging(_Staging):
    """Keep staged bytes in a bytearray without creating filesystem files."""

    def __init__(self) -> None:
        self._buffer = bytearray()
        self._discarded = False

    @property
    def size(self) -> int:
        """Return the current in-memory byte count."""
        return len(self._buffer)

    def write(self, chunk: bytes) -> None:
        """Append bytes to the private in-memory buffer."""
        if self._discarded:
            raise ValueError("staging store is closed")
        self._buffer.extend(_require_bytes(chunk, "chunk"))

    def read_range(self, offset: int, length: int) -> bytes:
        """Read a checked byte range from the private buffer."""
        if self._discarded:
            raise ValueError("staging store is closed")
        if offset < 0 or length < 0 or offset + length > len(self._buffer):
            raise ValueError("staging byte range is out of bounds")
        return bytes(self._buffer[offset:offset + length])

    def release(
        self,
        destination: Path | None = None,
        *,
        offset: int = 0,
        length: int | None = None,
    ) -> bytes | None:
        """Return a selected byte range and clear all staged data."""
        if destination is not None:
            raise ValueError("in-memory staging cannot publish a file")
        if self._discarded:
            raise ValueError("staging store is closed")
        actual_length = len(self._buffer) - offset if length is None else length
        if offset < 0 or actual_length < 0 or offset + actual_length > len(self._buffer):
            raise ValueError("staging byte range is out of bounds")
        released = bytes(self._buffer[offset:offset + actual_length])
        self.discard()
        return released

    def discard(self) -> None:
        """Overwrite and clear all bytes held by this store."""
        if self._discarded:
            return
        for offset in range(0, len(self._buffer), DEFAULT_CHUNK_BYTES):
            end = min(offset + DEFAULT_CHUNK_BYTES, len(self._buffer))
            self._buffer[offset:end] = bytes(end - offset)
        self._buffer.clear()
        self._discarded = True


class _FileStaging(_Staging):
    """Keep staged bytes in one mode-restricted file."""

    def __init__(self, path: Path) -> None:
        self._path: Path | None = path
        descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
        self._file = os.fdopen(descriptor, "w+b")
        self._size = 0

    @property
    def size(self) -> int:
        """Return the staged file byte count."""
        return self._size

    def write(self, chunk: bytes) -> None:
        """Append bytes to the staged file."""
        if self._file.closed:
            raise ValueError("staging store is closed")
        chunk = _require_bytes(chunk, "chunk")
        self._file.seek(self._size)
        self._file.write(chunk)
        self._size += len(chunk)

    def read_range(self, offset: int, length: int) -> bytes:
        """Read a checked byte range from the staged file."""
        if self._file.closed:
            raise ValueError("staging store is closed")
        if offset < 0 or length < 0 or offset + length > self._size:
            raise ValueError("staging byte range is out of bounds")
        self._file.seek(offset)
        data = self._file.read(length)
        if len(data) != length:
            raise OSError("staged file ended before the requested byte range")
        return data

    def release(
        self,
        destination: Path | None = None,
        *,
        offset: int = 0,
        length: int | None = None,
    ) -> bytes | None:
        """Atomically move the complete staged file to its authenticated path."""
        if destination is None or offset != 0 or length is not None:
            raise ValueError("file staging requires a whole-file destination")
        if self._file.closed or self._path is None:
            raise ValueError("staging store is closed")
        self._file.flush()
        self._file.close()
        os.replace(self._path, destination)
        self._path = None
        return None

    def discard(self) -> None:
        """Close and remove the staged file if it still exists."""
        if not self._file.closed:
            self._file.close()
        if self._path is not None:
            try:
                self._path.unlink()
            except FileNotFoundError:
                pass
            self._path = None


class _StagingSession:
    """Own a set of memory stores or a private temporary directory."""

    def __init__(self, file_backed: bool, parent: Path | None = None) -> None:
        self.file_backed = file_backed
        self.parent = parent
        self._temporary_directory: tempfile.TemporaryDirectory | None = None
        self._stores: list[_Staging] = []
        self._closed = False

    @property
    def directory(self) -> Path | None:
        """Return the private directory for file-backed staging."""
        if self._temporary_directory is None:
            return None
        return Path(self._temporary_directory.name)

    def __enter__(self) -> _StagingSession:
        """Create the private directory when the file backend is selected."""
        if self.file_backed and self._temporary_directory is None:
            self._temporary_directory = tempfile.TemporaryDirectory(
                prefix=".stego-staging-",
                dir=None if self.parent is None else os.fspath(self.parent),
            )
        return self

    def __exit__(self, exception_type: object, exception: object, traceback: object) -> None:
        """Discard all stores and remove the private directory."""
        self.close()

    def new_store(self, label: str) -> _Staging:
        """Create and track one staging store."""
        if self._closed:
            raise ValueError("staging session is closed")
        if not self.file_backed:
            store: _Staging = _MemoryStaging()
        else:
            directory = self.directory
            if directory is None:
                raise ValueError("file staging session is not active")
            path = directory / f"{secrets.token_hex(16)}-{label}.tmp"
            store = _FileStaging(path)
        self._stores.append(store)
        return store

    def new_path(self, label: str) -> Path:
        """Return an unused private path for a staged media output."""
        directory = self.directory
        if directory is None:
            raise ValueError("media output staging requires a file-backed session")
        path = directory / f"{secrets.token_hex(16)}-{label}.tmp"
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(descriptor)
        return path

    def close(self) -> None:
        """Discard staged data and clean up the private directory."""
        if self._closed:
            return
        for store in reversed(self._stores):
            store.discard()
        self._stores.clear()
        if self._temporary_directory is not None:
            self._temporary_directory.cleanup()
            self._temporary_directory = None
        self._closed = True


def _plan_layout(total_units: int, receiver_public_key: rsa.RSAPublicKey, start_unit: int, lsb_count: int, media_id: str, user_payload_size: int, metadata: bytes) -> EmbeddingLayout:
    """Check capacity and return the packet geometry before any carrier data is read.

    The record length does not depend on the media hash value, because the hash
    has a fixed size, so the whole geometry is known before the first pass.
    """
    span = bootstrap_span(receiver_public_key)
    minimum_record_length = serialized_record_length(MEDIA_ID_SIZE, 0, 0)
    minimum_units = minimum_carrier_units(span, lsb_count, minimum_record_length)
    if total_units < minimum_units:
        raise ValueError(
            "carrier is too small for the protocol: "
            f"total_units={total_units}, start_unit={start_unit}, "
            f"lsb_count={lsb_count}, minimum_units={minimum_units}"
        )
    if start_unit < span:
        raise ValueError(
            f"start_unit {start_unit} is below the reserved bootstrap region; "
            f"lowest legal start_unit is {span}"
        )
    record_overhead = serialized_record_length(
        len(media_id.encode("utf-8")), 0, len(metadata)
    )
    maximum_user_payload = max_user_payload_length(
        total_units, start_unit, span, lsb_count, record_overhead
    )
    if user_payload_size > maximum_user_payload:
        raise ValueError(
            f"user payload exceeds capacity: user_payload_length={user_payload_size}, "
            f"max_user_payload_length={maximum_user_payload}, total_units={total_units}, "
            f"start_unit={start_unit}, lsb_count={lsb_count}"
        )
    record_length = serialized_record_length(
        len(media_id.encode("utf-8")), user_payload_size, len(metadata)
    )
    return build_embedding_layout(
        total_units, start_unit, lsb_count, record_length + GCM_TAG_SIZE, span
    )


class _PacketReader(_PackedByteRangeReader):
    """Combine staged ciphertext and a fixed signature as bounded packet ranges."""

    def __init__(self, ciphertext: _Staging, signature: bytes) -> None:
        self._ciphertext = ciphertext
        self._signature = signature

    @property
    def size(self) -> int:
        """Return the combined packet byte count."""
        return self._ciphertext.size + len(self._signature)

    def read_range(self, offset: int, length: int) -> bytes:
        """Read the ciphertext or signature bytes overlapping one requested range."""
        if offset < 0 or length < 0 or offset + length > self.size:
            raise ValueError("packet byte range is out of bounds")
        ciphertext_size = self._ciphertext.size
        parts: list[bytes] = []
        if offset < ciphertext_size:
            count = min(length, ciphertext_size - offset)
            parts.append(self._ciphertext.read_range(offset, count))
        else:
            count = 0
        signature_offset = max(0, offset - ciphertext_size)
        signature_count = length - count
        if signature_count:
            parts.append(self._signature[signature_offset:signature_offset + signature_count])
        return b"".join(parts)


class CarrierEncoding:
    """Hold one prepared encoding and embed it during a second carrier pass."""

    def __init__(
        self,
        media_code: int,
        layout: EmbeddingLayout,
        payload: PayloadRecord | PayloadFileRecord,
        media_hash: bytes,
        ciphertext: _Staging,
        signature: bytes,
        envelope: bytes,
        session: _StagingSession,
        owns_session: bool,
        fixed_byte_count: int = 0,
    ) -> None:
        """Keep staged ciphertext and bounded packet readers for embedding."""
        self.layout = layout
        self.payload = payload
        self._media_hash = media_hash
        self._ciphertext = ciphertext
        self._signature = signature
        self._envelope = envelope
        self._session = session
        self._owns_session = owns_session
        self._closed = False
        self._bootstrap_transform = _packed_lsb_range_transform(
            BOOTSTRAP_START_UNIT,
            envelope,
            len(envelope) * 8,
            BOOTSTRAP_LSB_COUNT,
        )
        self._packet_transform = _packed_lsb_range_transform(
            layout.start_unit,
            _PacketReader(ciphertext, signature),
            layout.footprint * layout.lsb_count,
            layout.lsb_count,
        )
        self._rehash = _new_masked_hasher(media_code, layout, fixed_byte_count)
        self._next_unit = 0

    @property
    def _packet(self) -> bytes:
        """Return packet bytes for legacy internal tests that inspect this field."""
        return self._ciphertext.read_range(0, self._ciphertext.size) + self._signature

    def __enter__(self) -> CarrierEncoding:
        """Return this resource for use in a context manager."""
        return self

    def __exit__(self, exception_type: object, exception: object, traceback: object) -> None:
        """Release staged ciphertext when the embedding operation ends."""
        self.close()

    def embed_chunk(self, chunk_start: int, units: np.ndarray) -> np.ndarray:
        """Return a copy of an original chunk with bootstrap and packet bits embedded."""
        units = _validate_carrier_units(units)
        chunk_start = _validate_non_negative_integer(chunk_start, "chunk_start")
        if chunk_start != self._next_unit:
            raise ValueError("carrier chunks must be embedded once each, in order")
        self._rehash.update(units)
        chunk_end = chunk_start + int(units.size)
        result = self._bootstrap_transform(chunk_start, units)
        result = self._packet_transform(chunk_start, result)
        self._next_unit = chunk_end
        return result

    def update_fixed_bytes(self, chunk_start: int, units: np.ndarray, fixed_bytes: bytes) -> None:
        """Hash fixed bytes paired with the current original carrier chunk."""
        chunk_start = _validate_non_negative_integer(chunk_start, "chunk_start")
        units = _validate_carrier_units(units)
        if chunk_start != self._next_unit:
            raise ValueError("fixed bytes must match the current carrier chunk")
        self._rehash.update_fixed_bytes(_require_bytes(fixed_bytes, "fixed_bytes"))

    def finish(self) -> None:
        """Check that the second pass covered unchanged carrier data, then close."""
        try:
            if self._rehash.digest() != self._media_hash:
                raise ValueError(
                    "carrier changed between encoding passes; the output is not valid"
                )
        finally:
            self.close()

    def close(self) -> None:
        """Discard staged ciphertext and close an owned staging session."""
        if self._closed:
            return
        self._ciphertext.discard()
        if self._owns_session:
            self._session.close()
        self._closed = True


def _byte_chunks(data: bytes) -> Iterator[bytes]:
    """Yield an existing bytes payload in bounded slices."""
    for offset in range(0, len(data), DEFAULT_CHUNK_BYTES):
        yield data[offset:offset + DEFAULT_CHUNK_BYTES]


def _file_payload_chunks(path: Path, expected_size: int) -> Iterator[bytes]:
    """Yield exactly the stat-reported file length and reject size changes."""
    with path.open("rb") as payload_file:
        remaining = expected_size
        while remaining:
            chunk = payload_file.read(min(DEFAULT_CHUNK_BYTES, remaining))
            if not chunk:
                raise ValueError("payload file changed while it was read")
            remaining -= len(chunk)
            yield chunk
        if payload_file.read(1):
            raise ValueError("payload file changed while it was read")


def _stream_encrypt(
    key: bytes,
    nonce: bytes,
    aad: bytes,
    plaintext_chunks: Iterator[bytes],
    ciphertext: _Staging,
    signing_hasher: hashes.Hash,
) -> None:
    """Encrypt chunks once, staging ciphertext and updating its signing hash."""
    encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
    encryptor.authenticate_additional_data(aad)
    for chunk in plaintext_chunks:
        encrypted = encryptor.update(chunk)
        ciphertext.write(encrypted)
        signing_hasher.update(encrypted)
    final_bytes = encryptor.finalize()
    ciphertext.write(final_bytes)
    signing_hasher.update(final_bytes)
    tag = encryptor.tag
    ciphertext.write(tag)
    signing_hasher.update(tag)


def _iter_record_chunks(
    record: PayloadRecord | PayloadFileRecord,
    payload_chunks: Iterator[bytes],
) -> Iterator[bytes]:
    """Yield serialized fields and bounded payload chunks in wire order."""
    prefix, expected_size, suffix = _payload_record_segments(record)
    yield prefix
    actual_size = 0
    for chunk in payload_chunks:
        chunk = _require_bytes(chunk, "payload chunk")
        actual_size += len(chunk)
        if actual_size > expected_size:
            raise ValueError("payload file changed while it was read")
        yield chunk
    if actual_size != expected_size:
        raise ValueError("payload file changed while it was read")
    yield suffix


def _prepare_carrier_encoding(
    source: CarrierSource,
    media_code: int,
    media_context: bytes,
    signing_private_key: rsa.RSAPrivateKey,
    receiver_public_key: rsa.RSAPublicKey,
    start_unit: int,
    lsb_count: int,
    payload_size: int,
    metadata: bytes,
    payload_record_factory: Callable[[str, int, bytes, bytes], PayloadRecord | PayloadFileRecord],
    payload_chunks_factory: Callable[[], Iterator[bytes]],
    session: _StagingSession,
    owns_session: bool,
) -> CarrierEncoding:
    """Prepare a streamed signed packet using the selected staging backend."""
    source = _validate_carrier_source(source)
    media_code = _validate_media_code(media_code)
    media_context = _require_bytes(media_context, "media_context")
    signing_private_key = validate_rsa_private_key(signing_private_key)
    receiver_public_key = validate_rsa_public_key(receiver_public_key)
    start_unit = _validate_non_negative_integer(start_unit, "start_unit")
    lsb_count = _validate_lsb_count(lsb_count)
    payload_size = _validate_non_negative_integer(payload_size, "user_payload_size")
    metadata = _require_bytes(metadata, "metadata")
    try:
        metadata.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("metadata must contain valid UTF-8 bytes") from error

    total_units = _validate_non_negative_integer(source.total_units, "total_units")
    media_id = f"{MEDIA_PREFIXES[media_code]}-{secrets.token_hex(16)}"
    layout = _plan_layout(
        total_units, receiver_public_key, start_unit, lsb_count, media_id, payload_size, metadata
    )
    timestamp = int(datetime.now(timezone.utc).timestamp())
    nonce = secrets.token_bytes(NONCE_SIZE)
    media_hash = _hash_carrier_source(source, media_code, layout)
    payload = payload_record_factory(media_id, timestamp, nonce, media_hash)
    ciphertext = session.new_store("ciphertext")
    session_key = secrets.token_bytes(SESSION_KEY_SIZE)
    aead_nonce = secrets.token_bytes(AEAD_NONCE_SIZE)
    fields = BootstrapFields(
        PROTOCOL_VERSION, lsb_count, start_unit, layout.ciphertext_length,
        session_key, aead_nonce,
    )
    signing_hasher = hashes.Hash(hashes.SHA256())
    signing_hasher.update(encode_signing_input_prefix(media_code, media_context, layout))
    _stream_encrypt(
        session_key,
        aead_nonce,
        encode_bootstrap_aad(fields),
        _iter_record_chunks(payload, payload_chunks_factory()),
        ciphertext,
        signing_hasher,
    )
    if ciphertext.size != layout.ciphertext_length:
        raise ValueError("AES-GCM ciphertext has an unexpected length")
    signature = _sign_digest(signing_hasher.finalize(), signing_private_key)
    envelope = seal_to_public_key(serialize_bootstrap(fields), receiver_public_key)
    if len(envelope) * 8 != layout.bootstrap_span:
        raise ValueError("bootstrap envelope has an unexpected span")
    return CarrierEncoding(
        media_code,
        layout,
        payload,
        media_hash,
        ciphertext,
        signature,
        envelope,
        session,
        owns_session,
        source.fixed_byte_count,
    )


def prepare_carrier_encoding(source: CarrierSource, media_code: int, media_context: bytes, signing_private_key: rsa.RSAPrivateKey, receiver_public_key: rsa.RSAPublicKey, start_unit: int, lsb_count: int, user_payload: bytes, metadata: bytes) -> CarrierEncoding:
    """Prepare an in-memory streamed encoding for a bytes payload."""
    user_payload = _require_bytes(user_payload, "user_payload")
    metadata = _require_bytes(metadata, "metadata")
    payload = user_payload
    session = _StagingSession(False)
    session.__enter__()
    try:
        return _prepare_carrier_encoding(
            source,
            media_code,
            media_context,
            signing_private_key,
            receiver_public_key,
            start_unit,
            lsb_count,
            len(payload),
            metadata,
            lambda media_id, timestamp, nonce, media_hash: PayloadRecord(
                media_id, timestamp, nonce, media_hash, payload, metadata
            ),
            lambda: _byte_chunks(payload),
            session,
            True,
        )
    except BaseException:
        session.close()
        raise


def prepare_carrier_encoding_from_payload_path(source: CarrierSource, media_code: int, media_context: bytes, signing_private_key: rsa.RSAPrivateKey, receiver_public_key: rsa.RSAPublicKey, start_unit: int, lsb_count: int, payload_path: str | bytes | PathLike[str], metadata: bytes) -> CarrierEncoding:
    """Prepare a file-backed encoding while reading payload bytes in chunks."""
    path = Path(os.fsdecode(fspath(payload_path)))
    payload_size = path.stat().st_size
    metadata = _require_bytes(metadata, "metadata")
    session = _StagingSession(True)
    session.__enter__()
    try:
        return _prepare_carrier_encoding(
            source,
            media_code,
            media_context,
            signing_private_key,
            receiver_public_key,
            start_unit,
            lsb_count,
            payload_size,
            metadata,
            lambda media_id, timestamp, nonce, media_hash: PayloadFileRecord(
                media_id, timestamp, nonce, media_hash, payload_size, metadata
            ),
            lambda: _file_payload_chunks(path, payload_size),
            session,
            True,
        )
    except BaseException:
        session.close()
        raise


def encode_carrier(carrier_units: np.ndarray, media_code: int, media_context: bytes, signing_private_key: rsa.RSAPrivateKey, receiver_public_key: rsa.RSAPublicKey, start_unit: int, lsb_count: int, user_payload: bytes, metadata: bytes) -> tuple[np.ndarray, EmbeddingLayout, PayloadRecord]:
    """Encrypt, sign, and embed a record with a receiver bootstrap."""
    source = ArrayCarrier(_validate_carrier_units(carrier_units))
    encoding = prepare_carrier_encoding(
        source, media_code, media_context, signing_private_key, receiver_public_key,
        start_unit, lsb_count, user_payload, metadata,
    )
    try:
        encoded = source.rewrite(encoding.embed_chunk)
        encoding.finish()
        return encoded, encoding.layout, encoding.payload
    finally:
        encoding.close()


@dataclass(frozen=True)
class VerificationResult:
    """Keep a carrier's verification verdict and the details that support it."""
    valid: bool
    verdict: str
    detail: str
    payload: PayloadRecord | PayloadFileRecord | None
    key_fingerprint: str | None
    start_unit: int | None
    lsb_count: int | None
    preserved_bits: int | None
    preserved_ratio: float | None
    payload_path: Path | None = None
    protocol_version: int | None = None


@dataclass
class _VerificationContext:
    """Hold verification fields as the decoder recovers them."""

    protocol_version: int | None = None
    start_unit: int | None = None
    lsb_count: int | None = None
    preserved_bits: int | None = None
    preserved_ratio: float | None = None
    sender_key_fingerprint: str | None = None


def _failure_result(
    verdict: str,
    detail: str,
    context: _VerificationContext | None = None,
) -> VerificationResult:
    """Make a failed result that keeps known context but never payload data."""
    known = context or _VerificationContext()
    return VerificationResult(
        False,
        verdict,
        detail,
        None,
        known.sender_key_fingerprint,
        known.start_unit,
        known.lsb_count,
        known.preserved_bits,
        known.preserved_ratio,
        None,
        known.protocol_version,
    )


def _context_for_sender_key(
    sender_public_key: rsa.RSAPublicKey,
) -> _VerificationContext:
    """Return the sender fingerprint when the supplied key is valid."""
    context = _VerificationContext()
    try:
        valid_key = validate_rsa_public_key(sender_public_key)
    except (TypeError, ValueError):
        return context
    context.sender_key_fingerprint = display_rsa_public_key_fingerprint(valid_key)
    return context


def _stream_decrypt(
    key: bytes,
    nonce: bytes,
    aad: bytes,
    ciphertext: _Staging,
    plaintext: _Staging,
) -> None:
    """Decrypt a staged ciphertext into private staging before tag validation."""
    if ciphertext.size < GCM_TAG_SIZE:
        raise ValueError("ciphertext_length must include a 16-byte GCM tag")
    tag = ciphertext.read_range(ciphertext.size - GCM_TAG_SIZE, GCM_TAG_SIZE)
    decryptor = Cipher(
        algorithms.AES(key), modes.GCM(nonce, tag)
    ).decryptor()
    decryptor.authenticate_additional_data(aad)
    body_size = ciphertext.size - GCM_TAG_SIZE
    for offset in range(0, body_size, DEFAULT_CHUNK_BYTES):
        encrypted = ciphertext.read_range(
            offset, min(DEFAULT_CHUNK_BYTES, body_size - offset)
        )
        plaintext.write(decryptor.update(encrypted))
    plaintext.write(decryptor.finalize())


def _decode_carrier_source(
    source: CarrierSource,
    media_code: int,
    media_context: bytes,
    sender_public_key: rsa.RSAPublicKey,
    receiver_private_key: rsa.RSAPrivateKey,
    session: _StagingSession,
    payload_output_path: Path | None,
) -> VerificationResult:
    """Run the common packet, signature, decryption, and verdict sequence."""
    source = _validate_carrier_source(source)
    media_code = _validate_media_code(media_code)
    media_context = _require_bytes(media_context, "media_context")
    sender_public_key = validate_rsa_public_key(sender_public_key)
    context = _VerificationContext(
        sender_key_fingerprint=display_rsa_public_key_fingerprint(sender_public_key)
    )
    receiver_private_key = validate_rsa_private_key(receiver_private_key)
    total_units = _validate_non_negative_integer(source.total_units, "total_units")
    span = bootstrap_span(receiver_private_key)
    try:
        bootstrap_units = source.read_units(
            BOOTSTRAP_START_UNIT, min(span, total_units - BOOTSTRAP_START_UNIT)
        )
        envelope_bits = read_lsb_bits(bootstrap_units, span, BOOTSTRAP_LSB_COUNT)
        envelope = bit_sequence_to_bytes(envelope_bits)
    except (ValueError, OSError) as error:
        return _failure_result("Cannot Verify", str(error), context)
    try:
        bootstrap_plaintext = open_with_private_key(envelope, receiver_private_key)
    except ValueError:
        return _failure_result(
            "Payload Missing",
            "nothing was readable with the supplied receiver private key",
            context,
        )
    # Keep only the version byte before validation; other raw bytes can have
    # a different meaning in another version or in a malformed bootstrap.
    if bootstrap_plaintext:
        context.protocol_version = bootstrap_plaintext[0]
    try:
        fields = parse_bootstrap(bootstrap_plaintext)
    except ValueError as error:
        return _failure_result("Cannot Verify", str(error), context)
    context.protocol_version = fields.version
    context.start_unit = fields.start_unit
    context.lsb_count = fields.lsb_count
    if fields.ciphertext_length < GCM_TAG_SIZE:
        return _failure_result(
            "Cannot Verify", "ciphertext_length must include a 16-byte GCM tag", context
        )
    if fields.start_unit < span:
        return _failure_result(
            "Wrong Start Location",
            f"start_unit {fields.start_unit} is below bootstrap_span {span}",
            context,
        )
    try:
        layout = build_embedding_layout(
            total_units,
            fields.start_unit,
            fields.lsb_count,
            fields.ciphertext_length,
            span,
        )
    except ValueError as error:
        return _failure_result("Wrong Start Location", str(error), context)

    context.preserved_bits = preserved_bit_count(
        layout.total_units,
        layout.footprint,
        layout.lsb_count,
        layout.bootstrap_span,
    )
    total_bits = layout.total_units * 8
    context.preserved_ratio = (
        context.preserved_bits / total_bits if total_bits else 0.0
    )
    ciphertext = session.new_store("ciphertext")
    signature_buffer = bytearray()
    signing_hasher = hashes.Hash(hashes.SHA256())
    signing_hasher.update(encode_signing_input_prefix(media_code, media_context, layout))
    packet_bits_length = (layout.ciphertext_length + RSA_SIGNATURE_SIZE) * 8
    try:
        unit_alignment = 8 // gcd(layout.lsb_count, 8)
        chunk_units = max(
            unit_alignment,
            DEFAULT_CHUNK_BYTES // unit_alignment * unit_alignment,
        )
        packet_bit_offset = 0
        for unit_offset in range(0, layout.footprint, chunk_units):
            unit_count = min(chunk_units, layout.footprint - unit_offset)
            units = source.read_units(layout.start_unit + unit_offset, unit_count)
            if layout.lsb_count == 8:
                if units.size < unit_count:
                    raise ValueError("requested bit length exceeds carrier capacity")
                packet_bit_count = min(
                    unit_count * 8, packet_bits_length - packet_bit_offset
                )
                packet_chunk = units[:unit_count].tobytes()[:packet_bit_count // 8]
            else:
                chunk_bits = read_lsb_bits(
                    units, unit_count * layout.lsb_count, layout.lsb_count
                )
                packet_bit_count = min(
                    chunk_bits.size, packet_bits_length - packet_bit_offset
                )
                if np.any(chunk_bits[packet_bit_count:] != 0):
                    return _failure_result(
                        "Cannot Verify", "alignment padding must be zero", context
                    )
                packet_chunk = np.packbits(
                    chunk_bits[:packet_bit_count], bitorder="big"
                ).tobytes()
            ciphertext_remaining = layout.ciphertext_length - ciphertext.size
            ciphertext_count = min(len(packet_chunk), ciphertext_remaining)
            if ciphertext_count:
                ciphertext_chunk = packet_chunk[:ciphertext_count]
                ciphertext.write(ciphertext_chunk)
                signing_hasher.update(ciphertext_chunk)
            if ciphertext_count < len(packet_chunk):
                signature_buffer.extend(packet_chunk[ciphertext_count:])
            packet_bit_offset += packet_bit_count
    except (ValueError, OSError) as error:
        return _failure_result("Cannot Verify", str(error), context)

    signature = bytes(signature_buffer)
    if not _verify_digest(signing_hasher.finalize(), signature, sender_public_key):
        return _failure_result(
            "Signature Invalid", "RSA-PSS signature verification failed", context
        )

    plaintext = session.new_store("plaintext")
    try:
        _stream_decrypt(
            fields.session_key,
            fields.aead_nonce,
            encode_bootstrap_aad(fields),
            ciphertext,
            plaintext,
        )
    except InvalidTag:
        return _failure_result(
            "Cannot Decrypt",
            "signature verified but the AES-GCM tag rejected the body",
            context,
        )
    try:
        payload, user_payload_offset = parse_payload_from_reader(
            plaintext.size, plaintext.read_range
        )
    except (ValueError, OSError) as error:
        return _failure_result("Cannot Verify", str(error), context)
    try:
        calculated_hash = _hash_carrier_source(source, media_code, layout)
    except (ValueError, OSError) as error:
        return _failure_result(
            "Cannot Verify",
            f"carrier could not be read for the masked media hash: {error}",
            context,
        )
    if calculated_hash != payload.media_hash:
        return _failure_result("Tampered", "masked media hash mismatch", context)

    preserved_bits = context.preserved_bits
    ratio = context.preserved_ratio
    if payload_output_path is None:
        user_payload = plaintext.release(
            offset=user_payload_offset, length=payload.user_payload_size
        )
        if user_payload is None:
            raise ValueError("in-memory staging did not release payload bytes")
        released_payload: PayloadRecord | PayloadFileRecord = PayloadRecord(
            payload.media_id,
            payload.timestamp,
            payload.nonce,
            payload.media_hash,
            user_payload,
            payload.metadata,
        )
        released_path = None
    else:
        payload_file = session.new_store("authenticated-payload")
        for offset in range(0, payload.user_payload_size, DEFAULT_CHUNK_BYTES):
            chunk = plaintext.read_range(
                user_payload_offset + offset,
                min(DEFAULT_CHUNK_BYTES, payload.user_payload_size - offset),
            )
            payload_file.write(chunk)
        payload_file.release(payload_output_path)
        released_payload = payload
        released_path = payload_output_path
    return VerificationResult(
        True,
        "Authentic",
        "signature and masked media hash are valid under the supplied public key",
        released_payload,
        context.sender_key_fingerprint,
        layout.start_unit,
        layout.lsb_count,
        preserved_bits,
        ratio,
        released_path,
        context.protocol_version,
    )


def decode_carrier_source(source: CarrierSource, media_code: int, media_context: bytes, sender_public_key: rsa.RSAPublicKey, receiver_private_key: rsa.RSAPrivateKey) -> VerificationResult:
    """Recover and verify a packet using memory-only staging."""
    with _StagingSession(False) as session:
        return _decode_carrier_source(
            source, media_code, media_context, sender_public_key,
            receiver_private_key, session, None,
        )


def decode_carrier_source_to_payload_path(source: CarrierSource, media_code: int, media_context: bytes, sender_public_key: rsa.RSAPublicKey, receiver_private_key: rsa.RSAPrivateKey, payload_output_path: str | bytes | PathLike[str]) -> VerificationResult:
    """Verify a carrier and publish payload bytes only after an Authentic result."""
    output_path = Path(os.fsdecode(fspath(payload_output_path)))
    with _StagingSession(True, output_path.parent) as session:
        return _decode_carrier_source(
            source, media_code, media_context, sender_public_key,
            receiver_private_key, session, output_path,
        )


def decode_carrier(carrier_units: np.ndarray, media_code: int, media_context: bytes, sender_public_key: rsa.RSAPublicKey, receiver_private_key: rsa.RSAPrivateKey) -> VerificationResult:
    """Recover and verify an encrypted packet using the receiver's private key."""
    source = ArrayCarrier(_validate_carrier_units(carrier_units))
    return decode_carrier_source(source, media_code, media_context, sender_public_key, receiver_private_key)


def _paths_resolve_same(first_path: str | bytes | PathLike[str], second_path: str | bytes | PathLike[str]) -> bool:
    """Check whether two filesystem paths point to the same place."""
    for path in (first_path, second_path):
        if not isinstance(path, (str, bytes, PathLike)):
            raise TypeError("path must be a filesystem path")
    return os.path.normcase(os.path.realpath(os.fsdecode(fspath(first_path)))) == os.path.normcase(os.path.realpath(os.fsdecode(fspath(second_path))))


def encode_png(input_path: str | bytes | PathLike[str], output_path: str | bytes | PathLike[str], signing_private_key: rsa.RSAPrivateKey, receiver_public_key: rsa.RSAPublicKey, start_unit: int, lsb_count: int, user_payload: bytes, metadata: bytes) -> tuple[EmbeddingLayout, PayloadRecord]:
    """Encode a signed packet into an RGB or RGBA PNG file and save it."""
    if _paths_resolve_same(input_path, output_path):
        raise ValueError("input and output paths must be different")
    source = PngCarrier(input_path)
    encoding = prepare_carrier_encoding(
        source, source.media_code, source.media_context, signing_private_key,
        receiver_public_key, start_unit, lsb_count, user_payload, metadata,
    )
    try:
        source.rewrite_to_path(output_path, encoding.embed_chunk, encoding.update_fixed_bytes)
        encoding.finish()
        return encoding.layout, encoding.payload
    except BaseException:
        _remove_incomplete_output(output_path)
        raise
    finally:
        encoding.close()


def verify_png(input_path: str | bytes | PathLike[str], sender_public_key: rsa.RSAPublicKey, receiver_private_key: rsa.RSAPrivateKey) -> VerificationResult:
    """Verify an RGB or RGBA PNG using sender and receiver keys."""
    try:
        source = PngCarrier(input_path)
    except (OSError, ValueError, UnSupportedFileType) as error:
        return _failure_result(
            "Cannot Verify", str(error), _context_for_sender_key(sender_public_key)
        )
    return decode_carrier_source(
        source, source.media_code, source.media_context,
        sender_public_key, receiver_private_key,
    )


def _remove_incomplete_output(output_path: str | bytes | PathLike[str]) -> None:
    """Delete an output file left by a failed encode, keeping the original error if this fails."""
    try:
        os.remove(output_path)
    except OSError:
        pass


def encode_wav(input_path: str | bytes | PathLike[str], output_path: str | bytes | PathLike[str], signing_private_key: rsa.RSAPrivateKey, receiver_public_key: rsa.RSAPublicKey, start_unit: int, lsb_count: int, user_payload: bytes, metadata: bytes) -> tuple[EmbeddingLayout, PayloadRecord]:
    """Encode a signed packet into an uncompressed PCM WAV file and save it."""
    if _paths_resolve_same(input_path, output_path):
        raise ValueError("input and output paths must be different")
    source = WavCarrier(input_path)
    encoding = prepare_carrier_encoding(
        source, source.media_code, source.media_context, signing_private_key,
        receiver_public_key, start_unit, lsb_count, user_payload, metadata,
    )
    try:
        source.rewrite_to_path(output_path, encoding.embed_chunk, encoding.update_fixed_bytes)
        encoding.finish()
        return encoding.layout, encoding.payload
    except BaseException:
        _remove_incomplete_output(output_path)
        raise
    finally:
        encoding.close()


def _encode_file_from_payload_path(
    source: PngCarrier | WavCarrier,
    output_path: str | bytes | PathLike[str],
    signing_private_key: rsa.RSAPrivateKey,
    receiver_public_key: rsa.RSAPublicKey,
    start_unit: int,
    lsb_count: int,
    payload_path: str | bytes | PathLike[str],
    metadata: bytes,
) -> tuple[EmbeddingLayout, PayloadFileRecord]:
    """Encode a file payload and atomically publish the staged carrier."""
    payload_file_path = Path(os.fsdecode(fspath(payload_path)))
    payload_size = payload_file_path.stat().st_size
    output_file_path = Path(os.fsdecode(fspath(output_path)))
    with _StagingSession(True, output_file_path.parent) as session:
        encoding = _prepare_carrier_encoding(
            source,
            source.media_code,
            source.media_context,
            signing_private_key,
            receiver_public_key,
            start_unit,
            lsb_count,
            payload_size,
            metadata,
            lambda media_id, timestamp, nonce, media_hash: PayloadFileRecord(
                media_id, timestamp, nonce, media_hash, payload_size, metadata
            ),
            lambda: _file_payload_chunks(payload_file_path, payload_size),
            session,
            False,
        )
        staged_carrier = session.new_path("carrier")
        try:
            source.rewrite_to_path(
                staged_carrier, encoding.embed_chunk, encoding.update_fixed_bytes
            )
            encoding.finish()
            os.replace(staged_carrier, output_file_path)
            return encoding.layout, encoding.payload
        finally:
            encoding.close()


def encode_png_from_payload_path(
    input_path: str | bytes | PathLike[str],
    output_path: str | bytes | PathLike[str],
    signing_private_key: rsa.RSAPrivateKey,
    receiver_public_key: rsa.RSAPublicKey,
    start_unit: int,
    lsb_count: int,
    payload_path: str | bytes | PathLike[str],
    metadata: bytes,
    *,
    carrier_source: PngCarrier | None = None,
) -> tuple[EmbeddingLayout, PayloadFileRecord]:
    """Stream a payload file into a PNG, optionally reusing its validated source."""
    if _paths_resolve_same(input_path, output_path):
        raise ValueError("input and output paths must be different")
    if carrier_source is not None:
        if not isinstance(carrier_source, PngCarrier):
            raise TypeError("carrier_source must be a PngCarrier")
        if not _paths_resolve_same(carrier_source.path, input_path):
            raise ValueError("carrier_source must be loaded from input_path")
    source = carrier_source if carrier_source is not None else PngCarrier(input_path)
    return _encode_file_from_payload_path(
        source, output_path, signing_private_key, receiver_public_key,
        start_unit, lsb_count, payload_path, metadata,
    )


def encode_wav_from_payload_path(input_path: str | bytes | PathLike[str], output_path: str | bytes | PathLike[str], signing_private_key: rsa.RSAPrivateKey, receiver_public_key: rsa.RSAPublicKey, start_unit: int, lsb_count: int, payload_path: str | bytes | PathLike[str], metadata: bytes) -> tuple[EmbeddingLayout, PayloadFileRecord]:
    """Stream a payload file into an uncompressed PCM WAV carrier."""
    if _paths_resolve_same(input_path, output_path):
        raise ValueError("input and output paths must be different")
    return _encode_file_from_payload_path(
        WavCarrier(input_path), output_path, signing_private_key,
        receiver_public_key, start_unit, lsb_count, payload_path, metadata,
    )


def verify_png_to_payload_path(input_path: str | bytes | PathLike[str], sender_public_key: rsa.RSAPublicKey, receiver_private_key: rsa.RSAPrivateKey, payload_output_path: str | bytes | PathLike[str]) -> VerificationResult:
    """Verify an RGB or RGBA PNG and publish payload bytes after authentication."""
    try:
        source = PngCarrier(input_path)
    except (OSError, ValueError, UnSupportedFileType) as error:
        return _failure_result(
            "Cannot Verify", str(error), _context_for_sender_key(sender_public_key)
        )
    return decode_carrier_source_to_payload_path(
        source, source.media_code, source.media_context, sender_public_key,
        receiver_private_key, payload_output_path,
    )


def verify_wav(input_path: str | bytes | PathLike[str], sender_public_key: rsa.RSAPublicKey, receiver_private_key: rsa.RSAPrivateKey) -> VerificationResult:
    """Verify an uncompressed PCM WAV using sender and receiver keys."""
    try:
        source = WavCarrier(input_path)
    except (OSError, ValueError) as error:
        return _failure_result(
            "Cannot Verify", str(error), _context_for_sender_key(sender_public_key)
        )
    return decode_carrier_source(
        source, source.media_code, source.media_context,
        sender_public_key, receiver_private_key,
    )


def verify_wav_to_payload_path(input_path: str | bytes | PathLike[str], sender_public_key: rsa.RSAPublicKey, receiver_private_key: rsa.RSAPrivateKey, payload_output_path: str | bytes | PathLike[str]) -> VerificationResult:
    """Verify a WAV and publish payload bytes after authentication."""
    try:
        source = WavCarrier(input_path)
    except (OSError, ValueError) as error:
        return _failure_result(
            "Cannot Verify", str(error), _context_for_sender_key(sender_public_key)
        )
    return decode_carrier_source_to_payload_path(
        source, source.media_code, source.media_context, sender_public_key,
        receiver_private_key, payload_output_path,
    )
