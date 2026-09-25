# Payload streaming design

**Status: Stages 1–3 complete.** The design, streaming library APIs, Flask
integration, notebook demonstration, tests, and documentation are implemented.
The approved staging-backend amendments and compatibility rules below remain the
contract for future changes.

## Goal and fixed rules

The file APIs must process payload data in bounded chunks. They must not build a
complete serialized record, ciphertext, signing input, or decrypted payload in
memory. Protocol version 3 bytes, the record layout, bootstrap, media hash,
verdict order, and existing bytes APIs stay compatible. One internal staging
interface serves both APIs: the bytes API uses a memory backend and never writes
plaintext or ciphertext to disk; the file API uses a private-file backend.
Encryption, signing prehash, packet reading, decryption, and parsing use that
same interface. It provides `write(chunk)`, `read_range(offset, length)`,
`size`, `release`, and `discard`. Neither backend releases plaintext before
`Authentic`; the memory backend clears its buffer on every failure path. After
success, memory release returns only the requested payload range and clears its
store; file release atomically moves the staged payload-only file.

The existing bytes APIs remain available:

- `prepare_carrier_encoding(..., user_payload: bytes, metadata: bytes)`;
- `encode_png(..., user_payload: bytes, metadata: bytes)` and
  `encode_wav(..., user_payload: bytes, metadata: bytes)`; and
- `decode_carrier_source`, `verify_png`, and `verify_wav`, whose authentic
  `VerificationResult.payload.user_payload` remains `bytes`.

The file APIs are additional entry points. The file API has bounded payload
memory; the bytes API still necessarily holds the caller's input bytes and, on
successful verification, returns the requested payload bytes. Both use the same
streaming cryptographic implementation over the staging interface. The bytes
backend is a `bytearray`; the file backend stores ranges in restrictive
mode-0600 files inside a private mode-0700 directory.

## B. Stream the AES-GCM record

The record bytes stay exactly as defined by `serialize_payload`:

```text
u8 media_id length
media_id UTF-8 bytes
u64 timestamp
16-byte record nonce
32-byte media hash
u64 user-payload length
user-payload bytes
u64 metadata length
metadata UTF-8 bytes
```

The serializer yields these fields in order. It yields the user payload in
bounded reads; it does not concatenate the pieces. The existing
`serialize_payload` bytes API remains unchanged.

After the carrier's first hash pass, make the same session key, AEAD nonce,
bootstrap fields, and AAD as the current encoder. Create the encryptor as
follows:

```python
Cipher(algorithms.AES(session_key), modes.GCM(aead_nonce)).encryptor()
```

Call `authenticate_additional_data(encode_bootstrap_aad(fields))` before the
first `update`. Feed each serialized record piece to `update`. Write each output
chunk to the ciphertext staging store. The file backend uses a temporary
file; the bytes backend uses a `bytearray`. Call `finalize()`, write any returned
bytes, then append the 16-byte `encryptor.tag`. The packet ciphertext is exactly
`ciphertext_body || tag`, as returned by
`AESGCM(session_key).encrypt(aead_nonce, record, aad)`. The layout's
`ciphertext_length` continues to include the tag.

Input payload size comes from the payload file's initial `stat` result. Use that
size in `serialized_record_length` and the existing carrier-capacity functions
before reading carrier data. Read exactly that many payload bytes. Fail and
clean up if the file ends early or has extra bytes when the read completes; do
not silently encode a different length from the capacity calculation.

## C. Hash the signing input in the encryption pass

The current signing input is this exact byte sequence:

```text
SIGNING_DOMAIN
|| u8 protocol version || u8 media code || u8 LSB count
|| u64 total_units || u64 start_unit || u64 footprint
|| u64 ciphertext_length || media_context || ciphertext_with_tag
```

Add a helper that returns the fixed prefix through `media_context`; keep
`encode_signing_input()` as the bytes wrapper that appends the ciphertext. Start
`hashes.Hash(hashes.SHA256())` with that prefix. As each AES-GCM update emits a
ciphertext chunk, write it to the staging store and update the SHA-256 object
with the same chunk. Add the final GCM tag to both. This hashes the same
concatenated input without making a payload-sized signing-input value or doing
a second ciphertext pass.

Sign the resulting 32-byte digest with
`private_key.sign(digest, rsa_pss_padding(), utils.Prehashed(hashes.SHA256()))`.
The verifier hashes the same prefix and ciphertext bytes and calls
`public_key.verify(signature, digest, rsa_pss_padding(),
utils.Prehashed(hashes.SHA256()))`.

`rsa_pss_padding()` remains the authority for the parameters: MGF1 uses
SHA-256 and `RSA_PSS_SALT_LENGTH` is 32 bytes. Do not change it to
`PSS.MAX_LENGTH`. The prehashed signer and verifier use the same digest and
padding parameters as the current full-message calls. RSA-PSS signatures are
randomized, so compatibility means that signatures verify, not that the
signature bytes match.

The bytes `sign_bytes()` and `verify_signature()` APIs will hash their complete
input and call the same internal digest-sign/digest-verify helpers. This keeps
one RSA-PSS implementation for byte and streaming callers.

## D. Embed packet bytes through staging

`CarrierEncoding` keeps the ciphertext staging reader and the 256-byte
RSA signature; it does not keep `ciphertext || signature` as one stored
bytes value.
The packed LSB range transform accepts a bounded byte-range reader as well
as the existing bytes input used by small fields such as the bootstrap. The
same transform reads packet ranges from memory or disk through the staging
interface.

For each carrier chunk, the packet transform calculates the exact byte range
that overlaps its global packet bit range. It reads only that ciphertext range
from the staging backend, adds the overlapping signature bytes from the fixed
256-byte value,
and applies the existing packed transform. At most one carrier chunk of packet
bytes is resident. Packet order, LSB order, and alignment padding stay
unchanged.

The second carrier pass still hashes the original carrier units before
embedding. `CarrierEncoding.finish()` still checks that this second-pass hash
matches the first-pass hash. A carrier change still makes encode fail; the
staged carrier output is not published.

`CarrierEncoding` owns its ciphertext staging resource and supports a
context manager and idempotent `close()`. `finish()` closes it on success or
hash failure. High-level encode functions close it in `finally`, including on
`KeyboardInterrupt`. Callers of the low-level prepare API use it as a context
manager so an interrupted or abandoned embed also closes the resource.

## E. Verify through private staging

Keep the current verdict order. The carrier is read in the same three phases:
bootstrap, packet, and full masked-media hash.

1. Read and open the bootstrap; validate its fields and calculate the layout as
today. `Payload Missing`, `Cannot Verify`, and `Wrong Start Location` remain
before packet processing when their current checks fail.
2. Read packet units in bounded chunks. Check alignment padding as each chunk is
read. Pack its ciphertext bytes directly into a ciphertext staging store and
retain only the 256-byte signature. At the same time, hash the signing prefix
and ciphertext bytes. A bad pad or packet-read error returns `Cannot Verify`.
3. Verify RSA-PSS with `Prehashed(SHA256())`. A failure returns `Signature
Invalid` before GCM decryption, as today.
4. Read the last 16 bytes of the ciphertext staging store as the GCM tag. Decrypt
only the preceding ciphertext body with
`Cipher(algorithms.AES(session_key), modes.GCM(aead_nonce, tag)).decryptor()`.
Supply the existing bootstrap AAD. Write each `update()` result to the private
plaintext staging store: a hidden file for the file API and a `bytearray` for
the bytes API. These bytes are unauthenticated until `finalize()` and stay
inside staging; they are never passed to a caller or callback. `InvalidTag` at
`finalize()` returns the existing `Cannot
Decrypt` verdict and detail.
5. After GCM finalizes successfully, parse the plaintext staging store's record
header and metadata. Seek over the user-payload region; do not read it into
memory for the file API. Check exact file end and UTF-8 rules below. A parse error returns
`Cannot Verify`.
6. Calculate the full masked media hash, in the existing place in the verdict
order. A carrier read failure returns `Cannot Verify`; a mismatch returns
`Tampered`.
7. Only after the hash matches return `Authentic`. For the file API, copy only
the user-payload range to a second hidden staging file, then atomically move
that payload-only file to the requested output path with `os.replace`. For the
bytes API, release only the payload range from memory now, construct its existing
`PayloadRecord`, then clear the remaining staging data.

The file backend creates ciphertext and plaintext temporary files only inside a
private mode-0700 directory named with the `.stego-staging-` prefix. When a
final output path is supplied, create that directory under the output path's
parent so the final `os.replace` is on the same filesystem. Temporary files use
mode 0600. The bytes backend creates no files. No unauthenticated plaintext
reaches a caller, callback, or visible path at any point. On all failure
verdicts, the requested output is not newly created or replaced. The web
payload-download name pattern `[A-Za-z0-9_-]{22}` followed by `.bin`, `.png`, or
`.wav` cannot match a `.stego-staging-*` directory or its temporary filenames.
The Stage 3 web tests confirm these directories are not served.

### Streaming record checks

The file parser must make the same checks in the same order as `parse_payload`.
It reads the media-ID length, media ID, fixed 56-byte timestamp/nonce/hash
fields, user length, user payload range, metadata length, and metadata range.
It checks for trailing bytes before UTF-8 decoding. It then checks media-ID
UTF-8 and the existing `PayloadRecord` rules, followed by metadata UTF-8.

Preserve these exact `ValueError` details:

- `payload is truncated before media_id length`
- `payload is truncated in media_id`
- `payload is truncated in fixed fields`
- `payload is truncated in user length`
- `payload is truncated in user payload`
- `payload is truncated in metadata length`
- `payload is truncated in metadata`
- `payload contains trailing bytes`
- `media_id must contain valid UTF-8`
- `metadata must contain valid UTF-8 bytes`
- `media_id UTF-8 length must be between 1 and 255 bytes`

The parser also keeps the existing nonce, media-hash, and timestamp-width rules.
The user payload is skipped by offset in the file API and remains private until
the full media hash matches. The bytes API reads only that range after success.

### Cleanup on every path

A staging session owns each operation's memory stores or its file-backed
ciphertext, plaintext, and staged output files. The file session uses a
`TemporaryDirectory` named `.stego-staging-*` with mode 0700. Create it with
`tempfile.TemporaryDirectory(prefix=".stego-staging-", dir=parent)`. Put it next
to the final output when one is supplied; otherwise use the system temp dir.
The context is exited on success, every verdict, ordinary exceptions, and
`KeyboardInterrupt`.

| Exit path | Result | Cleanup and publication |
| --- | --- | --- |
| Invalid arguments, key, payload size, capacity, or source read during encode | Existing exception | Clear memory stores or remove file staging; do not publish carrier output. |
| Encode pass-2 carrier change, write error, or interruption | Existing exception | Clear memory stores or remove staged carrier and ciphertext; do not publish carrier output. |
| Bootstrap cannot be opened | `Payload Missing` | Discard ciphertext staging; no payload output. |
| Invalid bootstrap, wrong geometry, bad packet padding, packet I/O, or malformed decrypted record | `Cannot Verify` or existing geometry verdict | Clear memory stores or remove ciphertext and plaintext files; no payload output. |
| RSA-PSS failure | `Signature Invalid` | Discard ciphertext staging; do not create plaintext or output. |
| GCM `InvalidTag` | `Cannot Decrypt` | Clear or remove ciphertext and unauthenticated plaintext staging; no payload output. |
| Full media hash failure | `Tampered` or `Cannot Verify` on read failure | Clear or remove authenticated-but-not-yet-released plaintext staging; no payload output. |
| Any exception or `KeyboardInterrupt` | Re-raise or retain the existing failure mapping | Clear memory stores, close open files, and remove any file staging directory. |
| `Authentic` | Existing authentic result | Publish the payload-only file with `os.replace`, or release payload bytes for the bytes API; then discard remaining staging. |

If the caller already has a file at the requested output path, a failed
verification leaves it unchanged. A successful `os.replace` replaces it
atomically. Memory staging overwrites its `bytearray` in bounded blocks before
clearing it on failure or after release.

## F. API and payload result types

Keep the existing bytes signatures and semantics. Add separate names rather
than optional payload arguments, so a call cannot supply both a byte string and
a path:

```python
def prepare_carrier_encoding_from_payload_path(
    source: CarrierSource,
    media_code: int,
    media_context: bytes,
    signing_private_key: rsa.RSAPrivateKey,
    receiver_public_key: rsa.RSAPublicKey,
    start_unit: int,
    lsb_count: int,
    payload_path: str | bytes | PathLike[str],
    metadata: bytes,
) -> CarrierEncoding: ...

def encode_png_from_payload_path(
    input_path: str | bytes | PathLike[str],
    output_path: str | bytes | PathLike[str],
    signing_private_key: rsa.RSAPrivateKey,
    receiver_public_key: rsa.RSAPublicKey,
    start_unit: int,
    lsb_count: int,
    payload_path: str | bytes | PathLike[str],
    metadata: bytes,
) -> tuple[EmbeddingLayout, PayloadFileRecord]: ...

def encode_wav_from_payload_path(
    input_path: str | bytes | PathLike[str],
    output_path: str | bytes | PathLike[str],
    signing_private_key: rsa.RSAPrivateKey,
    receiver_public_key: rsa.RSAPublicKey,
    start_unit: int,
    lsb_count: int,
    payload_path: str | bytes | PathLike[str],
    metadata: bytes,
) -> tuple[EmbeddingLayout, PayloadFileRecord]: ...

def decode_carrier_source_to_payload_path(
    source: CarrierSource,
    media_code: int,
    media_context: bytes,
    sender_public_key: rsa.RSAPublicKey,
    receiver_private_key: rsa.RSAPrivateKey,
    payload_output_path: str | bytes | PathLike[str],
) -> VerificationResult: ...

def verify_png_to_payload_path(
    input_path: str | bytes | PathLike[str],
    sender_public_key: rsa.RSAPublicKey,
    receiver_private_key: rsa.RSAPrivateKey,
    payload_output_path: str | bytes | PathLike[str],
) -> VerificationResult: ...

def verify_wav_to_payload_path(
    input_path: str | bytes | PathLike[str],
    sender_public_key: rsa.RSAPublicKey,
    receiver_private_key: rsa.RSAPrivateKey,
    payload_output_path: str | bytes | PathLike[str],
) -> VerificationResult: ...
```

`...` in the function bodies marks a signature-only declaration, not omitted
arguments. Export the file variants and `PayloadFileRecord` from `stego`.

Keep `PayloadRecord.user_payload: bytes` unchanged and add a read-only
`user_payload_size` property. Add `PayloadFileRecord` with the same authenticated
record fields but `user_payload_size: int` instead of payload bytes. A file
encode returns this file record. Add `VerificationResult.payload_path:
Path | None`, defaulting to `None` for compatibility. The bytes verification
functions return the existing `PayloadRecord` with its bytes and no path. The
file verification functions return a `PayloadFileRecord` and set `payload_path`
only on `Authentic`. Failure results keep both payload fields empty. This keeps
file locations out of the signed record and preserves the bytes API's payload
field.

Both prepare paths use the payload length in `serialized_record_length` and the
existing capacity checks. The file variant gets that length from `stat()` and
checks it against the bytes actually read. Separate function names reject
ambiguous bytes/path combinations by construction. Metadata and keys remain
byte inputs; only the user payload is streamed.

## G. Memory and pass counts

| Operation | Carrier and payload passes | Bytes API staging | File API staging |
| --- | --- | --- | --- |
| Encode | Carrier: hash pass, then embed pass. Payload: one bounded read pass through AES-GCM and SHA-256; packet ranges are read during the existing embed pass. | Caller payload plus in-memory ciphertext store; no staging files. | O(chunk) payload/crypto RAM; ciphertext file is read by packet ranges. |
| Verify | Carrier: bootstrap read, packet read, full hash pass. Ciphertext is read once for decryption. Parsed payload is accessed by offset. | In-memory ciphertext and plaintext stores; return bytes only after `Authentic`; no staging files. | O(chunk) payload/crypto RAM; ciphertext and plaintext files coexist during decryption. After `Authentic`, copy the payload range to a hidden file and publish it atomically. |

The file APIs keep payload-dependent RAM to the I/O chunk and small fixed fields.
The bytes APIs still hold their caller-owned input or successful returned bytes,
but use the same streaming encryption, prehash, decryption, and parser code.
Carrier pass counts and the order of the carrier hash do not change.

## H. Stage 3 web integration (complete)

- Encode uploads and text messages use request-scoped files and the payload-path
  encode APIs. Key PEMs remain bounded byte inputs.
- Verification calls the payload-path file APIs. The library publishes only the
  authenticated payload; the route writes its JSON sidecar afterwards and
  removes the payload if sidecar creation fails.
- MIME sniffing reads at most 12 bytes. `text/plain` UTF-8 validation uses an
  incremental decoder over 64 KiB reads.
- The response shape, safe MIME rules, filename policy, `Cache-Control`, and
  browser security headers remain unchanged. No Base64 response is added.
- Tests cover PNG/WAV upload round trips, UTF-8 boundaries, staging path URL
  protection and cleanup, plus an opt-in 20 MiB WAV payload round trip.
- The notebook demonstrates file APIs. The root README documents the crash
  cleanup step for leftover `.stego-staging-*` directories.

## I. Stage 2 test plan

- Compare streamed AES-GCM ciphertext plus tag byte-for-byte with `AESGCM` for
  a fixed key, nonce, AAD, serialized record, and several input chunk sizes.
- Test the signing prefix, digest, and Prehashed sign/verify. Check PSS
  parameters against `rsa_pss_padding()`; compare verification, not randomized
  PSS signature bytes.
- Keep the existing bytes API behavior and verdict-order tests. Update only the
  decryption-order test to observe the new streaming decrypt helper instead of
  `aead_open`; the library no longer calls the one-shot decrypt API. Test file
  APIs for PNG and WAV, including a payload much larger than one I/O chunk.
- Make a one-off two-way compatibility check in a temporary worktree at the
  pre-change `HEAD`: old encode/new verify, then new encode/old verify. Remove
  the worktree. Keep a fixed AES-GCM vector in the normal suite and cross-check
  the one-shot and streaming implementations; this does not replace the
  one-off full-carrier test.
- For every failed file verification, assert that no staged directory, temp
  file, or newly requested output remains: `Payload Missing`, `Signature
  Invalid`, `Cannot Decrypt` with a valid signature and invalid tag, `Tampered`,
  and `Cannot Verify` for packet padding, malformed record, and I/O failures.
  Exercise malformed record fields and preserve every parse error above.
- Inject an exception and a `KeyboardInterrupt` during streamed encryption and
  decryption. Assert that all operation files are removed and output paths are
  not published. Point `tempfile.tempdir` at an empty directory during bytes
  encode and verify calls and assert that the directory stays empty.
- Stream a roughly 64 MiB payload file into a WAV at `k = 8`, then verify to a
  payload file. Use `tracemalloc` and require a peak below 16 MiB. Generate the
  inputs incrementally so the test itself does not hold the payload in memory.
  Keep an always-on 8 MiB test with the same memory bound. The 64 MiB test took
  0.537 s in Stage 2, so it also runs in the default suite.
- Check that failure results expose no payload path and publish no new file;
  on success check exact bytes and output path. Existing bytes API payload and
  verdict behavior stays unchanged apart from the decryption-order test above.

Stage 2 measurements on the WAV file API, with incrementally generated input:
8 MiB payload encode plus verify took 0.074 s with a 6.40 MiB `tracemalloc`
peak. 64 MiB took 0.537 s with a 6.39 MiB peak. Both the 8 MiB and 64 MiB tests run in the default suite.

## J. Stage files, risks, and exclusions

**Stage 1 — this design:** `AGENT_docs/PAYLOAD-STREAMING-DESIGN.md`,
`AGENT_docs/README.md`, and `AGENT_docs/AGENT_MAP.md`.

**Stage 2 — library and tests:** `stego/packet.py`, `stego/crypto.py`,
`stego/layout.py`, `stego/carrier.py`, `stego/core.py`, `stego/__init__.py`,
`test_stego.py`, and this note. Add no protocol version or wire-format change.

**Stage 3 — web, notebook, and docs (complete):** `stego_web/routes.py`,
`README.md`, `stego_web/services/current_protocol.py`,
`notebooks/FR1-12 Prototype.ipynb`, `test_webapp.py`,
`AGENT_docs/IMPLEMENTATION-STATUS.md`, `AGENT_docs/PAYLOAD-HANDLING.md`,
and `AGENT_docs/STREAMING-CARRIER-PLAN.md`. No JavaScript changes were needed.

**Risks:** GCM update emits plaintext before the tag is checked; private staging
and delayed publication are mandatory. While the file API verifies,
unauthenticated plaintext exists in a mode-0700 staging directory on disk. It is
deleted on every normal exit path, but a power loss or `SIGKILL` can leave it.
The root README instructs users to stop the server and manually delete
`.stego-staging-*` directories after a crash. The design needs temporary disk
space proportional to the encrypted and staged plaintext payload. A payload
file that changes while it is read can produce a mixed input; size checks do not
prevent a same-size change during a read. Prehashed PSS code must retain the
exact digest and padding parameters. Atomic replacement requires the temporary
directory and final path to be on the same filesystem.

**Not included:** a new protocol version, a format fallback, streaming metadata
or key uploads, forward-only carriers, a change to carrier-pass counts, or
publishing partial/unauthenticated plaintext. The bytes API cannot avoid its
caller-owned input or requested returned payload bytes; it only avoids extra
payload-sized protocol copies.
