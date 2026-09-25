# Carrier and Payload Flow

**Status:** File-backed carrier access, payload streaming, and the Flask disk boundary are implemented. This file is the current source of truth for bounded carrier/payload processing, staging cleanup, memory measurements, and file API entry points. The protocol format and verdicts are in [Current Protocol](CURRENT-PROTOCOL.md).

## Carrier interface and pass order

`CarrierSource` supplies bounded carrier-unit reads to `stego/core.py`. `PngCarrier` and `WavCarrier` are the public file-backed implementations. The internal array backend is not part of the package API. `read_units()` reads a bounded range; `iter_chunks()` returns units in order; `iter_chunks_with_fixed_bytes()` pairs unit chunks with fixed media bytes from the same read. `rewrite_to_path()` writes sequentially and may hash fixed bytes during that same read.

PNG keeps one read-only decoded pixel buffer, about one decoded image size D. Bounded reads avoid full RGB and alpha copies. Rewriting adds one output image, about 2 x D total. Pillow still decodes the whole image. WAV reads whole PCM frames in bounded chunks; carrier working memory does not grow with frame count. One PNG unit is an 8-bit R, G, or B value. One WAV unit is the low byte of one PCM sample.

## 4. Protocol flow

### Encode

Encoding makes two full carrier passes:

1. Validate inputs and calculate geometry before reading carrier data.
2. Hash every chunk with the bootstrap region and future packet footprint masked. Build and encrypt the record, sign it, and seal the bootstrap.
3. Read the original carrier again. Hash original units, then write bootstrap and packet bits where they overlap each chunk.
4. Confirm the second-pass unit count and hash match the first pass. If the source changed, fail and remove incomplete output.

### Verify

Verification opens and checks the carrier; reads and opens the bootstrap; reads the packet at the recovered position, checks padding, and verifies RSA-PSS; decrypts AES-GCM and parses the record; then makes one full chunked pass for the masked media hash. The backend must be seekable because packet position is known only after bootstrap decryption. Forward-only carrier streams are not supported.

## 8. Chunk size

`DEFAULT_CHUNK_BYTES` is 1 MiB of raw PCM data. Hash-pass throughput was measured on one 96 MiB 16-bit stereo WAV with warm page cache:

| Chunk | Throughput (MiB/s) | Traced peak memory |
| --- | ---: | ---: |
| 16 KiB | 1,420 | 0.17 MiB |
| 64 KiB | 1,733 | 0.28 MiB |
| 256 KiB | 1,834 | 0.75 MiB |
| **1 MiB** | **1,906** | **2.63 MiB** |
| 4 MiB | 1,758 | 10.13 MiB |
| 16 MiB | 1,414 | 40.13 MiB |

One MiB was fastest in this measurement, uses a few MiB of working memory, and exceeds the largest possible PCM frame (65,535 channels x 4 bytes).

## Payload APIs

Existing bytes APIs remain available and retain their behavior:

- `prepare_carrier_encoding(..., user_payload: bytes, metadata: bytes)`;
- `encode_png(..., user_payload: bytes, metadata: bytes)` and `encode_wav(..., user_payload: bytes, metadata: bytes)`;
- `decode_carrier_source`, `verify_png`, and `verify_wav`, returning `PayloadRecord.user_payload` as `bytes` on `Authentic`.

File APIs are additional entry points. The public functions exported from `stego` are:

```text
prepare_carrier_encoding_from_payload_path
encode_png_from_payload_path
encode_wav_from_payload_path
decode_carrier_source_to_payload_path
verify_png_to_payload_path
verify_wav_to_payload_path
PayloadFileRecord
```

The file encode functions accept a payload path and metadata bytes. The file verify functions accept an output path. They return `PayloadFileRecord` with the authenticated payload size; `VerificationResult.payload_path` is set only for `Authentic`. The bytes API still holds caller-owned input and successful returned payload bytes. File APIs keep payload-dependent memory bounded by their I/O chunk.

### Streaming cryptography and staging

The AES-GCM record serializer yields fields in order and reads payload files in bounded chunks. Encryption output is written to a staging store while the same ciphertext chunks update the SHA-256 signing prehash. RSA-PSS signs the digest with the existing fixed 32-byte salt. Packet embedding reads only the ciphertext ranges that overlap the current carrier chunk.

Verification stages ciphertext and decrypted plaintext privately. It checks the packet signature before GCM decryption, parses the record by offsets, and checks the full media hash before releasing the payload. Bytes APIs use memory staging; file APIs use mode-0600 files inside a private mode-0700 `.stego-staging-*` directory. The bytes backend makes no staging files. On success, only the authenticated payload range is released; file output is published with `os.replace`.

#### Cleanup rule

The staging session owns all memory and file resources. Exit it on success, every verdict, ordinary exceptions, and `KeyboardInterrupt`. Clear bytearray stores; close open files; remove the staging directory. A failed verification must not create or replace the requested output. On success, atomically move only the payload-only file to the output path. A prior output file remains unchanged on failure.

A power loss or `SIGKILL` can leave plaintext staging files. Stop the server and manually remove `.stego-staging-*` directories after a crash. Staging files are not served by the web routes. Temporary disk use grows with encrypted and staged plaintext payload size. Same-size payload input changes during an encode read are not prevented by size checks.

## 9. Memory claim

These are reference measurements on one local machine, not performance guarantees.

### Packed LSB operations and payload sizes

| Operation | Per-bit reference | Vectorized | Change |
| --- | ---: | ---: | ---: |
| Write 1,000,000 bits | 1.4308 s | 0.0102 s | about 140x faster |
| Read 1,000,000 bits | 0.4403 s | 0.0026 s | about 169x faster |

One-off encode/verify runs used an 8-bit mono WAV and `k=8`:

| Payload | Encode | Verify | Combined |
| --- | ---: | ---: | ---: |
| 1 MiB | 0.028 s | 0.052 s | 0.081 s |
| 16 MiB | 0.274 s | 0.684 s | 0.958 s |

The normal suite also encodes and verifies 4 MiB at `k=8`: 0.247 s combined, with a 12.01 MiB `tracemalloc` encode peak. The test requires combined time below 10 s and encode peak below `4 x payload size + 16 MiB`.

| State | Case | Encode peak | Verify peak |
| --- | --- | ---: | ---: |
| Before packed handling | 1 MiB payload, `k=3`, 96 MiB WAV | 20.0 MiB | 34.7 MiB |
| After packed handling | 4 MiB payload, `k=8`, about 4 MiB WAV | 12.01 MiB | Not measured with `tracemalloc` |

The before-Task-5 timing baseline used a 96 MiB WAV at `k=3`:

| Payload | Encode | Encode peak | Verify | Verify peak |
| --- | ---: | ---: | ---: | ---: |
| 673 B | 0.19 s | 4.3 MiB | 0.06 s | 2.7 MiB |
| 1 MiB | 18.4 s | 20.0 MiB | 4.5 s | 34.7 MiB |

The cases differ in payload size, LSB count, and verification measurement; they are examples, not a controlled speedup ratio. The removed full packet-bit arrays used about 8P bytes for payload size P. The current transform working memory is bounded by `chunk_units x lsb_count`.

File payload streaming was measured on an 8-bit mono WAV at `k=8`: 8 MiB encode plus verify took 0.074 s with 6.40 MiB `tracemalloc` peak; 64 MiB took 0.537 s with 6.39 MiB peak. Both tests run in the default suite.

### PNG carrier memory

The same 4341 x 26191 RGBA PNG (about 434 MiB decoded) was used. New encode and verify times are medians of three separate-process runs after one source read; old times are single runs under a different rule. The first encode run of each series was slower (about 9.5 s in two series); the cause was not determined. Verify runs did not show this. Peak RSS includes Python and native Pillow allocations and is not a limit or guarantee.

| Operation | Old time | New time | Old peak RSS | New peak RSS |
| --- | ---: | ---: | ---: | ---: |
| Encode | 8.1 s | 5.47 s | 1,571 MiB | 947.2 MiB |
| Verify | 1.9 s | 2.16 s | 1,350 MiB | 947.0 MiB |

A separate fixed-key check on RGB and RGBA carriers compared full carrier-unit reads and identity-rewrite outputs; both matched exactly. The encoded files were not compared because encoding uses random nonce material.

## 10. Whole-file WAV cap

`WavCarrier` reads whole PCM frames, verifies headers when reopening the file, checks the last declared frame on open, and preserves sample bytes outside the low-byte carrier unit. A short file fails early. File reads and early-end failures become `CarrierAccessError`; verification maps these to `Cannot Verify`. WAV output is chunked. The whole-file `WavPcmData`, `load_pcm_wav_from_path`, and `MAX_WAV_FRAME_BYTES` cap are removed. The optional 72 MiB WAV test passes through the file-backed path with traced peak below 16 MiB.

Flask accepts requests up to 256 MiB. Carrier and payload uploads go to request-scoped temporary files. Encode outputs go to `instance/stego-outputs`; authenticated recovered payloads and sidecars go to `instance/recovered-payloads`. These files have no expiry and users delete them manually. Recovered payloads are plaintext on disk. The service returns URLs, not carrier or payload Base64. Browser responses use `Cache-Control: no-store`.

## Limits and risks

- Memory is bounded by chunks for carrier and file payload processing, but it is not constant: payload and cryptographic buffers grow with packet size, and PNG requires a full decoded image plus an output image during rewrite.
- Verification is not a snapshot. A file changed between targeted reads and the final hash pass can yield a verdict based on more than one state. WAV headers are checked on reopen, but frame data is not locked.
- GCM emits unauthenticated plaintext before the tag check; private staging and delayed publication are mandatory.
- Temporary disk space is proportional to encrypted and staged plaintext payload sizes. A crash may leave plaintext staging as described by the cleanup rule.
- Atomic replacement requires staging and output paths on the same filesystem.
- The web request limit is 256 MiB; PNG image size limits follow Pillow configuration.

## 12. Web boundary follow-up

- Uploads use request-scoped files; keys remain bounded byte inputs. Carrier detection reads the first 12 bytes.
- File encode functions write directly to persistent output paths and remove partial outputs on failure.
- Verification publishes payload bytes only after `Authentic`; MIME sniffing reads at most 12 bytes and UTF-8 validation uses an incremental decoder.
- `/download/<id>.<ext>` and `/payload/<id>` validate identifiers and extensions, stream output, and apply browser safety headers. Failed sidecar creation removes the recovered payload.
- `Cache-Control: no-store` is retained. Stored files have no expiry.

## Source records and measurements

Earlier design details and stage chronology have been removed from current guidance. The measurements above retain carrier throughput, memory, payload, and PNG figures needed to explain the implemented behavior. The current web request and verification contract is in [Web Application Guide](WEB-APPLICATION-GUIDE.md).
