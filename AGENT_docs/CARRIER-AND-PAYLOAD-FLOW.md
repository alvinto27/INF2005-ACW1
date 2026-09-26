# Carrier and Payload Flow

**Status:** File-backed carrier access, payload streaming, and the Flask disk boundary are implemented. This file is the current source of truth for bounded carrier/payload processing, staging cleanup, memory measurements, and file API entry points. The protocol format and verdicts are in [Current Protocol](CURRENT-PROTOCOL.md).

## Carrier interface and pass order

`CarrierSource` supplies bounded carrier-unit reads to `stego/core.py`. `PngCarrier`, `WavCarrier`, and `VideoCarrier` are the public file-backed implementations. The internal array backend is not part of the package API. `read_units()` reads a bounded range; `iter_chunks()` returns units in order; `iter_chunks_with_fixed_bytes()` pairs unit chunks with fixed media bytes from the same read. `rewrite_to_path()` writes sequentially and may hash fixed bytes during that same read.

PyAV decodes 8-bit or 16-bit RGB/RGBA PNG to one read-only pixel buffer, about one decoded image size D. The decoded-byte size is checked from IHDR before decode against 715,827,880 bytes; FFmpeg also gets a format-specific `max_pixels` guard. Bounded reads avoid full RGB and alpha copies. Rewriting writes directly into one PyAV frame. A PNG unit is the low byte of one numeric R, G, or B sample value. WAV reads whole PCM frames in bounded chunks; carrier working memory does not grow with frame count. One WAV unit is the low byte of one PCM sample.

### Metadata in the output

`rewrite_to_path()` keeps carrier metadata that the masked media hash does not cover. The media hash, media context, carrier units, and fixed bytes do not change, so a file encoded before or after this rule verifies under both versions.

WAV output is a copy of the input file with only the declared sample bytes patched:

1. `_find_wav_data_chunk()` reads the RIFF chunk headers (ID and little-endian u32 size; an odd-sized chunk has one pad byte) and finds the first `data` chunk.
2. The writer opens the same file with `wave` and compares: the `wave` file position after the header read must equal the parsed data offset, and the declared data size must give the same whole-frame count. If they do not agree, the writer raises `ValueError`. It does not fall back.
3. The writer copies every byte before the samples, then reads, embeds, and writes the samples in chunks of whole frames, then copies every byte after the last whole frame. The chunk size is `DEFAULT_CHUNK_BYTES`.

The header, `LIST`/`INFO`, `cue `, `bext`, other chunks before or after `data`, pad bytes, and data bytes after the last whole frame stay byte-for-byte the same. The output length equals the input length. The callbacks run in the same order as before, and `fixed_bytes_callback` receives the original fixed bytes.

PNG output uses the PyAV PNG encoder for IHDR, IDAT, and IEND; encoder ancillary chunks are dropped. `_png_copied_chunks()` reads the input chunk list and selects chunks by the PNG rule for editors that change image data. Embedding changes only low bits; width, height, colour type, and bit depth stay the same. A chunk is kept only if it stays true after that change:

| Input chunk | Output |
| --- | --- |
| `tEXt`, `zTXt`, `iTXt`, `eXIf`, `pHYs`, `iCCP`, `sRGB`, `gAMA`, `cHRM`, `bKGD`, `sPLT`, `PLTE` (a suggested palette for truecolour) | Copied unchanged |
| `tIME` | Replaced in the same position with the encode time in UTC (7 bytes: year u16 big-endian, month, day, hour, minute, second) and a new CRC. The encoder does not add `tIME` when the input has none. |
| More than one `tIME` (not allowed by the PNG specification) | Encode stops with `ValueError` |
| `sBIT`, `hIST` | Dropped: `sBIT` would mark the embedded low bits as not significant, and `hIST` counts the old pixels |
| `tRNS` in an RGB PNG (colour key) | Encode stops with `ValueError`: "RGB PNG with a tRNS colour key is not supported; convert the image to RGBA". Embedding can move pixels onto or off the key colour and change the visible transparency. `encode_image` and the web app convert this source to RGBA instead (see [Source conversion](#source-conversion)). |
| `tRNS` in an RGBA PNG (not allowed by the PNG specification) | Dropped |
| Unknown ancillary chunk with the safe-to-copy bit set (fourth letter lowercase) | Copied |
| Unknown ancillary chunk that is not safe to copy (fourth letter uppercase), for example APNG or newer colour chunks | Dropped |
| Unknown critical chunk (first letter uppercase) | Encode stops with `ValueError`, as the PNG specification requires |
| `IHDR`, `IDAT`, `IEND` | Taken from the new image |

`_PngChunkSplicer` receives bytes from the PyAV PNG encoder, parses the PNG chunks, drops encoder ancillary chunks, and writes the image chunks to the output file. It inserts the copied chunks that came before the first input IDAT immediately before the first new IDAT, and the copied chunks that came after IDAT immediately before IEND. The copied chunks keep their order, data, and CRC; only a replaced `tIME` gets new data and a new CRC. `_utc_now()` supplies the time; tests patch it. The time is read only in the rewrite pass. PyAV ancillary chunks are discarded; unexpected critical chunks cause `ValueError`, so no chunk type is written twice.

The splicer holds only chunk offsets, the new `tIME` chunk, and one copy block, so it does not add a decoded-image copy.

These rules apply only to encoding. `PngCarrier` loading and verification do not read ancillary chunks. A stego file that later gets a `tRNS` chunk or other metadata verifies as before.

## Source conversion

`stego/sources.py` exposes `detect_source_family()` and the `open_image_source()` / `open_audio_source()` context managers. The detection helper returns the family and source label without decoding a frame. The context managers yield a validated `PngCarrier` or `WavCarrier`. Strict, supported PNG and PCM WAV inputs bypass conversion and keep their current metadata. Other accepted sources are decoded once with PyAV into a canonical PNG or PCM WAV snapshot in a private `.stego-source-*` directory under the caller's staging parent. The context manager removes that directory after success or failure. Pass the yielded carrier to an `encode_image*()` or `encode_audio*()` function to reuse the same converted source after checking capacity; the convenience functions convert and encode in one call.

Image conversion accepts still JPEG, PNG, WebP, GIF, TIFF, BMP, and AVIF images. It writes RGB or RGBA PNG at 8 bits for sources up to 8 bits and at 16 bits for sources up to 16 bits. The canonical integer values preserve the source component's top bits during depth expansion. Floating-point image formats such as EXR and integer depths above 16 bits are refused. Palette and grayscale images expand to RGB; alpha and PNG transparency are retained. EXIF orientations 1–8 are read from bounded JPEG APP1, PNG `eXIf`, WebP EXIF, or TIFF IFD0 data and applied before the snapshot is written. Animated GIF, PNG, and WebP sources are refused before decode. A decoded image over the 715,827,880-byte limit is refused before decode. `pHYs`, EXIF, text, and `sBIT` do not apply to the canonical pixels and are dropped from converted snapshots. Source `cICP`, `mDCV`, and `cLLI` PNG chunks are retained byte-for-byte.

RGB ICC profiles are kept with the RGB snapshot and final PNG. CMYK images are refused with `CMYK images are not supported`. Their CMYK ICC profile is not valid on an RGB PNG, and a colour-managed CMYK-to-RGB conversion needs a library outside PyAV. The application does not silently discard or misapply that profile.

Audio conversion requires exactly one audio stream and one or two channels. Attached cover-art streams and real video streams are ignored; only the selected audio stream is converted to WAV. This is policy: a video track in an audio source does not make the audio input ambiguous. Lossless integer PCM, FLAC, and ALAC keep their decoded 8-, 16-, 24-, or 32-bit samples; compressed or floating-point audio is resampled to integer PCM at its source rate, using 16 bits. The conversion keeps all decoded samples, including codec delay or padding. It refuses a canonical WAV whose data would exceed the RIFF 4 GiB limit. Metadata that is not part of decoded samples is not copied to converted snapshots. Strict PCM WAV files bypass conversion, so all original chunks remain in the final stego output.

The version-3 carrier protocol and its verifier do not change. Verification still accepts only canonical PNG or PCM WAV carriers and reports the same verdicts. Source conversion is an encode-side convenience; it is not a new wire format or a promise that the original compressed source can be recovered.

## Video carrier backend

`VideoCarrier` is the file-backed media-code-3 backend in `stego/video.py`. It performs a bounded scan, then reopens and decodes for range reads, hashing, and rewriting. It exposes ordered RGB low-byte and audio-low-byte carrier units, plus fixed timing, RGB high-byte, alpha, and audio-high-byte data. It supports canonical integer video depths from 8 through 16 bits, with or without alpha; see [Current Protocol](CURRENT-PROTOCOL.md#video-plus-audio-media-code-3). PyAV is a required dependency in `requirements.txt` and is imported at module load. PNG, WAV, and video media I/O use PyAV.

Only video sources that set `requires_output_check=True` use the additive `CarrierSource.open_rewritten_output(path)` hook. `CarrierEncoding.check_output(source)` verifies output context, embedded transforms, unit/fixed-byte counts, and the masked hash. Core `_rewrite_checked()` owns the sequence: rewrite, open and validate the output reader, close it, then call `finish()`. Any failure removes the incomplete output. Existing PNG/WAV sources use the default no-check behavior.

`encode_video()` writes one FFV1 video stream at the selected canonical format and optional PCM s16le audio directly to a same-directory `.stego-staging-*` Matroska file. The 8-bit no-alpha path remains `bgr0`. `encode_video_from_payload_path()` uses a private same-directory `.stego-staging-*` directory. Both publish with `os.replace` only after read-back checks and `finish()`. No extra track files or remux stage are used. Failure leaves the destination unpublished and removes the stage.

PASS 0 counts carrier units incrementally and checks each canonical frame's byte size before staging. The configured carrier-unit, frame-byte, output-size, and free-space limits are detailed in [Video Carrier Design](VIDEO-CARRIER-DESIGN.md). The final output cap is enforced while muxing; failures remove staging and do not publish. Audio remains limited to mono or stereo under the channel-identity rule in [Current Protocol](CURRENT-PROTOCOL.md#video-plus-audio-media-code-3). Tests monkeypatch the free-space requirement so they do not depend on host disk capacity.

## 4. Protocol flow

### Encode

The protocol core makes two source-content passes after backend validation. Video also makes an initial validation/count scan and a read-back pass after writing:

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
encode_video
verify_video
encode_video_from_payload_path
verify_video_to_payload_path
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

The same 4341 x 26191 RGBA PNG (about 434 MiB decoded) was used. New encode and verify times are medians of three separate-process runs after one source read; old times are single runs under a different rule. The first encode run of each series was slower (about 9.5 s in two series); the cause was not determined. Verify runs did not show this. Peak RSS includes Python and native decoder/encoder allocations and is not a limit or guarantee.

| Operation | Old time | New time | Old peak RSS | New peak RSS |
| --- | ---: | ---: | ---: | ---: |
| Encode | 8.1 s | 5.47 s | 1,571 MiB | 947.2 MiB |
| Verify | 1.9 s | 2.16 s | 1,350 MiB | 947.0 MiB |

The PNG chunk carry-over did not change these figures. For each version, three separate-process encode runs of the same PNG gave a median of 5.68 s and about 947 MiB peak RSS. The output kept the input `bKGD` chunk.

A separate fixed-key check on RGB and RGBA carriers compared full carrier-unit reads and identity-rewrite outputs; both matched exactly. The encoded files were not compared because encoding uses random nonce material.

#### PyAV PNG migration (M-S1)

The before run used revision `515cc65`; the after run used the PyAV PNG implementation. Each operation ran in three fresh processes with a small payload. The large source was 4341 × 26191 RGBA (113,695,131 pixels). Times and peak RSS include Python startup and native media buffers; RSS is a host-specific measurement, not a limit.

| Source | Operation | Before median | Before peak RSS | After median | After peak RSS |
| --- | --- | ---: | ---: | ---: | ---: |
| `samples/Banana.png` | Encode | 0.350 s | 80.5 MiB | 0.098 s | 94.7 MiB |
| `samples/Banana.png` | Verify | 0.063 s | 80.8 MiB | 0.038 s | 75.1 MiB |
| 4341 × 26191 RGBA | Encode | 5.365 s | 948.1 MiB | 3.517 s | 1870.8 MiB |
| 4341 × 26191 RGBA | Verify | 2.106 s | 948.0 MiB | 1.351 s | 938.2 MiB |

The PyAV PNG encoder uses `compression_level=1` and `pred=up`, selected from the large-image measurement. Direct writes into a PyAV frame removed the full output ndarray and saved 431 MiB (about 19%) from the first S1 encode peak. Keeping the decoded ndarray as a read-only view removed a decode copy and reduced verify peak by about 430 MiB. Setting encoder `thread_count=1` did not reduce peak RSS. Final large-image encode peak is 1.97 times the before peak; verify peak is 1.0% below it. The 2400×2400 RGBA memory test passes with its original `2.5 × decoded bytes + 2 MiB` traced-memory bound. These are host-specific measurements, not guarantees.

#### PyAV 16-bit PNG measurement (M-S2)

The generated RGBA source was 7746 × 7746 pixels: 60,000,516 pixels and 480,004,128 decoded bytes. It was written by PyAV with a smooth deterministic pattern (41,930,550-byte PNG). Each encode and verify ran in three fresh processes with the same small payload. Peak RSS is a process maximum and includes PyAV and Python allocations.

| Source | Operation | Median time | Median peak RSS |
| --- | --- | ---: | ---: |
| 16-bit RGBA, 7746 × 7746 | Encode | 5.129 s | 2011.6 MiB |
| 16-bit RGBA, 7746 × 7746 | Verify | 1.843 s | 1519.6 MiB |
| 8-bit RGBA, 4341 × 26191 (S1) | Encode | 3.517 s | 1870.8 MiB |
| 8-bit RGBA, 4341 × 26191 (S1) | Verify | 1.351 s | 938.2 MiB |

The two images have different decoded sizes (480,004,128 and 454,780,524 bytes). Treat these as host-specific examples, not a direct per-byte speed comparison.

## 10. Whole-file WAV cap

`WavCarrier` reads whole PCM frames, verifies headers when reopening the file, checks the last declared frame on open, and preserves sample bytes outside the low-byte carrier unit. A short file fails early. File reads and early-end failures become `CarrierAccessError`; verification maps these to `Cannot Verify`. WAV output is a chunked copy of the input file with only the declared samples patched; see [Metadata in the output](#metadata-in-the-output). For a 96 MiB 16-bit stereo WAV, three separate-process encode runs took about 0.3 s with 54 MiB peak RSS, before and after this change. The whole-file `WavPcmData`, `load_pcm_wav_from_path`, and `MAX_WAV_FRAME_BYTES` cap are removed. The optional 72 MiB WAV test passes through the file-backed path with traced peak below 16 MiB.

Flask accepts requests up to 256 MiB. Carrier and payload uploads go to request-scoped temporary files. Encode outputs go to `instance/stego-outputs`; authenticated recovered payloads and sidecars go to `instance/recovered-payloads`. These files have no expiry and users delete them manually. Recovered payloads are plaintext on disk. The service returns URLs, not carrier or payload Base64. Browser responses use `Cache-Control: no-store`.

## Limits and risks

- Application-side carrier and file-payload buffers use chunks. A canonical decoded frame is limited to 256 MiB, so frame-sized working memory is bounded by this cap times a small number of working copies. The 640×360 video-plus-audio RSS test measured 182,648 KiB at 5 seconds and 219,328 KiB at 15 seconds (about 36 MiB more); these are measurements, not a guarantee. Audio sample rate, samples per decoded audio frame, and compressed packet size have no explicit caps before FFmpeg/PyAV allocates decoded data. This is not an absolute guarantee against hostile media. Payload and cryptographic buffers grow with packet size, and PNG requires a full decoded image plus an output image during rewrite.
- Verification is not a snapshot. A file changed between targeted reads and the final hash pass can yield a verdict based on more than one state. WAV headers are checked on reopen, but frame data is not locked.
- GCM emits unauthenticated plaintext before the tag check; private staging and delayed publication are mandatory.
- Temporary disk space is proportional to encrypted and staged plaintext payload sizes. A crash may leave plaintext staging as described by the cleanup rule.
- Atomic replacement requires staging and output paths on the same filesystem.
- The web request limit is 256 MiB; PNG images have a 715,827,880-byte decoded-size cap checked before decode; FFmpeg also receives a format-specific `max_pixels` limit.

## 12. Web boundary follow-up

- Uploads use request-scoped files; keys remain bounded byte inputs. Carrier detection reads the first 12 bytes.
- Bytes-API encode functions write directly to the output path and remove partial outputs on failure. File-payload encode functions write to staging and publish with `os.replace`.
- Verification publishes payload bytes only after `Authentic`; MIME sniffing reads at most 12 bytes and UTF-8 validation uses an incremental decoder.
- `/download/<id>.<ext>` and `/payload/<id>` validate identifiers and extensions, stream output, and apply browser safety headers. Failed sidecar creation removes the recovered payload.
- `Cache-Control: no-store` is retained. Stored files have no expiry.

## Source records and measurements

Earlier design details and stage chronology have been removed from current guidance. The measurements above retain carrier throughput, memory, payload, and PNG figures needed to explain the implemented behavior. The current web request and verification contract is in [Web Application Guide](WEB-APPLICATION-GUIDE.md).
