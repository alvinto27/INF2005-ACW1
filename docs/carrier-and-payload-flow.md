# Carrier and payload flow

This guide follows a file through the library: how a cover is read and, if needed, converted; how the payload is encrypted and embedded without ever loading the whole thing into memory; how temporary files are cleaned up; and how much time and memory this takes in practice. The [protocol guide](protocol.md) describes the wire format and verdicts that this machinery serves.

A recurring theme is **bounded processing**: wherever we can, we read and write in fixed-size chunks, so that memory use stays roughly the same whether the file is 1 MB or 10 GB. The sections below note where that is true and where it is not (a PNG, for example, has to be decoded whole).

## Carrier interface and pass order

`CarrierSource` is the interface that `stego/core.py` uses to read carrier units in bounded ranges. `PngCarrier`, `WavCarrier`, and `VideoCarrier` are the public file-backed implementations. The internal array backend is not part of the package API. `read_units()` reads a bounded range; `iter_chunks()` returns units in order; `iter_chunks_with_fixed_bytes()` pairs unit chunks with fixed media bytes from the same read. `rewrite_to_path()` writes sequentially and may hash fixed bytes during that same read. It can accept a separate `preview_transform` when a media writer must prepare data before the ordered embedding pass; the preview must not change the hash or the state of the carrier pass.

PyAV decodes an 8-bit or 16-bit RGB/RGBA PNG into one read-only pixel buffer, roughly the size of the decoded image. The decoded-byte size is checked from IHDR before decode against 715,827,880 bytes; FFmpeg also gets a format-specific `max_pixels` guard. Bounded reads avoid full RGB and alpha copies. Rewriting writes directly into one PyAV frame. A PNG unit is the low byte of one numeric R, G, or B sample value. WAV reads whole PCM frames in bounded chunks; carrier working memory does not grow with frame count. One WAV unit is the low byte of one PCM sample.

### Metadata in the output

`rewrite_to_path()` keeps carrier metadata that the masked media hash does not cover. Keeping this metadata does not affect the media hash, media context, carrier units, or fixed bytes, so it has no effect on verification.

WAV output is a copy of the input file with only the declared sample bytes patched:

1. `_find_wav_data_chunk()` reads the RIFF chunk headers (ID and little-endian u32 size; an odd-sized chunk has one pad byte) and finds the first `data` chunk.
2. The writer opens the same file with `wave` and compares: the `wave` file position after the header read must equal the parsed data offset, and the declared data size must give the same whole-frame count. If they do not agree, the writer raises `ValueError`. It does not fall back.
3. The writer copies every byte before the samples, then reads, embeds, and writes the samples in chunks of whole frames, then copies every byte after the last whole frame. The chunk size is `DEFAULT_CHUNK_BYTES`.

The header, `LIST`/`INFO`, `cue `, `bext`, other chunks before or after `data`, pad bytes, and data bytes after the last whole frame stay byte-for-byte the same. The output length equals the input length. The hashing callbacks still run in protocol order, and `fixed_bytes_callback` receives the original fixed bytes.

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

The splicer holds only chunk offsets, the new `tIME` chunk, and one copy block, so it does not add a decoded-image copy. The PyAV-encoded PNG is staged beside the output in a `.stego-staging-*.png` file. This avoids `/tmp`, which may be RAM-backed, and normal exits remove the staging file.

These rules apply only to encoding. `PngCarrier` loading and verification do not read ancillary chunks. A stego file that later gains a `tRNS` chunk or other metadata still gives the same verdict.

## Source conversion

`stego/sources.py` exposes `detect_source_family()` and the `open_image_source()` / `open_audio_source()` context managers. The detection helper returns the family and source label without decoding a frame. The context managers yield a validated `PngCarrier` or `WavCarrier`. Strict, supported PNG and PCM WAV inputs skip conversion and keep their metadata. Other accepted sources are decoded once with PyAV into a canonical PNG or PCM WAV snapshot in a private `.stego-source-*` directory under the caller's staging parent. The context manager removes that directory after success or failure. Pass the yielded carrier to an `encode_image*()` or `encode_audio*()` function to reuse the same converted source after checking capacity; the convenience functions convert and encode in one call.

Image conversion checks free space for the snapshot and filtering temporary before frame decode. It uses twice a conservative PNG size bound that includes scanline and Deflate overhead, source-file size for copied ancillary chunks, and fixed slack. The still-image allowlist is PNG, JPEG, WebP, AVIF, BMP, TIFF, and GIF, checked by file signature. AVIF is accepted when `avif` or `avis` is a major or compatible ISO-BMFF brand, including `mif1` major-brand files with a compatible `avif` brand. Animated sources remain refused. HEIC/HEIF, JPEG XL, JPEG 2000, PPM, TGA, EXR, and other image formats are refused; image demuxers never enter the video family. It writes RGB or RGBA PNG at 8 bits for sources up to 8 bits and at 16 bits for sources up to 16 bits. The canonical integer values preserve the source component's top bits during depth expansion. Palette and grayscale images expand to RGB; alpha and PNG transparency are retained. EXIF orientations 1–8 are read from bounded JPEG APP1, PNG `eXIf`, WebP EXIF, or TIFF IFD0 data and applied before the snapshot is written. Animated GIF, PNG, and WebP sources are refused before decode. A decoded image over the 715,827,880-byte limit is refused before decode. `pHYs`, EXIF, text, and `sBIT` do not apply to the canonical pixels and are dropped from converted snapshots. Source `cICP`, `mDCV`, and `cLLI` PNG chunks are retained byte-for-byte.

RGB ICC profiles are kept with the RGB snapshot and final PNG. CMYK images are refused with `CMYK images are not supported`. Their CMYK ICC profile is not valid on an RGB PNG, and a colour-managed CMYK-to-RGB conversion needs a library outside PyAV. We refuse these images rather than silently discarding or misapplying the profile.

The audio-source allowlist is WAV with a `pcm_*` codec, MP3 with the MP3 codec, AAC in ADTS, M4A in a MOV/MP4-family container with AAC or ALAC, FLAC with the FLAC codec, and Ogg with Vorbis or Opus. AIFF, WMA, and audio-only Matroska/WebM are refused. Converted audio sources require exactly one audio stream and one or two channels. Strict PCM WAV carriers bypass conversion and accept any positive channel count. Attached cover-art streams and audio tracks alongside a real video stream are ignored by source-family detection; only the selected audio stream is converted when the audio helper is used directly. Lossless integer PCM, FLAC, and ALAC keep 8-, 16-, 24-, and 32-bit samples. Lossless depths below 16 bits become 16-bit PCM without loss; other lossless depths above 16 bits are refused. Lossy or floating-point audio is resampled to 16-bit PCM at its source rate. The conversion keeps all decoded samples, including codec delay or padding. Converted audio can hold up to 4,294,967,256 bytes of PCM data, the largest size that a standard WAV file can record. Metadata that is not part of decoded samples is not copied to converted snapshots. Strict PCM WAV files bypass conversion, so all original chunks remain in the final stego output.

Video sources are accepted only from MP4/MOV, Matroska/WebM, and AVI containers, with one decodable video stream and zero or one audio stream. Audio-only Matroska/WebM is not a video source. Other containers, including image2 and `*_pipe` still-image demuxers, are refused instead of being sent to `VideoCarrier`.

Source conversion only affects encoding. It does not change the version 3 protocol, the verifier, or the verdicts: for images and audio, verification accepts only canonical PNG or PCM WAV. Conversion is a convenience for the sender, not a new wire format, and the original compressed source cannot be recovered from the output.

## Video carrier backend

`VideoCarrier` is the file-backed media-code-3 backend in `stego/video.py`. It performs a bounded scan, then reopens and decodes for range reads, hashing, and rewriting. It exposes ordered RGB low-byte and audio-low-byte carrier units, plus fixed timing, RGB high-byte, alpha, and audio-high-byte data. It supports canonical integer video depths from 8 through 16 bits, with or without alpha; see [Protocol](video-carrier.md#carrier-and-context). PyAV is a required dependency (in `requirements.txt`) and handles all PNG, WAV, and video input and output.

Video sources set `requires_output_check=True`, which makes the core call an extra `CarrierSource.open_rewritten_output(path)` hook after writing. `CarrierEncoding.check_output(source)` verifies output context, embedded transforms, unit/fixed-byte counts, and the masked hash. Core `_rewrite_checked()` owns the sequence: rewrite, open and validate the output reader, close it, then call `finish()`. Any failure removes the incomplete output. PNG and WAV sources skip this step.

`encode_video()` writes one FFV1 video stream at the selected canonical format and optional PCM s16le audio to a same-directory `.stego-staging-*` Matroska file. A bounded audio-only PCM spool beside the output lets the writer mux audio packets up to each video frame's time; it checks free space before creating the spool and removes it on success or failure. The writer still hashes and embeds carrier units in protocol order: all video units, then all audio units. It checks the ordered audio transform against the spool before finishing. The 8-bit format without alpha is `bgr0`. `encode_video_from_payload_path()` uses a private same-directory `.stego-staging-*` directory. Both publish with `os.replace` only after read-back checks and `finish()`. No video spool or second remux stage is used. Failure leaves the destination unpublished and removes staging files.

The initial scan counts carrier units incrementally and checks each canonical frame's byte size before staging. The limits are 512 Gi carrier units, 256 MiB per canonical frame, and 1280 GiB of Matroska output. The payload-path API reserves space for its payload file as well as the 3 GiB free-space reserve. Before each Matroska packet write, the encoder checks for the reserve, that packet's size, and 1 MiB of mux slack. The output-size cap is still checked after each packet. A failed check removes staging and does not publish the output. See [Video Carrier](video-carrier.md) for the resolution and duration examples. Audio is limited to mono or stereo under the channel-identity rule in [Protocol](video-carrier.md#carrier-and-context). Tests mock the required free space, so their results do not depend on the machine's available disk capacity.

## Protocol flow

### Encode

After the backend has validated the cover, the protocol core reads it twice. Video adds a validation and counting scan before this, and a read-back check after writing:

1. Validate inputs and calculate geometry before reading carrier data.
2. Hash every chunk with the bootstrap region and future packet footprint masked. Build and encrypt the record, sign it, and seal the bootstrap.
3. Read the original carrier again. Hash original units, then write bootstrap and packet bits where they overlap each chunk.
4. Confirm the second-pass unit count and hash match the first pass. If the source changed, fail and remove incomplete output.

### Verify

Verification opens and checks the carrier; reads and opens the bootstrap; reads the packet at the recovered position, checks padding, and verifies RSA-PSS; decrypts AES-GCM and parses the record; then makes one full chunked pass for the masked media hash. The backend must be seekable because packet position is known only after bootstrap decryption. Forward-only carrier streams are not supported.

## Chunk size

`DEFAULT_CHUNK_BYTES` is 1 MiB of raw PCM data. Hash-pass throughput was measured on one 96 MiB 16-bit stereo WAV with warm page cache:

| Chunk | Throughput (MiB/s) | Traced peak memory |
| --- | ---: | ---: |
| 16 KiB | 1,420 | 0.17 MiB |
| 64 KiB | 1,733 | 0.28 MiB |
| 256 KiB | 1,834 | 0.75 MiB |
| **1 MiB** | **1,906** | **2.63 MiB** |
| 4 MiB | 1,758 | 10.13 MiB |
| 16 MiB | 1,414 | 40.13 MiB |

We chose 1 MiB because it was the fastest in this measurement, needs only a few MiB of working memory, and is larger than the largest possible PCM frame (65,535 channels × 4 bytes).

## Payload APIs

The library offers two styles of API. The **bytes APIs** take and return the payload as in-memory `bytes`:

- `prepare_carrier_encoding(..., user_payload: bytes, metadata: bytes)`;
- `encode_png(..., user_payload: bytes, metadata: bytes)` and `encode_wav(..., user_payload: bytes, metadata: bytes)`;
- `decode_carrier_source`, `verify_png`, and `verify_wav`, returning `PayloadRecord.user_payload` as `bytes` on `Authentic`.

The **file APIs** read the payload from a file and write recovered payloads to a file, so the payload never has to fit in memory. The public file-based and video functions exported from `stego` are:

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

The file encode functions accept a payload path and metadata bytes. The file verify functions accept an output path. They return `PayloadFileRecord` with the authenticated payload size; `VerificationResult.payload_path` is set only for `Authentic`. The bytes APIs hold the whole input payload and the whole recovered payload in memory. The file APIs keep payload-related memory bounded by their I/O chunk size.

### Streaming cryptography and staging

The AES-GCM record serializer yields fields in order and reads payload files in bounded chunks. Encryption output is written to a staging store while the same ciphertext chunks update the SHA-256 signing prehash. RSA-PSS signs the digest with the protocol's fixed 32-byte salt. Packet embedding reads only the ciphertext ranges that overlap the current carrier chunk.

Verification stages ciphertext and decrypted plaintext privately. It checks the packet signature before GCM decryption, parses the record by offsets, and checks the full media hash before releasing the payload. Bytes APIs use memory staging; file APIs use mode-0600 files inside a private mode-0700 `.stego-staging-*` directory. The bytes backend makes no staging files. On success, only the authenticated payload range is released; file output is published with `os.replace`.

#### Cleanup rule

The staging session owns all of its memory and file resources, and it is always closed: on success, on every verdict, on ordinary exceptions, and on `KeyboardInterrupt`. Closing it clears in-memory buffers, closes open files, and removes the staging directory. A failed verification never creates or replaces the requested output. On success, only the payload file is moved atomically to the output path. If verification fails, any earlier file at that path is left unchanged.

Before the file-backed verifier creates its ciphertext staging file, it checks free space on the staging directory's filesystem. The check requires `3 × ciphertext_length + DISK_SPACE_RESERVE_BYTES`, covering the simultaneous ciphertext, plaintext, and authenticated-payload staging files. A failed check returns `Cannot Verify`; the memory-only verifier does not run this disk check.

A power loss or `SIGKILL` can leave plaintext staging files behind. After a crash, stop the server and delete any `.stego-staging-*` directories by hand. Staging files are not served by the web routes. Temporary disk use grows with encrypted and staged plaintext payload size. Same-size payload input changes during an encode read are not prevented by size checks.

## Memory measurements

These figures come from one local machine. They show the scale of time and memory involved and are not performance guarantees.

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

Packing the bits instead of handling them one at a time also cut memory use:

| State | Case | Encode peak | Verify peak |
| --- | --- | ---: | ---: |
| Before packed handling | 1 MiB payload, `k=3`, 96 MiB WAV | 20.0 MiB | 34.7 MiB |
| After packed handling | 4 MiB payload, `k=8`, about 4 MiB WAV | 12.01 MiB | Not measured with `tracemalloc` |

An earlier timing baseline used a 96 MiB WAV at `k=3`:

| Payload | Encode | Encode peak | Verify | Verify peak |
| --- | ---: | ---: | ---: | ---: |
| 673 B | 0.19 s | 4.3 MiB | 0.06 s | 2.7 MiB |
| 1 MiB | 18.4 s | 20.0 MiB | 4.5 s | 34.7 MiB |

These cases differ in payload size, LSB count, and how verification was measured, so they are examples rather than a controlled speed-up ratio. The full packet-bit arrays we used before took about 8P bytes for a payload of P bytes. The current transform working memory is bounded by `chunk_units x lsb_count`.

File payload streaming was measured on an 8-bit mono WAV at `k=8`: 8 MiB encode plus verify took 0.074 s with 6.40 MiB `tracemalloc` peak; 64 MiB took 0.537 s with 6.39 MiB peak. Both tests run in the default suite.

### PNG carrier memory

This test used a 4341 × 26191 RGBA PNG (about 434 MiB decoded). "Old" is the earlier implementation and "new" is the current one. Encode and verify times are medians of three separate-process runs after one source read. The first encode run of each series was slower (about 9.5 s in two series); the cause was not determined. Verify runs did not show this. Peak RSS includes Python and native decoder/encoder allocations and is not a limit or guarantee.

| Operation | Old time | New time | Old peak RSS | New peak RSS |
| --- | ---: | ---: | ---: | ---: |
| Encode | 8.1 s | 5.47 s | 1,571 MiB | 947.2 MiB |
| Verify | 1.9 s | 2.16 s | 1,350 MiB | 947.0 MiB |

Copying ancillary chunks into the output (see [Metadata in the output](#metadata-in-the-output)) did not change these figures. With and without that change, three separate-process encode runs of the same PNG gave a median of 5.68 s and about 947 MiB peak RSS. The output kept the input `bKGD` chunk.

A separate fixed-key check on RGB and RGBA carriers compared full carrier-unit reads and identity-rewrite outputs; both matched exactly. The encoded files were not compared because encoding uses random nonce material.

#### PNG implementation measurements

This comparison covers the switch to direct PyAV frame writes and PNG encoder tuning. It used three fresh processes per operation with a small payload. The source was 4341 × 26191 RGBA (113,695,131 pixels). Times and peak RSS include Python startup and native media buffers; RSS is a host-specific measurement, not a limit.

| Source | Operation | Before median | Before peak RSS | After median | After peak RSS |
| --- | --- | ---: | ---: | ---: | ---: |
| `samples/Banana.png` | Encode | 0.350 s | 80.5 MiB | 0.098 s | 94.7 MiB |
| `samples/Banana.png` | Verify | 0.063 s | 80.8 MiB | 0.038 s | 75.1 MiB |
| 4341 × 26191 RGBA | Encode | 5.365 s | 948.1 MiB | 3.517 s | 1870.8 MiB |
| 4341 × 26191 RGBA | Verify | 2.106 s | 948.0 MiB | 1.351 s | 938.2 MiB |

The PyAV PNG encoder uses `compression_level=1` and `pred=up`, selected from the large-image measurement. Direct writes into a PyAV frame removed the full output ndarray and saved 431 MiB (about 19%) from the first encode peak. Keeping the decoded ndarray as a read-only view removed a decode copy and reduced verify peak by about 430 MiB. Setting encoder `thread_count=1` did not reduce peak RSS. On the large image, the final encode peak is 1.97 times the earlier peak, while the verify peak is 1.0% lower. The 2400×2400 RGBA memory test passes with its original `2.5 × decoded bytes + 2 MiB` traced-memory bound. These are host-specific measurements, not guarantees.

#### 16-bit PNG measurements

The generated RGBA source was 7746 × 7746 pixels: 60,000,516 pixels and 480,004,128 decoded bytes. It was written by PyAV with a smooth deterministic pattern (41,930,550-byte PNG). Each encode and verify ran in three fresh processes with the same small payload. Peak RSS is a process maximum and includes PyAV and Python allocations.

| Source | Operation | Median time | Median peak RSS |
| --- | --- | ---: | ---: |
| 16-bit RGBA, 7746 × 7746 | Encode | 5.129 s | 2011.6 MiB |
| 16-bit RGBA, 7746 × 7746 | Verify | 1.843 s | 1519.6 MiB |
| 8-bit RGBA, 4341 × 26191 | Encode | 3.517 s | 1870.8 MiB |
| 8-bit RGBA, 4341 × 26191 | Verify | 1.351 s | 938.2 MiB |

The two images have different decoded sizes (480,004,128 and 454,780,524 bytes). So these are host-specific examples, not a direct per-byte speed comparison.

## WAV and request storage

`WavCarrier` reads whole PCM frames, verifies headers when reopening the file, checks the last declared frame on open, and preserves sample bytes outside the low-byte carrier unit. A short file fails early. File reads and early-end failures become `CarrierAccessError`; verification maps these to `Cannot Verify`. WAV output is a chunked copy of the input file with only the declared samples patched; see [Metadata in the output](#metadata-in-the-output). In one local measurement, three encode runs on a 96 MiB 16-bit stereo WAV took about 0.3 s each with 54 MiB peak RSS.

Flask has no fixed request-size cap by default. Before reading an encode or verify body, it returns 411 if `Content-Length` is missing. It rejects a declared length greater than the free space in `STEGO_WORK_DIR` minus the shared 3 GiB reserve. Multipart streams and request-scoped temporary files use `STEGO_WORK_DIR`, defaulting to `instance/work` on the same filesystem as carrier outputs. On systems where `/tmp` is RAM-backed, storing uploads there can consume memory. A deployment can still set `MAX_CONTENT_LENGTH`. Encode outputs go to `instance/stego-outputs`; authenticated recovered payloads and sidecars go to `instance/recovered-payloads`. These files never expire; users delete them by hand. Recovered payloads are plaintext on disk. The service returns URLs, not carrier or payload Base64. Browser responses use `Cache-Control: no-store`.

## Limits and risks

- Application-side carrier and file-payload buffers use chunks. A canonical decoded frame is limited to 256 MiB, so frame-sized working memory is bounded by this cap times a small number of working copies. Converted PNG/WAV outputs are checked before writing; PNG reserves space for the encoder temporary and final output, while WAV reserves its source size. Payload-file encoding also reserves its payload size. The 640×360 video-plus-audio RSS test measured 182,648 KiB at 5 seconds and 219,328 KiB at 15 seconds (about 36 MiB more); these are measurements, not a guarantee. Audio sample rate, samples per decoded audio frame, and compressed packet size have no explicit caps before FFmpeg/PyAV allocates decoded data. This is not an absolute guarantee against hostile media. Payload and cryptographic buffers grow with packet size, and PNG requires a full decoded image plus an output image during rewrite.
- Verification is not a snapshot. A file changed between targeted reads and the final hash pass can yield a verdict based on more than one state. WAV headers are checked on reopen, but frame data is not locked.
- AES-GCM produces plaintext before it has checked the tag, so that plaintext is not yet authenticated. This is why we stage it privately and publish it only after every check passes.
- Temporary disk space is proportional to encrypted and staged plaintext payload sizes. A crash may leave plaintext staging as described by the cleanup rule.
- Atomic replacement requires staging and output paths on the same filesystem.
- Flask has no fixed request-size cap by default. It returns 411 for a request without `Content-Length`, and its free-space guard rejects a declared body that exceeds the free space in `STEGO_WORK_DIR` minus the shared 3 GiB reserve; deployments can set `MAX_CONTENT_LENGTH`. PNG images have a 715,827,880-byte decoded-size cap checked before decode, and FFmpeg also receives a format-specific `max_pixels` limit. Converted audio can hold up to 4,294,967,256 bytes of PCM data, the largest size that a standard WAV file can record. It checks the shared reserve before the first PCM write and after each 64 MiB of output.

## See also

For Flask request handling, upload storage, verification responses, and payload downloads, see the [web application guide](web-application.md).
