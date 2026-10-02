# Carrier and payload flow

This guide describes how the `stego` library reads a cover, converts it if needed, embeds the packet, and writes the output. It also covers how payloads are staged and cleaned up, and how much memory and time this takes. Terms are defined in the [glossary](README.md#glossary).

## Encode flow

```text
cover file
   │  convert if not already PNG / PCM WAV      (see Source conversion)
   ▼
carrier ── pass 1: read all units, compute the media hash
   │       build the record, encrypt it, sign it, encrypt the bootstrap
   ▼
carrier ── pass 2: read again, write bootstrap and packet bits into a staging file
   │       check the hash matches pass 1 (the cover did not change)
   ▼
staging file ── video only: read back and check the output
   │
   ▼
output file (moved into place with os.replace)
```

If any step fails, the staging file is deleted and no output is created.

## Verify flow

1. Open the carrier and check its format.
2. Read the bootstrap and decrypt it.
3. Read the packet at the recovered position, check padding, and verify the signature.
4. Decrypt the record into a private staging area and parse it.
5. Read the whole carrier once more to compute the media hash.
6. If the verdict is `Authentic`, move the payload to the output path.

The carrier must allow random access, because the packet position is only known after step 2.

## Carrier interface

`PngCarrier`, `WavCarrier`, and `VideoCarrier` implement the `CarrierSource` interface used by `stego/core.py`:

| Method | Purpose |
| --- | --- |
| `read_units()` | Read a range of carrier units |
| `iter_chunks()` | Read all units in order, in chunks |
| `iter_chunks_with_fixed_bytes()` | Read units and fixed bytes together in one pass |
| `rewrite_to_path()` | Write the output in one pass, embedding bits as it goes |

`VideoCarrier` also implements `open_rewritten_output()`, so the core can read back and check the video output before publishing it.

## Memory use

We read and write in chunks wherever the format allows, so memory does not grow with file size. PNG is the exception.

| Data | Memory |
| --- | --- |
| PNG carrier | The whole decoded image (up to 715,827,880 bytes), plus one output frame |
| WAV carrier | Whole PCM frames in chunks of 1 MiB |
| Video carrier | One decoded frame at a time (up to 256 MiB per frame) |
| Payload, file APIs | Chunks only |
| Payload, bytes APIs | The whole payload |
| LSB changes | At most chunk size × LSB count |

## Source conversion

Covers that are not already a valid PNG or PCM WAV carrier are converted once, before encoding, into a temporary PNG or WAV in a private `.stego-source-*` folder. The folder is deleted when encoding ends. PNG and PCM WAV files that already meet the carrier rules are used as they are and keep their metadata.

Conversion only affects encoding. Verification still accepts only PNG, PCM WAV, and MKV carriers, and the original compressed file cannot be recovered from the output.

### Images

| Source | Result |
| --- | --- |
| PNG, JPEG, WebP, AVIF, BMP, TIFF, GIF (detected by file signature) | Converted to RGB or RGBA PNG |
| Up to 8 bits per component | 8-bit PNG |
| 9 to 16 bits per component | 16-bit PNG (top bits kept) |
| Palette or grayscale | Expanded to RGB |
| Alpha or PNG transparency (`tRNS`) | Kept as an alpha channel |
| EXIF orientation 1 to 8 | Applied to the pixels |
| RGB ICC profile, `cICP`, `mDCV`, `cLLI` | Kept |
| `pHYs`, EXIF, text, `sBIT` | Dropped |
| CMYK | Refused: `CMYK images are not supported` |
| Animated GIF, PNG, or WebP | Refused |
| Decoded size over 715,827,880 bytes | Refused before decoding |

AVIF is accepted when `avif` or `avis` is the major or a compatible brand, including files whose major brand is `mif1`. Before converting, the converter checks that there is room for about twice the PNG size plus the 3 GiB reserve.

CMYK is refused because its ICC profile is not valid on an RGB PNG, and PyAV has no colour-managed CMYK-to-RGB conversion.

### Audio

| Source | Result |
| --- | --- |
| PCM WAV, MP3, AAC (ADTS), M4A (AAC or ALAC), FLAC, Ogg (Vorbis or Opus) | Converted to PCM WAV |
| Lossless integer audio at 8, 16, 24, or 32 bits | Same bit depth |
| Lossless integer audio at other depths up to 16 bits | 16-bit |
| Lossless integer audio at other depths over 16 bits | Refused |
| Lossy or floating-point audio | 16-bit, at the original sample rate |
| More than one audio stream, or more than two channels | Refused |

- All decoded samples are kept, including codec delay and padding.
- Metadata is not copied to converted files.
- Converted audio can hold up to 4,294,967,256 bytes of PCM data, the largest size a WAV file can record. Free space is checked before writing and after every 64 MiB.
- A PCM WAV used directly (without conversion) can have any number of channels.

### Video

Video is accepted from MP4/MOV, Matroska/WebM, and AVI with one video stream and at most one audio stream. It is not converted to a separate file first; `VideoCarrier` decodes it directly. See the [video carrier guide](video-carrier.md).

## Metadata in the output

Metadata outside the media hash is copied to the output where it is still correct after embedding. It does not affect verification.

### WAV

The output is a byte-for-byte copy of the input, except for the sample bytes. All chunks (`LIST`, `cue `, `bext`, and others), padding, and trailing bytes stay the same, and the file length does not change. If the RIFF headers and Python's `wave` module disagree about where the samples start, encoding stops.

### PNG

The image chunks (`IHDR`, `IDAT`, `IEND`) come from the new image. Other chunks are handled as follows:

| Input chunk | Output |
| --- | --- |
| `tEXt`, `zTXt`, `iTXt`, `eXIf`, `pHYs`, `iCCP`, `sRGB`, `gAMA`, `cHRM`, `bKGD`, `sPLT`, `PLTE` | Copied |
| `tIME` | Updated to the encode time (UTC) |
| More than one `tIME` | Encoding stops |
| `sBIT`, `hIST` | Dropped, because they describe the old pixel values |
| `tRNS` in an RGB PNG | Encoding stops: `RGB PNG with a tRNS colour key is not supported; convert the image to RGBA`. Source conversion handles this by converting to RGBA. |
| `tRNS` in an RGBA PNG | Dropped |
| Unknown chunk marked safe to copy | Copied |
| Unknown chunk not marked safe to copy | Dropped |
| Unknown critical chunk | Encoding stops |

Copied chunks keep their order and position (before or after the image data). The PNG is first written to a `.stego-staging-*.png` file next to the output.

## Payload APIs

| | Bytes APIs | File APIs |
| --- | --- | --- |
| Functions | `encode_png`, `encode_wav`, `verify_png`, `verify_wav`, `prepare_carrier_encoding`, `decode_carrier_source` | `encode_png_from_payload_path`, `encode_wav_from_payload_path`, `verify_png_to_payload_path`, `verify_wav_to_payload_path`, and the video equivalents |
| Payload input | `bytes` | Path to a file |
| Recovered payload | `bytes` in the result | Written to an output path |
| Memory | Whole payload | Chunks only |
| Staging | In memory | Private files on disk |

The web app uses the file APIs.

## Staging and cleanup

During encoding, the record is encrypted in chunks. The ciphertext is written to staging while the same chunks feed the signature hash.

AES-GCM produces plaintext before it has checked the tag, so verification writes the plaintext to private staging and only releases it after every check passes.

- File APIs stage in a `.stego-staging-*` folder (mode 0700) with files of mode 0600.
- Before staging to disk, the verifier checks for free space of 3 × the ciphertext length plus the 3 GiB reserve. If there is not enough, the verdict is `Cannot Verify`.
- Staging is always cleaned up: on success, on every verdict, on errors, and on `KeyboardInterrupt`.
- A failed verification never creates or replaces the output file.
- Staging and output must be on the same filesystem, so the final move is atomic.

### Cleanup rule

A power cut or `SIGKILL` can leave `.stego-staging-*` folders behind, and they may contain unencrypted payload data. Stop the server and delete them by hand. The web routes never serve staging files.

## Chunk size

`DEFAULT_CHUNK_BYTES` is 1 MiB. We chose it from this hash-pass measurement on a 96 MiB 16-bit stereo WAV:

| Chunk | Speed (MiB/s) | Peak memory |
| --- | ---: | ---: |
| 16 KiB | 1,420 | 0.17 MiB |
| 64 KiB | 1,733 | 0.28 MiB |
| 256 KiB | 1,834 | 0.75 MiB |
| **1 MiB** | **1,906** | **2.63 MiB** |
| 4 MiB | 1,758 | 10.13 MiB |
| 16 MiB | 1,414 | 40.13 MiB |

1 MiB was the fastest, uses little memory, and is larger than the largest possible PCM frame (65,535 channels × 4 bytes).

## Measurements

These figures come from one local machine and are not guarantees.

| Case | Time | Peak memory |
| --- | ---: | ---: |
| Encode, 8-bit RGBA PNG, 4341 × 26191 (434 MiB decoded) | 3.517 s | 1,870.8 MiB |
| Verify, same PNG | 1.351 s | 938.2 MiB |
| Encode, 16-bit RGBA PNG, 7746 × 7746 (458 MiB decoded) | 5.129 s | 2,011.6 MiB |
| Verify, same PNG | 1.843 s | 1,519.6 MiB |
| Encode, 96 MiB 16-bit stereo WAV | about 0.3 s | 54 MiB |
| Encode and verify, 64 MiB file payload, 8-bit WAV, `k`=8 | 0.537 s | 6.39 MiB |

PNG times are medians of three runs. Peak memory is the process maximum for PNG and WAV, and Python allocations (`tracemalloc`) for the payload case. The PNG encoder uses `compression_level=1` and `pred=up`, which were fastest on the large image. Writing and reading bits in packed arrays instead of one at a time made LSB reads and writes over 100 times faster.

## Limits

- PNG needs the whole decoded image in memory, plus an output frame.
- Audio sample rate, audio frame size, and compressed packet size have no explicit limits before FFmpeg decodes them, so memory use for hostile files is not fully bounded.
- Verification is not a snapshot. A file changed during verification can give a verdict based on two versions of it.
- A payload file that changes during encoding without changing size is not detected by the size check.
- Temporary disk use grows with the payload size.

For request handling and upload storage, see the [web application guide](web-application.md).
