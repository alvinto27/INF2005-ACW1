# PyAV Migration Record

**Status:** Stages S1–S4 are accepted. This record gives the migration history and evidence. It is not the source of current rules. Use [Current Protocol](CURRENT-PROTOCOL.md), [Carrier and Payload Flow](CARRIER-AND-PAYLOAD-FLOW.md), and [Web Application Guide](WEB-APPLICATION-GUIDE.md) for current behavior.

## Goal

Use PyAV as the only media library in the application. PyAV must handle runtime media I/O. PyAV is a required dependency. Pillow is used only by tests and the demonstration notebook.

The migration kept protocol version 3. It did not change the signature, encryption, media hash, or verification verdicts. Source conversion is an encode-side feature. Verification still reads canonical PNG, PCM WAV, and supported video carriers. `Authentic` does not prove which source file was used. For example, it does not authenticate the original JPEG or MP3 bytes. It authenticates the decoded canonical carrier data and the signed protocol record. See the current [protocol authenticity boundary](CURRENT-PROTOCOL.md#hash-rule-and-carrier-interpretation).

## Stages

| Stage | Commit | Change |
| --- | --- | --- |
| S1 — PyAV PNG I/O | [`6378bdf`](https://github.com/alvinto27/INF2005-ACW1/commit/6378bdfd99331600fd4b1fd0e7fcb4d7ddfb4106) | Replaced Pillow PNG carrier decode and encode with PyAV. Kept strict 8-bit RGB/RGBA rules, chunk handling, error behavior, and size checks. Made PyAV required and restored web route test coverage. |
| S2 — 16-bit PNG | [`c66384d`](https://github.com/alvinto27/INF2005-ACW1/commit/c66384d33293e4a17481a7a061c36a3130173870) | Added strict 16-bit RGB/RGBA PNG carriers. Set sample ordering and context rules. Added the 715,827,880-byte decoded-size cap and checked it before decode. |
| S3 — source conversion | [`0a7f553`](https://github.com/alvinto27/INF2005-ACW1/commit/0a7f553053663a14ce47db1f31c3b8417bdbbd6c) | Added PyAV conversion from supported still-image and audio sources to temporary canonical PNG/WAV. Kept strict PNG and PCM WAV on the direct path. Added orientation, depth, channel, metadata, and size rules, with tests. |
| S4 — web sources | [`38ecc23`](https://github.com/alvinto27/INF2005-ACW1/commit/38ecc23c91aa387edefc90f922171a46b05c2386) | Added common image and audio sources to the web encode route. Added source metadata to its response and conversion messages to the interface. Kept verification PNG/WAV-only and refused real video in the web app. |

## Decisions

- **PyAV is required.** Runtime image, audio, and video I/O uses PyAV. Pillow is test/notebook-only.
- **16-bit PNG uses Option A.** An 8-bit PNG keeps the 9-byte `>IIB` context. A 16-bit PNG uses a 10-byte `>IIBB` context with depth 16. Carrier units use the low byte of the numeric RGB sample. The fixed-byte stream uses the corresponding high bytes and alpha bytes in the defined order. The current ordering is in [Current Protocol](CURRENT-PROTOCOL.md#hash-rule-and-carrier-interpretation).
- **PNG size cap.** Refuse a decoded image larger than 715,827,880 bytes before decode. Current dimensions and error behavior are in [Current Protocol](CURRENT-PROTOCOL.md#carrier-units).
- **Canonical image depth.** Convert sources up to 8 bits to 8-bit RGB/RGBA PNG. Convert sources above 8 bits and up to 16 bits to 16-bit PNG. PyAV's conversion replicates lower-depth integer bits when it expands a sample; for example, the top bits of a 10-bit AVIF sample match the source value. Refuse floating-point and over-16-bit sources. Current limits are in [Carrier and Payload Flow](CARRIER-AND-PAYLOAD-FLOW.md#source-conversion).
- **Image metadata.** Keep tested RGB ICC profiles and applicable PNG colour chunks. Converted sources drop pHYs, EXIF, and text metadata that does not describe the canonical pixels. Strict carrier metadata rules and converted-source rules are in [Carrier and Payload Flow](CARRIER-AND-PAYLOAD-FLOW.md#metadata-in-the-output) and [Source conversion](CARRIER-AND-PAYLOAD-FLOW.md#source-conversion).
- **CMYK.** Refuse CMYK with `CMYK images are not supported`. A CMYK ICC profile is not valid on an RGB PNG. A correct colour-managed conversion needs a library outside PyAV. No profile is silently dropped or applied to the wrong colour model.
- **Audio depth.** Keep decoded integer sample width for lossless integer PCM, FLAC, and ALAC. Convert lossy or floating-point audio to 16-bit PCM at the source rate. Keep every decoded sample, including codec delay or padding. The library source converter ignores video streams when it selects the one audio stream; the web app refuses real video tracks. See [Source conversion](CARRIER-AND-PAYLOAD-FLOW.md#source-conversion) and [Web Application Guide](WEB-APPLICATION-GUIDE.md#encode-request).
- **Source authenticity.** A converted carrier does not authenticate its original compressed source, source metadata, or decoder settings. The source label shown by the web app is informational. The protocol authenticates the canonical carrier data and record only.

## P0 and S3a evidence

### Pixel parity

The P0/S1 checks compared complete carrier-unit reads and identity rewrites for RGB and RGBA PNG inputs. The output pixels matched exactly. Fixed-key checks matched; encoded-file byte comparisons were not used because each encode has a random nonce. S3a tested orientation filters for all eight EXIF values against Pillow's orientation result. Converted output pixels matched exactly for the supported test fixtures. PyAV SideData was not needed for orientation.

### PNG speed and memory

These are historical host measurements from three fresh processes per operation for the S1 before/after rows. They include Python startup and native media buffers. They are not performance guarantees. The large 8-bit image was 4341 × 26191 RGBA.

| Input | Operation | Before time / peak RSS | After time / peak RSS |
| --- | --- | ---: | ---: |
| `samples/Banana.png` | Encode | 0.350 s / 80.5 MiB | 0.098 s / 94.7 MiB |
| `samples/Banana.png` | Verify | 0.063 s / 80.8 MiB | 0.038 s / 75.1 MiB |
| 4341 × 26191 RGBA | Encode | 5.365 s / 948.1 MiB | 3.517 s / 1870.8 MiB |
| 4341 × 26191 RGBA | Verify | 2.106 s / 948.0 MiB | 1.351 s / 938.2 MiB |

The large encode became faster but used more peak memory after PyAV PNG encoding. A separate 16-bit test used a 7746 × 7746 RGBA image, with 480,004,128 decoded bytes. Its encode median was 5.129 s at 2011.6 MiB peak RSS; verify was 1.843 s at 1519.6 MiB. The detailed measurements and later memory changes are in [Carrier and Payload Flow](CARRIER-AND-PAYLOAD-FLOW.md#png-carrier-memory).

### SideData and orientation

Reading a PyAV ICC_PROFILE SideData wrapper caused a process-level SIGSEGV in a probe. The code does not read PyAV SideData wrappers. Bounded JPEG, WebP, and PNG parsers detect an ICC profile. The PyAV filter graph and PNG encoder carry the profile into `iCCP`. Tested RGB ICC profiles survived the JPEG snapshot and final PNG byte-for-byte.

The converter uses a bounded EXIF parser. It reads orientation from supported JPEG APP1, PNG `eXIf`, WebP EXIF, and TIFF IFD0 data. It applies verified PyAV filter chains for orientations 1–8. It does not trust unbounded metadata sizes or depend on SideData.

### Audio check

The AAC probe decoded 240,640 samples per channel although the stream declared 240,000. The extra 640 samples are codec delay or padding. PCM output kept all decoded samples. The measured probe is recorded in [Video Carrier Design](VIDEO-CARRIER-DESIGN.md#g3-aac-details).

## Current rules

This record does not replace current guides. Use:

- [Current Protocol](CURRENT-PROTOCOL.md) for wire format, hash, context, verdicts, and compatibility.
- [Carrier and Payload Flow](CARRIER-AND-PAYLOAD-FLOW.md) for PNG/WAV I/O, source conversion, limits, and metadata.
- [Web Application Guide](WEB-APPLICATION-GUIDE.md) for accepted web sources, video refusal, response fields, and status rules.
