# Current Protocol

**Status:** Protocol version 3 is implemented. This file is the source of truth for the current masked-media wire format, security checks, compatibility, and typed-payload rules. Historical version 1 decisions are in [Protocol Version 1 History](PROTOCOL-V1-HISTORY.md).

## Overview

The protocol embeds a signed, encrypted payload in 8-bit or 16-bit RGB or RGBA PNG carrier units, in the least-significant byte of each uncompressed PCM WAV sample, or in the optional video-plus-audio carrier with media code 3. An RSA-OAEP bootstrap carries packet geometry and AES-256-GCM session material to the intended receiver. RSA-PSS authenticates the ciphertext and carrier interpretation. Verification needs the sender public key and receiver private key. The packet has no public marker or header; version 1 and version 2 files are not readable by the active protocol.

Every media-data byte preserved by embedding is covered by the version 3 full media hash. The payload record contains that hash and the user content. The signature authenticates the record ciphertext, media interpretation, and embedding layout. It does not authenticate overwritten cover LSBs or identify a real-world person.

## Hash rule and carrier interpretation

Version 3 hashes two streams:

1. `unit_digest` is SHA-256 over carrier units in order after clearing the lowest bit in the reserved bootstrap span and the lowest `lsb_count` bits in the packet footprint, including alignment padding.
2. `fixed_digest` is SHA-256 over all media-data bytes that embedding does not change. For 8-bit RGBA PNG it includes alpha bytes in pixel order. For 16-bit PNG it includes the high byte of every RGB value in unit order, then, for RGBA, every 16-bit alpha value as little-endian bytes in pixel order. WAV fixed bytes are every non-carrier byte of each declared multi-byte PCM sample. Empty input uses the normal SHA-256 empty digest.

The final hash is:

```python
media_hash = SHA256(
    b"INF2005-ACW1\x00MEDIA-HASH-V3\x00"
    + struct.pack(">BB", media_code, lsb_count)
    + encode_protocol_field(total_units, "total_units")
    + encode_protocol_field(fixed_byte_count, "fixed_byte_count")
    + encode_protocol_field(start_unit, "start_unit")
    + encode_protocol_field(footprint, "footprint")
    + encode_protocol_field(bootstrap_span, "bootstrap_span")
    + unit_digest
    + fixed_digest
)
```

All integer fields here use unsigned 64-bit big-endian encoding. The stream digests are 32 bytes each. Chunk boundaries do not affect either digest.

PNG input must be a single-frame, 8-bit or 16-bit RGB or RGBA image. Each pixel has three carrier units: the low byte of R, G, and B in row-major order. For 16-bit samples, each unit is the low-order byte of the numeric sample value, not the byte at the lower memory address. The fixed bytes for 16-bit images follow the order above. The 8-bit RGBA fixed-byte rule remains unchanged. WAV carrier units are the low byte of each declared PCM sample. Other sample bytes are fixed data. PNG ancillary chunks and WAV chunks outside declared PCM samples are not hashed. The encoder output keeps them: it copies PNG ancillary chunks that stay true after embedding and every WAV byte outside the declared samples. It updates an existing PNG `tIME` to the encode time. It drops `sBIT`, `hIST`, an RGBA `tRNS`, and unknown chunks that are not safe to copy. The strict PNG adapter refuses to encode an RGB PNG with a `tRNS` colour key. The source converter can convert such an image to RGBA and keep the transparency as alpha. Because ancillary chunks are not hashed, a change to them does not change the verdict. This is a carrier-output rule, not a wire-format change; see [Carrier and Payload Flow](CARRIER-AND-PAYLOAD-FLOW.md#metadata-in-the-output).

An 8-bit PNG media context remains the 9-byte `struct.pack(">IIB", width, height, channel_count)`. A 16-bit PNG uses the 10-byte `struct.pack(">IIBB", width, height, channel_count, 16)`. Existing 8-bit files keep their old context and remain compatible. WAV context is `struct.pack(">HBIQ", channels, sample_width, frame_rate, frame_count)`.

The core protocol still reads strict PNG and PCM WAV carriers only. The optional `stego.sources` encode helpers accept supported image and audio files, convert non-strict sources once into temporary canonical PNG/WAV carriers, then call the same protocol encoders. Strict carriers bypass conversion. This does not change verification, the wire format, or verdicts. See [Source conversion](CARRIER-AND-PAYLOAD-FLOW.md#source-conversion) for accepted formats, conversion limits, and cleanup.

### Video-plus-audio media code 3

The optional video carrier uses media code **3** and media-ID prefix **`VID-`**. It keeps the version-3 wire format unchanged. Its 32-byte media context is `struct.pack(">IIQBBIHQ", width, height, frame_count, canonical_video_depth, video_channel_count, audio_sample_rate, audio_channels, audio_frames_per_channel)`. The video channel count is 3 without alpha and 4 with alpha. With no audio, all three audio fields are zero. The context signs the video depth and channel count, not channel identities. For a source pixel format, let `S` be the largest component bit depth, including alpha. Reject floating-point formats and `S > 16`. Select the smallest canonical depth `D >= S` from these tables:

| Source depth `S` | No alpha `D` | Alpha `D` |
| ---: | ---: | ---: |
| 1–8 | 8 | 8 |
| 9 | 9 | 10 |
| 10 | 10 | 10 |
| 11–12 | 12 | 12 |
| 13–14 | 14 | 14 |
| 15–16 | 16 | 16 |

The decoder converts each source frame to the selected canonical RGB or RGBA format. The encoder keeps the resulting canonical integer values, except for the selected RGB low bits; it does not normalize them to the full range of the canonical depth. The canonical values can differ from the source component values, for example after a YUV-to-RGB conversion or a 9-bit-to-10-bit promotion. A source depth or alpha-presence change during decode is refused. The current video carrier accepts one audio channel with FC identity or unspecified identity, and two channels with FL, FR identities in that order or two unspecified identities. Matroska PCM records the channel count but not the channel mask, so this rule accepts the unspecified layouts produced by our own output. It treats unspecified one- and two-channel audio as mono and stereo. It refuses any other specified identity or channel order with `unsupported audio channel layout`; counts other than one or two return `unsupported audio channel count`.

Video carrier units are the low byte of each canonical R, G, and B value, in row-major pixel order and frame presentation order. Alpha values are never carrier units. The fixed-byte digest receives each frame's signed big-endian i64 millisecond tick, then all RGB high bytes in R/G/B order when `D > 8`, then the alpha values (one byte at `D = 8`, otherwise two-byte little-endian values) when alpha is present. Audio carrier units follow all video units: they are the low byte of each decoded interleaved signed 16-bit little-endian sample. If audio exists, its fixed bytes follow video fixed bytes and contain one signed i64 audio-start tick followed by one high byte per audio sample. Chunk boundaries have no meaning and do not affect the hash.

Timestamp seconds are calculated exactly as `pts * time_base`. The first decoded video frame is time zero for each carrier read, including read-back after the Matroska muxer shifts timestamps. Canonical video timing contains frame-start presentation timestamps only. The last frame's display duration, stream duration, and container duration are not authenticated. The FFV1 stream's nominal `rate=25` is not signed; explicit frame-start ticks carry the canonical timing. Each frame-start timestamp and the audio-start offset from the video origin are rounded to the nearest millisecond, with ties away from zero. Missing, non-increasing, or colliding video ticks are refused. Audio continuity compares frame timestamps with the expected sample position. Audio frame timestamp deviations of at most half a millisecond (rounded up to a whole sample) are treated as container timestamp quantization. A real gap or overlap within that tolerance cannot be distinguished and is accepted; larger ones are refused. The reader converts audio to s16 without resampling or changing sample order; accepted channel identities follow the rule above.

Video resource limits are defined in [Video Carrier Design](VIDEO-CARRIER-DESIGN.md).

Video authenticity covers the signed context, decoded canonical RGB and alpha values, canonical timing ticks, decoded s16 sample bytes, audio timing, masked media hash, and embedded packet. It does not cover container bytes, title or other tags, chapters, subtitles, attachments, rotation/display matrix, display aspect metadata, colour primaries, transfer characteristics, colour range, or additional tracks. The carrier drops colour metadata; HDR PQ/HLG video may therefore display with incorrect colours in players. The current video carrier drops tags and extra streams; a file with unsupported extra streams is refused rather than silently selected. Decoder threading uses FFmpeg automatic mode for speed and does not alter the protocol. Tested FFV1 decoding is lossless, and tested H.264/AAC decoding produced identical RGB/s16 and fixed bytes under automatic and single-slice thread settings. If any input decode differs between passes, its hash check fails; if read-back differs, output validation fails. Both failures stop encoding before publication.

The encoder and verifier mask the same carrier regions before hashing. The hash therefore stays reproducible when only the bits used for embedding change. A start unit below the reserved bootstrap span is rejected.

## Carrier units

A PNG carrier unit is the low byte of one R, G, or B sample value; RGB and RGBA pixels have three units at both supported PNG depths. For 16-bit samples, this is the low byte of the numeric value, regardless of byte order in memory. A WAV carrier unit is one PCM sample's low byte, not one file byte. For multi-byte samples the other bytes are fixed data and are hashed. Capacity therefore scales by `1 / sample_width` compared with counting all sample bytes.

Accept only single-frame, 8-bit or 16-bit PNG images with RGB or RGBA colour type. Reject palette, grayscale, grayscale-alpha, 1/2/4-bit, animated, and other PNG modes. A non-PNG file keeps `UnSupportedFileType`. Unsupported colour type reports `PNG must be RGB or RGBA; palette and grayscale images are not supported`; an invalid sample depth reports `PNG must use 8-bit or 16-bit RGB or RGBA samples`; animation reports `animated PNG images are not supported`. The strict PNG adapter refuses RGB PNG with a `tRNS` colour key at either depth with the existing conversion message; the source converter instead turns this key into RGBA alpha. The decoded-byte limit is 715,827,880 bytes. The exact pre-decode refusal is `PNG decoded size exceeds configured limit: {bytes} bytes > {limit} bytes`. The byte count is width × height × channels × bytes per sample. FFmpeg `max_pixels` is also set from this limit as a second decoder guard. This gives these maximum pixel counts:

| PNG format | Maximum pixels |
| --- | ---: |
| 8-bit RGB | 238,609,293 |
| 8-bit RGBA | 178,956,970 |
| 16-bit RGB | 119,304,646 |
| 16-bit RGBA | 89,478,485 |

## Wire format and signing

The payload record, before encryption, is:

```text
media_id_length  u8
media_id         media_id_length bytes of UTF-8
timestamp        u64, Unix seconds in UTC
nonce            16 bytes
media_hash       32 bytes
user_length      u64
user_payload     user_length arbitrary bytes
metadata_length  u64
metadata         metadata_length bytes of UTF-8
```

General lengths, positions, counters, and timestamps use unsigned 64-bit big-endian fields. Bounded enumerations and prefix lengths use u8. The generated 36-byte media identifier gives 109 bytes of record overhead before user payload and metadata. The complete record is encrypted as a whole using AES-256-GCM.

The packet is `ciphertext || 256-byte RSA-PSS signature`, followed by zero alignment bits needed to fill the last carrier unit. The ciphertext length includes the 16-byte GCM tag. The signing input is:

```text
SIGNING_DOMAIN
|| version(u8) || media_code(u8) || lsb_count(u8)
|| total_units(u64) || start_unit(u64) || footprint(u64)
|| ciphertext_length(u64) || media_context || ciphertext
```

The signing version comes from `PROTOCOL_VERSION`, not received bootstrap data. RSA-PSS uses SHA-256 and a fixed 32-byte salt. The signer hashes the signing input in a stream and signs the digest with RSA-PSS over `Prehashed(SHA256())`; this gives the same signature as normal RSA-PSS/SHA-256 over the whole input, so the wire format does not change. The signature is checked before decryption. AES-GCM authenticates the ciphertext and additional data under the supplied session key and nonce; the protocol makes no key-commitment claim.

The bootstrap plaintext is:

```text
version             u8
lsb_count           u8
start_unit          u64
ciphertext_length   u64
session_key         32 bytes
aead_nonce          12 bytes
```

It is 62 bytes. Its GCM additional data is version, LSB count, start unit, and ciphertext length, totalling 18 bytes. The fixed RSA-2048 bootstrap span is 2,048 carrier units.

The packet footprint is derived as:

```python
packet_bits = (ciphertext_length + 256) * 8
footprint = (packet_bits + lsb_count - 1) // lsb_count
pad_bits = footprint * lsb_count - packet_bits
```

## Typed payload metadata

Protocol version 3 encrypts the complete payload record, including `user_payload`. Typed-file demonstrations keep raw file bytes in `user_payload` and put the MIME claim and bare filename in the existing metadata field:

```text
kind=png;flow=typed-content;mime=image/png;name=generated.png
```

This is not a new wrapper. Entries use `;` and key/value pairs use `=`. MIME and filename values cannot contain either delimiter because the convention has no escaping. Web MIME sniffing, validation, preview, and safe file handling are described in the [Web Application Guide](WEB-APPLICATION-GUIDE.md#result-and-payload-handling).

## Payload discovery

The active decoder reads one fixed bootstrap, opens it with the receiver private key, validates its fields and geometry, reads the packet at the recovered location, verifies RSA-PSS, opens AES-GCM, parses the record, then checks the version 3 media hash. It does not search for another packet after a failure. Relocating a packet causes signature verification to fail because the recovered start unit is signed. There is no candidate list, ambiguity branch, or guarantee that a carrier contains only one packet.

The fixed bootstrap span remains observable, but its fields and packet location require the receiver private key. A pristine carrier and a wrong receiver key both return `Payload Missing`.

## Verification verdicts

| Verdict | Operational meaning |
| --- | --- |
| `Authentic` | Bootstrap and packet parse, padding is valid, RSA-PSS and AES-GCM verify, and the recomputed v3 media hash equals the stored hash. |
| `Tampered` | The signature verifies, but the recomputed media hash differs from the signed stored hash. |
| `Signature Invalid` | RSA-PSS verification fails for the extracted signature and reconstructed signing input. |
| `Payload Missing` | The bootstrap cannot be opened with the supplied receiver private key, including a pristine carrier or wrong receiver key. |
| `Wrong Start Location` | Valid geometry gives a footprint outside the carrier or overlapping the reserved bootstrap span. |
| `Cannot Decrypt` | The signed ciphertext fails its AES-GCM authentication tag. |
| `Cannot Verify` | The adapter rejects the file, the bootstrap is malformed, parsing or padding fails, or the carrier cannot be read completely during the hash pass. A readable version 2 bootstrap returns this verdict with detail `unsupported bootstrap version`. |

## Capacity and measured sizes

For the generated 36-byte media ID, record overhead is 109 bytes. Adding the 16-byte GCM tag and 256-byte RSA-PSS signature gives 381 bytes before user payload. Capacity values below use empty metadata, start unit 2,048, and a 2,048-unit bootstrap span.

| `k` | Banana PNG, 6,021,120 units | WAV, 32,000 samples |
| ---: | ---: | ---: |
| 1 | 752,003 | 3,363 |
| 2 | 1,504,387 | 7,107 |
| 3 | 2,256,771 | 10,851 |
| 8 | 6,018,691 | 29,571 |

The bootstrap plaintext is 62 bytes and GCM additional data is 18 bytes. Minimum carrier units for `k=1/2/3/8` are 5,096 / 3,572 / 3,064 / 2,429. The notebook demonstration record is 176 bytes, ciphertext 192 bytes, and packet 448 bytes. Capacity helpers reject carriers that cannot hold the mandatory protocol object; zero user capacity means the complete object fits exactly.

## Limits and compatibility

- Media-code-3 video carriers produced before the 8–16-bit change (commit `ff4ab39`) used an experimental 30-byte context. They are development files. The current 32-byte interpretation does not verify them, and they are not part of the supported compatibility set.
- Overwritten cover LSBs are destroyed and cannot be recovered or authenticated. Padding checks are format checks, not cryptographic checks.
- With `k=8` and a full-carrier footprint, carrier-unit bits provide no integrity evidence. RGBA alpha and non-LSB bytes of multi-byte WAV samples remain covered by the fixed stream.
- Transparent RGBA pixel colour can change even when alpha is zero. The strict PNG adapter refuses an RGB PNG with a `tRNS` colour key, because embedding can move pixels onto or off the key colour. The source converter can turn the key into RGBA alpha before encoding. PNG ancillary data, including text, `eXIf`, `iCCP`, and `tRNS`, and WAV data outside declared PCM samples, such as `LIST` chunks, are outside the hash. Verification does not read them, so a `tRNS` chunk added after encoding does not change the verdict. The output keeps this metadata, but anyone can change it and the verdict stays `Authentic`. Do not use it as evidence.
- Verification reads a file more than once. A file changed during verification can produce a verdict that combines two file states. Timestamps and nonces alone do not prevent replay.
- A wrong receiver key and an absent payload share one verdict. The sender public key must be trusted through a separate method.
- Version 1 and version 2 masked-media files are not accepted. A readable version 2 bootstrap returns `Cannot Verify`; the verifier does not retry. The old `STG1` format was a separate protocol and was not interoperable; its code and tests have been removed. See the [removal record](MERGE-LEFTOVER-REMOVAL.md).
- The protocol does not implement key management, a trust store, PKI, networking, replay protection, public-key-only verification, or automatic packet discovery.
