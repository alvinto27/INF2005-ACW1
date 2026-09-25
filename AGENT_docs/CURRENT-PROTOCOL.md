# Current Protocol

**Status:** Protocol version 3 is implemented. This file is the source of truth for the current masked-media wire format, security checks, compatibility, and typed-payload rules. Historical version 1 decisions are in [Protocol Version 1 History](PROTOCOL-V1-HISTORY.md).

## Overview

The protocol embeds a signed, encrypted payload in 8-bit RGB or RGBA PNG carrier units, or in the least-significant byte of each uncompressed PCM WAV sample. An RSA-OAEP bootstrap carries packet geometry and AES-256-GCM session material to the intended receiver. RSA-PSS authenticates the ciphertext and carrier interpretation. Verification needs the sender public key and receiver private key. The packet has no public marker or header; version 1 and version 2 files are not readable by the active protocol.

Every media-data byte preserved by embedding is covered by the version 3 full media hash. The payload record contains that hash and the user content. The signature authenticates the record ciphertext, media interpretation, and embedding layout. It does not authenticate overwritten cover LSBs or identify a real-world person.

## Hash rule and carrier interpretation

Version 3 hashes two streams:

1. `unit_digest` is SHA-256 over carrier units in order after clearing the lowest bit in the reserved bootstrap span and the lowest `lsb_count` bits in the packet footprint, including alignment padding.
2. `fixed_digest` is SHA-256 over all media-data bytes that embedding does not change. This includes PNG alpha bytes and every non-carrier byte of each declared multi-byte PCM sample. Empty input uses the normal SHA-256 empty digest.

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

PNG input must be a single-frame, 8-bit RGB or RGBA image. RGB and RGBA have three carrier units per pixel; alpha is fixed data and remains byte-for-byte unchanged. WAV carrier units are the low byte of each declared PCM sample. Other sample bytes are fixed data. PNG ancillary chunks and WAV chunks outside declared PCM samples are not hashed.

PNG media context is `struct.pack(">IIB", width, height, channel_count)`, with channel count 3 or 4. WAV context is `struct.pack(">HBIQ", channels, sample_width, frame_rate, frame_count)`.

The encoder and verifier mask the same carrier regions before hashing. The hash therefore stays reproducible when only the bits used for embedding change. A start unit below the reserved bootstrap span is rejected.

## Carrier units

A PNG carrier unit is one 8-bit R, G, or B value; an RGBA pixel still has only three carrier units. A WAV carrier unit is one PCM sample's low byte, not one file byte. For multi-byte samples the other bytes are fixed data and are hashed. Capacity therefore scales by `1 / sample_width` compared with counting all sample bytes.

Accept only single-frame, 8-bit PNG images in RGB or RGBA mode. Reject palette, grayscale, 16-bit, animated, and other PNG modes. A non-PNG file keeps `UnSupportedFileType`. Format errors remain specific: unsupported mode reports `PNG must be RGB or RGBA; palette and grayscale images are not supported`; non-8-bit samples report `PNG must use 8-bit RGB or RGBA samples`; animation reports `animated PNG images are not supported`; and images above twice Pillow's configured pixel limit report the pixel count and limit.

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

- Overwritten cover LSBs are destroyed and cannot be recovered or authenticated. Padding checks are format checks, not cryptographic checks.
- With `k=8` and a full-carrier footprint, carrier-unit bits provide no integrity evidence. RGBA alpha and non-LSB bytes of multi-byte WAV samples remain covered by the fixed stream.
- Transparent RGBA pixel colour can change even when alpha is zero. PNG ancillary data, including `tRNS`, and WAV data outside declared PCM samples are outside the hash.
- Verification reads a file more than once. A file changed during verification can produce a verdict that combines two file states. Timestamps and nonces alone do not prevent replay.
- A wrong receiver key and an absent payload share one verdict. The sender public key must be trusted through a separate method.
- Version 1 and version 2 masked-media files are not accepted. A readable version 2 bootstrap returns `Cannot Verify`; the verifier does not retry. The old `STG1` format was a separate protocol and was not interoperable; its code and tests have been removed. See the [removal record](MERGE-LEFTOVER-REMOVAL.md).
- The protocol does not implement key management, a trust store, PKI, networking, replay protection, public-key-only verification, or automatic packet discovery.
