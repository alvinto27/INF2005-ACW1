# Protocol (version 3)

This guide defines the data that StegoVerify embeds and how it is checked. Terms such as *carrier unit*, *bootstrap*, and *fixed bytes* are defined in the [glossary](README.md#glossary). Earlier versions are described in the [protocol history](history/protocol-history.md#version-1-integrity-protocol).

## Overview

A stego file contains two embedded objects:

```text
carrier units:  0 ............ 2047   ...   start_unit ............ start_unit + footprint   ...
                [   bootstrap     ]         [            packet              ]
                 1 LSB per unit              k LSBs per unit
                 RSA-OAEP                    AES-256-GCM ciphertext + RSA-PSS signature
```

| Object | Position | Contents | Protected by |
| --- | --- | --- | --- |
| Bootstrap | Units 0 to 2,047, lowest bit only | Start unit, LSB count, ciphertext length, AES key and nonce | RSA-OAEP with the receiver's public key |
| Packet | From the start unit, using `k` bits per unit | Encrypted payload record, then the signature | AES-256-GCM, and an RSA-PSS signature by the sender |

- The packet has no public header. Its position and LSB count are only in the bootstrap, so they cannot be read without the receiver's private key.
- The payload record contains a media hash of the carrier. The hash leaves out the bits that embedding changes, so the sender and receiver compute the same value.
- The signature covers the ciphertext, the carrier description, and the packet position. Moving the packet or changing the LSB count makes the signature invalid.

Verification needs the stego file, the sender's public key, and the receiver's private key. It does not need the original cover.

## Carriers

| Carrier | Media code | Carrier unit | Fixed bytes |
| --- | ---: | --- | --- |
| PNG | 1 | Low byte of each R, G, and B value, in row-major order (3 units per pixel) | 8-bit RGBA: alpha bytes. 16-bit: RGB high bytes, then 16-bit alpha values (little-endian) |
| WAV | 2 | Low byte of each PCM sample | All other bytes of each sample |
| Video | 3 | Low byte of each R, G, and B value, then low byte of each 16-bit audio sample | Frame timestamps, RGB high bytes, alpha, audio start time, audio high bytes. See [video carrier](video-carrier.md#carrier-units-and-fixed-bytes). |

For 16-bit values, the "low byte" is the low-order byte of the number, whatever the byte order in the file. Alpha is never a carrier unit.

### PNG input rules

The PNG carrier accepts single-frame, 8-bit or 16-bit, RGB or RGBA images. The encode page converts other images to this form first (see [source conversion](carrier-and-payload-flow.md#source-conversion)).

| Input | Result |
| --- | --- |
| Palette, grayscale, or grayscale-alpha | Refused: `PNG must be RGB or RGBA; palette and grayscale images are not supported` |
| 1-, 2-, or 4-bit samples | Refused: `PNG must use 8-bit or 16-bit RGB or RGBA samples` |
| Animated PNG | Refused: `animated PNG images are not supported` |
| RGB with a `tRNS` colour key | Refused, because embedding could move pixels onto or off the key colour. Source conversion turns the key into an alpha channel instead. |
| Decoded size over 715,827,880 bytes | Refused before decoding: `PNG decoded size exceeds configured limit` |

The decoded size is width × height × channels × bytes per sample. This gives these pixel limits:

| PNG format | Maximum pixels |
| --- | ---: |
| 8-bit RGB | 238,609,293 |
| 8-bit RGBA | 178,956,970 |
| 16-bit RGB | 119,304,646 |
| 16-bit RGBA | 89,478,485 |

### Media context

The media context describes the carrier and is included in the signature.

| Carrier | Format | Fields |
| --- | --- | --- |
| 8-bit PNG | `>IIB` (9 bytes) | width, height, channel count |
| 16-bit PNG | `>IIBB` (10 bytes) | width, height, channel count, 16 |
| WAV | `>HBIQ` | channels, sample width, frame rate, frame count |
| Video | `>IIQBBIHQ` (32 bytes) | width, height, frame count, video depth, video channels, audio sample rate, audio channels, audio frames per channel |

8-bit PNG keeps the shorter 9-byte context so that 8-bit files made before 16-bit support still verify.

## Media hash

The media hash combines two SHA-256 digests:

1. **`unit_digest`** covers all carrier units in order, with the embedded bits set to zero: the lowest bit in the bootstrap area, and the lowest `k` bits in the packet area (including padding).
2. **`fixed_digest`** covers all fixed bytes in order.

```python
media_hash = SHA256(
    b"INF2005-ACW1\x00MEDIA-HASH-V3\x00"
    + struct.pack(">BB", media_code, lsb_count)
    + total_units + fixed_byte_count + start_unit + footprint + bootstrap_span   # each u64 big-endian
    + unit_digest
    + fixed_digest
)
```

Chunk boundaries do not affect either digest. PNG ancillary chunks (such as text and `tIME`) and WAV chunks outside the samples are not hashed. The encoder copies most of them to the output; the rules are in [metadata in the output](carrier-and-payload-flow.md#metadata-in-the-output).

## Payload record

This is the plaintext before encryption. Lengths, positions, and timestamps are unsigned 64-bit big-endian.

| Field | Size |
| --- | --- |
| `media_id_length` | u8 |
| `media_id` | UTF-8, 36 bytes (for example `IMG-` + 32 hex characters) |
| `timestamp` | u64, Unix seconds (UTC) |
| `nonce` | 16 bytes |
| `media_hash` | 32 bytes |
| `user_length` | u64 |
| `user_payload` | `user_length` bytes |
| `metadata_length` | u64 |
| `metadata` | UTF-8, `metadata_length` bytes |

The fixed fields total 109 bytes. The whole record is encrypted with AES-256-GCM, which adds a 16-byte tag.

### Payload metadata

File payloads store the raw file in `user_payload`. The MIME type and file name go in `metadata` as `key=value` pairs separated by `;`:

```text
kind=png;flow=typed-content;mime=image/png;name=generated.png
```

There is no escaping, so values cannot contain `;` or `=`. The [web application guide](web-application.md#recovered-payloads) explains how these values are used for previews.

## Packet and signature

```text
packet = ciphertext || 256-byte RSA-PSS signature || zero padding to the end of the last unit
```

The signed data is:

```text
b"INF2005-ACW1\x00SIGN\x00"
|| version (u8) || media_code (u8) || lsb_count (u8)
|| total_units (u64) || start_unit (u64) || footprint (u64)
|| ciphertext_length (u64) || media_context || ciphertext
```

- RSA-PSS uses SHA-256 and a fixed 32-byte salt.
- The data is hashed in chunks and signed as a prehashed digest. The signature is the same as signing the whole input directly.
- The version comes from the verifier's own constant, not from the received bootstrap.
- The signature is checked before decryption.

The number of carrier units the packet uses (the footprint) is:

```python
packet_bits = (ciphertext_length + 256) * 8
footprint   = ceil(packet_bits / lsb_count)
pad_bits    = footprint * lsb_count - packet_bits
```

## Bootstrap

| Field | Size |
| --- | --- |
| `version` | u8 |
| `lsb_count` | u8 |
| `start_unit` | u64 |
| `ciphertext_length` | u64 |
| `session_key` | 32 bytes |
| `aead_nonce` | 12 bytes |

The plaintext is 62 bytes. The first four fields (18 bytes) are also used as AES-GCM additional data. RSA-2048 OAEP encryption gives 256 bytes, which fill the lowest bit of units 0 to 2,047. The start unit must be 2,048 or higher.

## Verification

The verifier runs these steps in order and stops at the first failure:

1. Read the bootstrap and decrypt it with the receiver's private key.
2. Check the recovered fields and that the packet fits in the carrier.
3. Read the packet and check its padding.
4. Verify the RSA-PSS signature.
5. Decrypt with AES-GCM and parse the record.
6. Recompute the media hash and compare it with the stored one.

There is only one bootstrap. The verifier does not search for other packets.

### Verification verdicts

| Verdict | Condition |
| --- | --- |
| `Authentic` | All six steps pass. |
| `Tampered` | The signature is valid, but the recomputed media hash differs from the stored one. |
| `Signature Invalid` | RSA-PSS verification fails. |
| `Payload Missing` | The receiver's private key cannot decrypt the bootstrap. This happens with a wrong key and with a file that has no payload. |
| `Wrong Start Location` | The recovered position puts the packet outside the carrier or over the bootstrap. |
| `Cannot Decrypt` | The ciphertext fails its AES-GCM tag check. |
| `Cannot Verify` | The file cannot be read, the bootstrap or record is malformed, the padding is wrong, or the carrier cannot be fully read during hashing. A version 2 bootstrap gives the detail `unsupported bootstrap version`. |

## Capacity

Each payload needs 381 bytes of overhead: the 109-byte record header, the 16-byte GCM tag, and the 256-byte signature. The table shows the largest payload with empty metadata and start unit 2,048.

| `k` | Banana PNG (6,021,120 units) | WAV (32,000 samples) |
| ---: | ---: | ---: |
| 1 | 752,003 bytes | 3,363 bytes |
| 2 | 1,504,387 bytes | 7,107 bytes |
| 3 | 2,256,771 bytes | 10,851 bytes |
| 8 | 6,018,691 bytes | 29,571 bytes |

The smallest carrier that can hold an empty payload has 5,096, 3,572, 3,064, or 2,429 units for `k` = 1, 2, 3, or 8.

## Limits and compatibility

- Only version 3 files are accepted. Version 1 and 2 files, and files from the removed `STG1` implementation, cannot be verified. See the [repository history](history/repository-history.md).
- Video files made with an early 30-byte development context do not verify.
- Overwritten cover bits cannot be recovered or checked. At `k` = 8 across the whole carrier, only the fixed bytes are checked.
- Padding checks are format checks, not cryptographic checks.
- Metadata outside the hash (PNG text, `eXIf`, `iCCP`, `tRNS`, WAV `LIST` chunks) can change without changing the verdict.
- In RGBA images, the colour of fully transparent pixels can change.
- Verification reads the file more than once. A file changed during verification can give a verdict based on two versions of it.
- A wrong receiver key and a missing payload give the same verdict.
- The sender's public key must be trusted through a separate channel. There is no key management, trust store, PKI, or replay protection.
