# Masked Media Integrity Design

## What the system does

The system embeds a signed binary payload in the least-significant bits of a strict RGB PNG image or an uncompressed PCM WAV file. It hashes all carrier bits that the embedding operation preserves. Verification uses a caller-supplied RSA public key to authenticate the payload, media interpretation, and embedding layout.

## Integrity invariant

Every carrier bit that embedding intentionally preserves is represented in the masked media hash. The payload contains that hash and the user content. The signature authenticates the payload together with the media interpretation and the embedding layout. The signature bytes are validated by RSA-PSS verification itself.

## Why the hash remains reproducible

The encoder and verifier copy the carrier and clear the selected least-significant bits inside the embedding footprint. Packet embedding can change only those cleared bits. Therefore, masking the original carrier and masking the received carrier produce the same bytes when all preserved bits are unchanged.

For example, with `k = 3`, the footprint mask is `11111000`. A carrier byte `10110110` becomes `10110000` for hashing. Embedding can change the byte to any value from `10110000` through `10110111`; applying the same mask always produces `10110000`. A change to any of the upper five bits produces a different masked byte.

The exact media-hash calculation is:

```python
masked = carrier_units.copy()
mask = (~((1 << lsb_count) - 1)) & 0xFF
masked[start_unit:start_unit + footprint] &= np.uint8(mask)
preimage = (
    MEDIA_HASH_DOMAIN
    + struct.pack(">BBQQQ", media_code, lsb_count, total_units, start_unit, footprint)
    + masked.tobytes()
)
media_hash = hashlib.sha256(preimage).digest()
```

`MEDIA_HASH_DOMAIN` is exactly:

```python
b"INF2005-ACW1\x00MEDIA-HASH\x00"
```

## Module dependencies

Imports flow from `constants` to `bits`, then `layout`, `packet`, and `core`. The `keys` and `media` modules depend only on `constants` and `bits`; `core` is the only module where protocol, keys, and media meet.

## Packet format and signing input

The packet header is exactly 23 bytes with this format:

```python
PACKET_HEADER_FORMAT = ">16sBBBI"
```

| Header field | Size | Value |
| --- | ---: | --- |
| `magic` | 16 bytes | `d9df721b281169d4335290e30fdb48b1` |
| `version` | 1 byte | `1` |
| `lsb_count` | 1 byte | `1` through `8` |
| `media_code` | 1 byte | `1` for PNG or `2` for WAV |
| `payload_length` | 4 bytes | Length of the complete payload in bytes |

The payload is exactly:

```text
media_id_length  u8
media_id         media_id_length bytes of UTF-8
timestamp        u64, Unix seconds in UTC
nonce            16 bytes
media_hash       32 bytes
user_length      u32
user_payload     user_length arbitrary bytes
metadata_length  u32
metadata         metadata_length UTF-8 bytes
```

All integers use big-endian byte order. The packet continues with a 256-byte RSA-2048 signature, followed by `(-packet_bits) mod lsb_count` zero alignment bits.

The exact layout arithmetic is:

```python
packet_bits = (23 + payload_length + 256) * 8
footprint = (packet_bits + lsb_count - 1) // lsb_count
pad_bits = footprint * lsb_count - packet_bits
```

The exact signing input is:

```python
SIGNING_DOMAIN = b"INF2005-ACW1\x00SIGN\x00"
signing_input = (
    SIGNING_DOMAIN
    + struct.pack(
        ">BBBQQQI",
        PROTOCOL_VERSION,
        media_code,
        lsb_count,
        total_units,
        start_unit,
        footprint,
        payload_length,
    )
    + media_context
    + payload_bytes
)
```

The PNG media context is exactly `struct.pack(">II", width, height)`. The WAV media context is exactly `struct.pack(">HBIQ", channels, sample_width, frame_rate, frame_count)`.

## Payload discovery

The decoder scans the carrier for the fixed 16-byte magic under each `k` value from 1 through 8. Each match supplies a candidate start unit and `k`. The decoder then reads the fixed header, checks its declarations, derives the footprint, extracts the packet, and applies the verification stages without moving or resizing the candidate.

`start_unit` is never declared in the packet. It is discovered from the magic position and then included in the signing input. There is no start field for an attacker to falsify, and relocating a packet causes RSA-PSS verification to fail.

## Signature scope

The RSA-PSS signature authenticates the protocol version, media code, selected LSB count, total carrier-unit count, discovered start unit, derived footprint, payload length, fixed media context, and every payload byte. The payload bytes include the stored media hash, user payload, metadata, media identifier, timestamp, and nonce. RSA-PSS verification validates the received signature bytes against this signing input.

The signature does not authenticate the original values of overwritten cover LSBs. It does not cover file-container metadata outside the decoded carrier units. It does not identify a person, prove freshness, or prevent removal of the embedded packet.

## Verification verdicts

| Verdict | Operational meaning |
| --- | --- |
| `Authentic` | The packet parses, its padding is valid, its RSA-PSS signature verifies with the supplied key, and the recomputed masked media hash equals the signed stored hash. |
| `Tampered` | The signature verifies, but the recomputed masked media hash differs from the signed stored hash. |
| `Signature Invalid` | RSA-PSS verification fails for the extracted signature and reconstructed signing input. |
| `Payload Missing` | No start-magic candidate is found for any supported LSB count. |
| `Wrong Start Location` | Magic is found, but the declared packet length produces an out-of-range or inconsistent footprint at that discovered start. |
| `Cannot Verify` | The adapter rejects the file, or packet parsing, bounds, header consistency, or padding validation fails. |

When candidates fail at different stages, the decoder prefers the failure that reached the deepest integrity check: `Tampered`, then `Signature Invalid`, then `Wrong Start Location`, then `Cannot Verify`.

## Limitations

- Overwritten cover LSBs are destroyed and cannot be recovered or authenticated.
- The alignment padding zero-check is a format check, not a cryptographic one.
- RSA-PSS is randomised, so verification proves the signed input is intact, not that the signature bytes are byte-for-byte original.
- As the footprint grows, the preserved-bit count falls. At `k = 8` with a full-carrier footprint, the media hash witnesses nothing, and the reported `preserved_bits` says so.
- The magic is public, so anyone can locate and strip the packet. This is concealment, not security.
- Container metadata outside the decoded carrier is not covered.
- A timestamp and nonce alone do not prevent replay.

## Authenticity claim

The received media and embedded verification data pass the defined integrity checks, and the digital signature verifies using the public key supplied for verification.

This claim says nothing about a real-world identity. The caller must obtain the correct public key by a separate method.

## What this project does not implement

- Encryption
- Key management or a trust store
- Public-key infrastructure (PKI)
- Networking
- Replay protection
