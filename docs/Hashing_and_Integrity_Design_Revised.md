# Hashing, Integrity, and Key Trust Design

Revision: 11 September 2026

## Purpose and scope

This record retains the three-region media-integrity design and adds the agreed SSH-style trust-on-first-use (TOFU) workflow. The shared protocol operates on a media object represented as ordered 8-bit carrier units. Each media adapter supplies loading, carrier conversion, canonical media context, reconstruction, and saving. Two adapters are fixed for version 1: static RGB PNG and uncompressed RIFF/WAVE PCM.

Each signer holds their own private key; the application does not distribute a shared private key. The decoder can receive only a media object carrying the public key needed for mathematical verification. Trust in that key is a separate, local user decision.

The scope is integrity and authenticity relative to an accepted signing key. This design does not provide encryption, confidentiality, exact reconstruction of an original cover, independent proof of a person's identity, or a solution for the wider assignment.

The exact packet fields and byte layout remain implementation details. The baseline settings below consolidate the proposed implementation rules.

## Terms

- **Media object:** the input or output object handled by a media adapter, such as a PNG image or a WAV file.
- **Carrier unit:** one 8-bit value in the adapter-defined carrier sequence. For the current PNG adapter, one unit is one colour-channel value.
- **Cover object:** the media object before embedding.
- **Stego object:** the media object after embedding.
- **Payload:** the hidden message and its verification metadata.
- **Digital signature:** the RSA signature created with the signer's private key.
- **LSBs:** the lower bits replaced by embedding.
- **Upper bits:** the bits in that unit that embedding does not replace.
- **Signature alignment padding:** zero bits appended after the signature to fill complete carrier units. This is separate from RSA-PSS's internal encoding and salt.
- **Start magic:** a fixed 128-bit prime value that identifies the beginning of a candidate Region 2 packet. It is public and provides identification, not authentication.
- **Key fingerprint:** a digest of a defined canonical public-key encoding, used to recognise a key.
- **Trusted key:** a public key explicitly accepted in the decoder's local trust store.

## Assignment requirement

As described in the supplied design record, the assignment permits hashing a media file, verification payload, or selected stable representation. FR9 requires the verifier to recompute the relevant hash and compare it with the embedded or signed value. Original-cover reconstruction is not required.

This design protects the adapter's decoded carrier sequence, not arbitrary container-file bytes. Compression and metadata may change without changing the protected carrier values. The shared rules apply to both fixed version-1 adapters.

## Original hashing problem

Hashing an entire cover object before embedding cannot produce a digest reproducible from the stego object when embedding overwrites carrier LSBs. Clearing all selected LSBs before hashing would make the hash reproducible but leave those bit planes outside that hash. At eight LSBs, it would remove all carrier information from that hash.

A hash cannot reconstruct overwritten bits. Recovery would require the original media object or separately retained recovery data. Instead, this design authenticates the post-embedding carrier representation.

## Baseline media and cryptographic rules

For the shared version 1 protocol:

- Operate on an adapter-provided ordered sequence of 8-bit carrier units.
- Use a media type code and bounded canonical media-context bytes to identify how those units are interpreted.
- Represent each byte most-significant bit first. For an LSB count of k, fill selected positions from bit k−1 down to bit 0.
- Permit k only within the supported range 1 through 8.
- Use SHA-256 and RSA-2048 with RSA-PSS, MGF1 using SHA-256, and a 32-byte salt. The signature is 256 bytes, or 2,048 bits.
- Treat these as fixed version-1 parameters. Header identifiers cannot enable unsupported algorithms or weaker settings.
- Bind protocol version, media type, canonical media-context length and bytes, bit ordering, lengths, and region positions into an unambiguous signing input.
- Use this fixed 128-bit start magic, encoded as 16 big-endian bytes:

  ```text
  d9df721b281169d4335290e30fdb48b1
  ```

  The value is prime, but primality provides no authenticity or secrecy. Its purpose is to provide a long, fixed, low-collision packet identifier.

The current PNG adapter profile accepts only static, 8-bit RGB PNG objects and defines their carrier order as rows top-to-bottom, pixels left-to-right, and channels R, G, B. It rejects alpha, palette, grayscale, 16-bit, and animated inputs rather than silently converting them during verification.

The fixed WAV adapter accepts RIFF/WAVE uncompressed PCM (`comptype == "NONE"`) with sample widths from 1 through 4 bytes, positive channels and frame rate, and a non-negative frame count. Every decoded byte in interleaved frame order is one uint8 carrier unit. The expected frame-byte length is `frame_count * channels * sample_width`, and decoded frame bytes are limited to 64 MiB. Its canonical context is `b"WAV-PCM\\x00"` followed by `>HBIQ` fields for channels, sample width, frame rate, and frame count. Reconstruction preserves the WAV parameters and replaces the frame bytes exactly; saving writes those frame bytes exactly as uncompressed PCM. Container metadata outside the decoded context and frame bytes is not authenticated.

## Agreed three-region design

The regions are non-overlapping and together cover every carrier unit. Region 1 is exactly the complement of Regions 2 and 3. The layout, hashes, framing, signature, and trust workflow are media-neutral.

### Region 1: unembedded carrier units

These units contain neither payload nor signature bits. Hash their complete 8-bit values in carrier order with SHA-256. Store the digest inside the payload as `unembedded_carrier_hash`.

### Region 2: header and payload units

Embed the header and payload into their selected LSBs. Sign the complete final 8-bit values of these units, together with the required media context and layout.

This protects the payload LSBs, unchanged upper bits, and every bit of the last unit, including any positions after the final payload bit. Region 2 includes the embedded public key and any claimed signer metadata.

### Region 3: signature-reserved units

Before signature embedding, hash the upper bits that will remain unchanged. Store the digest in the payload as `reserved_upper_bits_hash`.

Read these bits in carrier order, from bit 7 down to bit k in each unit. The version-1 hash preimage is `REGION3_HASH_DOMAIN` (`b"INF2005-ACW1\\x00V1\\x00REGION3-UPPER\\x00"`), followed by the LSB count as one unsigned byte, the carrier-unit count as an unsigned 64-bit integer, the upper-bit stream length as an unsigned 64-bit integer, and the stream packed most-significant bit first into bytes with trailing zero fill. These packing zeros are not embedded into the media object.

At k = 8, this upper-bit stream is empty. Its encoded length is zero; the hash still uses the defined domain and length encoding.

After signing Region 2, append zero bits to the actual signature until its length is divisible by k, then embed it into complete Region 3 units.

For RSA-2048 at three LSBs: 2,048 signature bits require 683 units, providing 2,049 positions. The final position must be zero.

## Payload contents and authenticated layout

Region 2 begins with the fixed start magic followed by the versioned, length-delimited header and the payload record. The header carries the fixed protocol and framing fields. The version-1 payload record has exactly these top-level fields, with no extras or omissions:

| Field | Canonical value |
| --- | --- |
| `media_type` | Integer media code `1` or `2`; boolean values are rejected. |
| `media_context` | Standard, canonically padded Base64 for decoded context bytes of at most 4,096 bytes. |
| `public_key_der` | Standard, canonically padded Base64 for canonical RSA-2048/e=65537 SubjectPublicKeyInfo DER of at most 512 bytes. |
| `unembedded_carrier_hash` | Lowercase hexadecimal for exactly 32 bytes. |
| `reserved_upper_bits_hash` | Lowercase hexadecimal for exactly 32 bytes. |
| `media_id` | Nonempty UTF-8 text of at most 128 encoded bytes, with no control characters. |
| `timestamp` | A real UTC timestamp in exact form `YYYY-MM-DDTHH:MM:SSZ`. |
| `nonce` | Lowercase hexadecimal for exactly 16 bytes. |
| `message` | UTF-8 text of at most 15 MiB encoded bytes. |
| `metadata` | An object of at most 32 string-to-string entries; keys are nonempty, at most 64 UTF-8 bytes, and values are at most 1,024 UTF-8 bytes; neither may contain control characters. |

The record exposes decoded binary values as bytes and metadata as immutable sorted key/value pairs. It uses canonical UTF-8 JSON exactly as `json.dumps(..., sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")`. Parsing rejects duplicate keys, malformed UTF-8, noncanonical Base64 or hexadecimal values, invalid field types, and any input whose byte-for-byte canonical reserialization differs. The serialized record must obey the existing 16 MiB payload limit.

The record does not embed a fingerprint, layout duplication, algorithm choices, or fields derivable from the signed header and layout. The two integrity fields are hashes, not signatures. The RSA signature remains separate in Region 3.

The decoder must calculate the fingerprint from the actual public key; it must not trust an embedded fingerprint, key ID, or display name as proof of key identity. The final signing-input serialization must avoid ambiguous field concatenation and bind all interpretation-relevant media and layout context.

## Key management and trust on first use

### One application, separate key ownership

The application can both sign and verify media objects. These capabilities do not require sharing a private key between users.

The key manager must:

1. Generate a signing key pair for the user.
2. Store the private key locally, preferably encrypted under a user password; never embed it in a media object or bundle a shared private key with distributed software.
3. Embed the matching public key when encoding.
4. Maintain a local list of explicitly trusted public keys and optional user-assigned labels.
5. Allow users to inspect fingerprints and remove trust.

Public-key import and export can support confirmation outside the media workflow, but are not required for a media object to carry its verification key.

Private-key persistence is fixed as encrypted PEM using PKCS8 and `serialization.BestAvailableEncryption(password)`. Passwords are nonempty bytes of at most 1,024 bytes. The PEM is at most 16 KiB. Saving a new key uses exclusive creation with owner-only permissions on POSIX; loading is bounded. No specific cipher is claimed because the cryptography library selects it.

The local trust store is fixed as canonical UTF-8 JSON version 1 with `keys` and `version` fields. It contains at most 64 canonical RSA public-key DER records and is at most 128 KiB. Records are sorted by raw DER bytes; actual-key duplicates are rejected; nonempty local labels are optional but unique. Fingerprints are derived from the actual DER and are not stored redundantly. Persistence uses an owner-only temporary file and atomic replacement. Local filesystem and trust-store security remain assumptions.

### First encounter

The decoder extracts bounded metadata and the public key, then performs signature, padding, and carrier-hash checks. If all pass but the key is unknown, display:

> Signature Valid — Key Not Trusted

This means the content is consistent with the included signature and public key. It does not prove that the content was never replaced and signed under a different key, or that the claimed signer identity is real.

Only after all checks pass may the application offer:

> This media object verifies under an unknown public key. Would you like to trust this key for future objects? Confirm its fingerprint with the intended signer if you need assurance of their identity.

Display the calculated fingerprint. Treat any embedded signer name as a claim; allow a separate local label. Accepting stores the actual key and its calculated fingerprint as trusted. Declining leaves the result verified but untrusted.

### Subsequent encounters

If the object passes every check and its actual public key matches an accepted key, display:

> Authentic — signed by a trusted key.

Here, authentic means approved under a key this user previously accepted. It does not mean an identity authority independently verified the person, or that the depicted event is true.

A different key claiming a name already associated with a trusted key must not silently replace that key. Where such an identity association exists, show a key-change warning and require a separate trust decision. Without an established association, report the key as unknown; names alone cannot reliably identify key rotation.

Accepting trust can update the current passing object’s trust status too. Trust never overrides failed signature, hash, padding, or parsing checks.

### TOFU limitation

As with SSH-style first-use acceptance, the first trust decision matters. If the user accepts an impersonator's key, future verification recognises that accepted key. The software records trust; it cannot manufacture identity assurance from a media object alone.

The trust, signature, and hash stages are shared by both fixed adapters. The current prototype does not implement GUI trust prompts. Callers control loading private keys and trust records through the existing path-persistence functions; local filesystem and trust-store security remain assumptions.

## Protection of final carrier bits

| Final bits | Protection |
| --- | --- |
| Complete Region 1 values | Recomputed hash compared with the digest inside signed Region 2. |
| Complete Region 2 values | Directly included in the signing input. |
| Region 3 upper bits | Recomputed hash compared with the digest inside signed Region 2. |
| Region 3 actual signature bits | Must form a valid RSA-PSS signature under the included key; authenticity additionally requires local trust in that key. |
| Region 3 alignment padding | Must all be zero. |

The signature field requires a qualification: RSA-PSS can produce different valid signatures for the same signing input because it uses a salt. Replacing a signature with another legitimately generated signature for exactly that input can change Region 3 carrier units while still passing verification. Arbitrary corruption is expected to fail; verification does not prove byte-for-byte identity of the original signature field.

## Why there is no hashing loop

The sequence is finite:

1. Allocate all regions.
2. Calculate the two hashes.
3. Build and embed Region 2.
4. Sign complete final Region 2 values and context.
5. Embed the signature and zero alignment padding into Region 3.

The signing input excludes Region 3's complete values. Its upper bits are covered through the signed digest, its signature bits must verify, and its alignment padding must be zero. The public key is known before signing and can be included in Region 2 without creating a loop.

## Encoding procedure

1. Validate and decode the supported media object through its adapter into the fixed carrier order.
2. Load the user's signing key and matching public key.
3. Create the adapter's canonical media context and let the user select a carrier-unit-aligned start location and an LSB count.
4. Build Region 2 so its embedded bit stream begins at that location with the fixed 16-byte start magic, followed by the versioned header and payload.
5. Calculate the serialized header and payload size, including the public key and fixed-size placeholders for both hashes.
6. Calculate the signature size and alignment padding.
7. Allocate complete, separate carrier units for Regions 2 and 3; define Region 1 as their complement. Reject insufficient capacity.
8. Calculate `unembedded_carrier_hash` from Region 1.
9. Calculate `reserved_upper_bits_hash` from Region 3's unchanged upper bits using the defined packing rules.
10. Build the final payload and confirm that replacing hash placeholders did not change the allocated serialized length.
11. Embed the start magic, header, and payload into Region 2 as one continuous bit stream. Do not add field padding after the magic.
12. Construct the exact signing input from the domain, protocol version, media code, canonical media context, authenticated layout, and complete final Region 2 values.
13. Sign using the fixed RSA-PSS parameters.
14. Append the required zero alignment padding and embed into Region 3.
15. Save through the media adapter without changing decoded carrier values.

Static RGB PNG and uncompressed PCM WAV use this same sequence through their fixed adapter methods.

## Verification procedure

1. Validate and decode the media object through its adapter into the same carrier order.
2. For each supported LSB count from 1 through 8, scan carrier-unit-aligned start positions for the fixed 128-bit magic under the defined extraction order.
3. Treat each magic match as an untrusted candidate. Extract the bounded fixed header immediately after the magic; require its declared LSB count to match the current scan.
4. Parse and range-check the bounded layout, payload, media context, and public key. Treat them as untrusted until authentication succeeds.
5. Reject unsupported algorithms or media codes, invalid key parameters, impossible lengths, overlapping regions, and out-of-range positions.
6. Check that the declared media context matches the adapter's decoded representation and extraction layout.
7. Extract the exact signature and padding stream from Region 3. Under the version-1 profile, use 256 signature bytes.
8. Reject any nonzero signature alignment padding.
9. Reconstruct the exact signing input from current complete Region 2 values and the authenticated media context and layout.
10. Verify RSA-PSS using the extracted public key and fixed protocol parameters. Pass only actual signature bytes, without alignment padding.
11. Stop on signature failure.
12. Recompute and compare both carrier-integrity hashes against the authenticated payload.
13. Stop if either comparison fails.
14. Calculate the public-key fingerprint and look up the actual key in the local trust store.
15. Return trusted authenticity or verified-but-untrusted status. Offer first-use trust only for an otherwise valid result.

A magic match identifies only a candidate. It does not authenticate that candidate. The verifier must not relocate regions or reinterpret bits merely to obtain a passing result. It must apply fixed bounds to scanning and candidate parsing. Both fixed adapters use the same shared verification stages.

## Expected results and failure priority

| Condition | Result |
| --- | --- |
| Unsupported media object or malformed header, key, layout, context, or length | Parsing/format failure; no trust prompt. |
| Nonzero signature alignment padding | Padding failure; no trust prompt. |
| Region 2 content changes, including public key or metadata | Signature failure, or earlier parsing failure. |
| Arbitrary corruption of signature bits | Signature failure. |
| Region 1 changes | `unembedded_carrier_hash` mismatch. |
| Region 3 upper bits change | `reserved_upper_bits_hash` mismatch. |
| All checks pass; key unknown or not accepted | Signature Valid — Key Not Trusted. |
| All checks pass; actual key is locally trusted | Authentic — signed by a trusted key. |
| New key claims an identity already associated with another key | Key-change warning; no automatic trust replacement. |

Processing priority is format/layout, alignment padding, signature, integrity hashes, then trust classification. Both hash mismatches may be reported together after successful signature verification. A trusted key never converts a failed check into success.

## What the design proves

When all cryptographic checks pass:

> The payload, media context, layout, and decoded carrier units outside the actual signature field match the representation authenticated under the included public key. The signature field contains a valid signature, and its alignment padding is zero.

When that key is also locally trusted:

> The authenticated media representation was approved under a signing key accepted by this user.

These statements assume the signing private key and local trust store remain secure. Verification does not establish unchanged original signature bytes, recover overwritten cover LSBs, authenticate arbitrary container metadata, prove a real-world identity on first use, or guarantee freshness. A timestamp and nonce alone do not prevent replay without additional checking or state.

## Capacity and original-bit retention

Capacity must include the header, message, metadata, public key, two SHA-256 digests, RSA signature, and mandatory signature alignment padding.

For N1, N2, and N3 carrier units in the three regions and k selected LSBs:

`original_bits_retained = 8*N1 + (8-k)*(N2 + N3)`

This counts positions deliberately left untouched, not overwritten positions that coincidentally retain their previous value. It describes encoder-side retention by layout; the decoder cannot independently prove the original cover object's provenance.

Region 1 may be empty without weakening packet authentication. At fewer than eight LSBs, original upper bits remain in Regions 2 and 3. At eight LSBs with no Region 1, no original carrier bits remain.

Report authenticity and retention separately. This authenticity-only baseline does not require a minimum Region 1 size. Any later minimum is an application policy, not a cryptographic requirement. Retention percentage is not a visual-quality metric.

## Remaining implementation details

The media-neutral encoder and decoder are wired through thin fixed-format PNG and WAV encode/verify wrappers. The wrappers do not load key or trust files; callers provide those inputs.

The following version-1 standards are fixed: the 16-byte start magic; the `>BBHI` Region 2 header and length-delimited framing; the 64-candidate scan bound; both Region 1 and Region 3 hash preimages; the Region 2 signing domain and `>BBIBQQQQQQHB` context; canonical RSA public-key DER with its SHA-256 fingerprint; the exact ten-field canonical JSON payload record; the encrypted private-key PEM boundary and persistence limits; the canonical trust-store JSON and limits; and the PNG and WAV adapter representations defined above.

Only these details remain unresolved:

1. Machine-readable verdict codes and final user-facing verdict details.
2. GUI trust prompts; the current prototype leaves trust decisions and file-key/trust loading to callers.

## Technical reference

RSA-PSS behaviour and encoding parameters: RFC 8017, sections 8.1 and 9.1 (`https://www.rfc-editor.org/rfc/rfc8017.html#section-8.1`).
