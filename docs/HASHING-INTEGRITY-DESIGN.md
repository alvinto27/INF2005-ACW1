# Hashing and Integrity Design

## Purpose and scope

This note records the agreed image-authenticity design. It explains the hashing problem, the three protected regions, the encoding order, and the limits of the design.

The scope is authenticity only. The design checks that a trusted signing key approved the decoded stego pixels and hidden payload and that they have not changed. It does not provide encryption, confidentiality, exact reconstruction of the original cover, or a solution for the wider assignment.

This is a design record. The exact packet fields and byte layout still need implementation details.

## Terms

- **Cover image:** the image before embedding.
- **Stego image:** the image after embedding.
- **Payload:** the hidden message and its verification metadata.
- **Digital signature:** the RSA signature created with the private key.
- **Carrier unit:** one 8-bit image colour-channel value. The current image algorithm flattens these values before embedding.
- **LSBs:** the lower bits of a carrier unit that embedding replaces.
- **Upper bits:** bits in the same carrier unit that embedding does not replace.
- **Signature padding:** zero bits added after the RSA signature so its bit length fills complete carrier units at the selected LSB count.

The design must process decoded image carrier units in one defined order. It must not hash arbitrary PNG file bytes. PNG metadata and compression can change even when the decoded pixels do not change.

## Assignment requirement

The assignment treats hashing as an integrity check. It permits hashing a media file, a verification payload, or a selected stable representation. FR9 requires the verifier to recompute the relevant hash and compare it with the embedded or signed value.

The assignment does not require reconstruction of the original image. The design must still state exactly what its verification process protects.

## The original hashing problem

A direct hash of the complete cover image cannot be reproduced from the stego image:

1. The system hashes the original carrier units.
2. Embedding replaces some original LSBs.
3. The stego carrier units differ from the cover carrier units.
4. A complete hash of the stego image therefore differs without any attack.

Clearing every selected LSB before hashing would make the hash reproducible, but would create large ignored bit planes. At an eight-LSB setting, clearing all eight bits would remove all image information from that hash.

A hash also cannot reconstruct an overwritten original bit. Exact recovery of the original cover would require the original image or separately stored recovery data. The assignment does not require that recovery.

## Agreed three-region design

The image carrier units are divided into three non-overlapping regions.

### Region 1: unembedded carrier units

These carrier units store neither payload bits nor signature bits. Hash their complete 8-bit values with SHA-256.

Store the result in the payload as:

```text
unembedded_pixels_hash
```

### Region 2: payload-bearing carrier units

These carrier units hold the header and payload in their LSBs.

After embedding the payload, use the complete final 8-bit values of these carrier units as the main input to RSA-PSS/SHA-256 signing. This covers both:

- The embedded header and payload LSBs.
- The unchanged upper bits of the same carrier units.

The signing input must also include the image and layout context needed to bind these values to their intended positions.

### Region 3: signature-reserved carrier units

These carrier units are reserved for the RSA signature. Their LSBs change when the signature is embedded, so their complete values cannot be included in a reproducible pre-embedding hash.

Before embedding the signature:

1. Read only the upper bits that signature embedding will not replace.
2. Preserve their exact carrier-unit and bit order.
3. Hash that ordered bit stream with SHA-256.
4. Store the result in the payload as:

```text
reserved_upper_bits_hash
```

After the payload-bearing carrier units are signed:

1. Convert the RSA signature bytes to exactly the signature-size number of bits.
2. Append zero padding until the total bit count is a multiple of the selected LSB count.
3. Embed the signature and padding into complete Region 3 carrier units.

For example, RSA-2048 produces 2,048 signature bits. At three LSBs per carrier unit, Region 3 needs 683 units and has 2,049 selected LSB positions. The last position is mandatory zero padding.

## Payload contents

The payload contains two image-integrity hashes:

```text
payload
├── unembedded_pixels_hash
├── reserved_upper_bits_hash
├── media ID, timestamp, and nonce
├── message and application metadata
└── authenticated image and embedding layout
```

These are **hash digests**, not digital signatures.

The separate RSA digital signature is created after payload embedding and is stored in Region 3.

The authenticated layout must define at least:

- Image width, height, and colour mode.
- Carrier-unit and bit ordering.
- Start location or the values used to derive it.
- Number of LSBs used per carrier unit.
- Header and payload lengths.
- Region 2 positions.
- Region 3 positions.
- Hash algorithm and signature algorithm identifiers.

The verifier must use strict ranges and reject overlapping or impossible regions.

## Protection of every final image bit

| Final stego-image bits | Protection method |
| --- | --- |
| Complete values in Region 1 | Compared through `unembedded_pixels_hash`, which is inside the signed payload. |
| Complete values in Region 2 | Direct input to RSA-PSS/SHA-256 signature creation and verification. |
| Upper bits in Region 3 | Compared through `reserved_upper_bits_hash`, which is inside the signed payload. |
| Actual signature bits in Region 3 LSBs | Form the RSA signature; changing them makes signature verification fail. |
| Signature-padding bits in Region 3 LSBs | Must all equal zero; the verifier rejects any other value. |

This arrangement does not leave an ordinary unprotected bit region in the final stego pixel representation.

## Why the signature does not create a loop

The RSA signature is stored in Region 3, but Region 3 is not part of the complete carrier-unit input signed in Region 2.

The process is therefore finite:

```text
calculate two hashes
→ build and embed payload in Region 2
→ sign complete Region 2 carrier units and their context
→ embed signature in Region 3 LSBs
```

The signature does not need to sign its own bits:

- A changed actual signature bit produces a different signature and verification fails.
- A changed signature-padding bit fails the mandatory zero-padding check.
- A changed Region 3 upper bit changes `reserved_upper_bits_hash`.
- That expected hash is inside the payload represented by the signed Region 2 carrier units.

Payload alignment does not create the same gap. The signature input contains the complete final Region 2 carrier-unit values, including all bits in the last unit. It therefore protects any selected LSB positions left after the final payload bit.

## Encoding procedure

1. Decode the PNG into a fixed sequence of 8-bit carrier units.
2. Select the start location and LSB count.
3. Calculate the payload size using fixed-size placeholders for both SHA-256 hashes.
4. Calculate the fixed RSA signature size from the key size.
5. Calculate how many zero-padding bits are needed to make the signature bit length a multiple of the selected LSB count.
6. Allocate Region 2 for the header and payload.
7. Allocate a separate Region 3 for the signature and its zero padding, using complete carrier units.
8. Treat all other carrier units as Region 1.
9. Calculate `unembedded_pixels_hash` from the complete Region 1 values in their defined order.
10. Calculate `reserved_upper_bits_hash` from only the unchanged upper bits in Region 3, in their defined order.
11. Build the final payload containing both hashes, the message, metadata, and layout.
12. Embed the header and payload into the Region 2 LSBs.
13. Build the signature input from:
    - A domain label identifying this protocol and version.
    - Image dimensions and colour mode.
    - Start location, LSB count, lengths, and region positions.
    - The complete final Region 2 carrier-unit values in order, including any positions after the last payload bit.
14. Sign that exact input with RSA-PSS/SHA-256.
15. Append the calculated zero padding to the signature bits.
16. Embed the signature and padding into the Region 3 LSBs.
17. Save the stego image as lossless PNG.

The implementation must confirm the final serialized payload length after replacing the hash placeholders. A binary fixed-length hash field is simplest. A 64-character hexadecimal SHA-256 field also has a fixed length.

## Verification procedure

1. Decode the stego PNG into the same carrier-unit order.
2. Recover or derive the start location.
3. Read and validate the bounded header and layout.
4. Extract the payload from Region 2.
5. Extract the complete signature-and-padding bit stream from Region 3.
6. Split out the exact number of RSA signature bytes defined by the key size.
7. Check every remaining padding bit. Reject the image if any padding bit is not zero.
8. Pass only the actual signature bytes, without padding, to RSA-PSS verification.
9. Rebuild the exact signature input from the current complete Region 2 values and authenticated context.
10. Verify the RSA-PSS/SHA-256 signature.
11. Stop with `Signature Invalid` if verification fails.
12. Recompute `unembedded_pixels_hash` from the current complete Region 1 values.
13. Recompute `reserved_upper_bits_hash` from the current Region 3 upper bits only.
14. Compare both results with the values in the authenticated payload.
15. Return a verdict that identifies which check failed.

A corrupt header, invalid region, or unusable length must produce a failure. The verifier must not move a region or select different bits merely to make verification pass.

## Expected tamper results

| Modification | Expected result |
| --- | --- |
| Change any Region 1 bit | `unembedded_pixels_hash` mismatch. |
| Change an upper bit in Region 2 | Digital-signature failure. |
| Change a payload LSB in Region 2 | Digital-signature failure. |
| Change an upper bit in Region 3 | `reserved_upper_bits_hash` mismatch after payload authentication. |
| Change an actual signature bit in Region 3 | Digital-signature failure. |
| Change a signature-padding bit in Region 3 | Mandatory zero-padding check fails. |
| Change signed layout data | Digital-signature failure or a strict parsing failure. |

## What the design proves

If the signature and both hash comparisons pass, the system can claim:

> The final decoded stego pixel representation and authenticated layout match what the signer approved.

It also proves that the extracted payload represented by Region 2 has not changed.

It does not recover or prove the old values of original LSBs replaced during embedding. Those old values no longer exist in the stego image. This limitation does not create a post-embedding tamper gap because the new values are covered by Region 2 signing or Region 3 signature verification.

## Capacity limit

Physical capacity includes space used by:

- The header.
- The payload and its two SHA-256 hashes.
- The RSA signature.
- Mandatory signature zero padding.

As the packet grows, Regions 2 and 3 consume more carrier units and Region 1 becomes smaller. If eight LSBs are used and the packet occupies every carrier unit, the image contains only packet data. The signature may still authenticate that packet, but there is no remaining original image content in Region 1.

The program should distinguish physical embedding capacity from meaningful media-integrity capacity. It may enforce a minimum Region 1 size or return a limited verdict when no meaningful original carrier content remains.

## Remaining implementation details

The agreed design uses complete separate carrier units for Regions 2 and 3 and mandatory zero padding for Region 3 alignment. The following details remain to be specified:

1. Exact payload and header formats.
2. Exact carrier-unit, channel, byte, and bit order.
3. How the decoder securely finds the start location.
4. The complete signing-input serialization.
5. The minimum permitted Region 1 size.
6. Exact verdict names and failure priority.
