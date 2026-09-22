# KISS Reduction Specification

## Purpose

This record defines the agreed reduction scope after reviewing the current protocol against the INF2005 ACW1 brief. It is not a protocol redesign. The goal is to remove infrastructure that is more general than the assignment or the anticipated video extension requires, while preserving security behaviour that exists for a concrete requirement or attack model.

The current version 2 architecture remains the baseline. Reduction work should be surgical. Do not use this review as justification for a broad backend rewrite.

## Core decisions

### Keep: user-selected arbitrary start location

The brief explicitly allows the user to choose the payload start location and requires the decoder to recover that same location while protecting the information against guessing, unauthorised extraction, and tampering.

The start location therefore remains user-selected rather than being replaced with a purely derived location.

### Keep: encrypted receiver bootstrap

The fixed RSA-OAEP bootstrap remains. It solves the recovery problem created by an arbitrary secret user-selected start location: the legitimate receiver needs a known place from which to recover the hidden packet geometry, while an unauthorised observer should not receive that geometry in plaintext.

The receiver keypair is therefore intentional rather than redundant:

- receiver public key: used by the encoder to protect bootstrap information;
- receiver private key: required to recover the bootstrap and locate/decrypt the hidden packet.

### Keep: per-object AES session key and hybrid encryption

A fresh AES-256-GCM session key remains generated for each protected stego object. RSA-OAEP protects the small bootstrap/session material; AES-GCM protects the potentially large payload record.

This is required by the design because RSA-OAEP is not appropriate for arbitrary-size payload encryption, while the assignment includes a custom payload whose confidentiality and integrity must be protected.

### Keep: whole-record encryption

The complete payload record remains encrypted with AES-GCM, not only the user-provided content.

This serves two purposes:

1. payload confidentiality and authenticated encryption;
2. resistance to brute-force location discovery through recognisable embedded structure.

Leaving record fields such as identifiers, timestamps, lengths, metadata, MIME strings, or other predictable prefixes in plaintext would give an attacker structure that can be searched for at candidate LSB locations. Encrypting the complete record removes that recognisable plaintext signature and is simpler than maintaining mixed plaintext/encrypted record sections.

### Keep: masked-media hash and RSA-PSS signature

The existing integrity model remains:

- hash the carrier bits intentionally preserved by embedding;
- include the resulting media hash in the protected record;
- authenticate the encrypted packet and embedding geometry with RSA-PSS;
- recompute and compare the masked-media hash during verification.

These mechanisms directly support the assignment's integrity and digital-signature requirements.

## Agreed reductions

### 1. Replace carrier-derived integer widths with fixed-width fields

Remove the `carrier_field_width(total_units)` protocol rule and the associated variable-width serialisation/parsing infrastructure.

The original motivation was legitimate: the design anticipated larger carriers, streaming access, and the brief's optional video extension. However, dynamically changing integer widths is more general than necessary to preserve that future direction.

Use one fixed-width integer representation throughout the protocol: `u64` (8-byte unsigned, big-endian).

This applies to integer-valued protocol fields such as:

- carrier geometry and positions;
- payload and metadata lengths;
- ciphertext and footprint lengths;
- timestamps;
- other protocol counters or sizes that require serialisation.

The implementation should define this width once as a protocol constant/helper and use it consistently rather than maintaining per-field or carrier-derived width rules.

Using `u64` for the timestamp is intentionally slightly wider than necessary for this assignment, but the extra bytes are negligible and the uniform encoding rule reduces parser, serializer, test, and documentation complexity.

The objective is fixed, uniform parsing and serialisation, not minimising a few bytes of protocol overhead.

This still leaves the format comfortably capable of representing image, audio, and realistically foreseeable video carriers. Streaming or video support does not require carrier-dependent integer widths.

### 2. Remove the separate caller-side content header

Arbitrary binary custom payload support remains. The system should still be able to represent payloads such as text, images, documents, audio, or other files.

However, MIME type and original filename should move into the existing FR3 team-defined metadata rather than being carried in a second nested content-header format.

The resulting conceptual payload record is:

```text
PayloadRecord
|- media_id
|- timestamp
|- nonce
|- media_hash
|- metadata
|  |- MIME/content type
|  `- original filename
`- user_payload
   `- raw arbitrary bytes
```

The steganography and cryptographic layers therefore continue to operate on arbitrary bytes without maintaining another mini-protocol solely to describe those bytes.

The exact metadata encoding may remain an implementation detail; do not introduce a replacement envelope merely to move these two fields.

## Opportunistic cleanup

### Protocol flags

`flags` currently has only one legal value, zero. No implemented assignment feature depends on an optional protocol mode.

Removing it would slightly simplify bootstrap serialisation, authenticated data, signature input, validation, and tests, but the reduction is small. Therefore:

- remove `flags` if the bootstrap/signing format is already being changed as part of the fixed-width cleanup;
- otherwise do not churn an otherwise stable format solely to remove one byte.

Protocol versioning is sufficient for future incompatible format changes.

## Features explicitly retained

The following were reviewed and are not reduction targets at this time:

- whole-record AES-GCM encryption;
- per-object AES session key;
- RSA-OAEP receiver bootstrap;
- separate sender signing and receiver decryption key roles;
- RSA-PSS signature;
- masked-media hashing;
- user-selectable 1-8 LSB depth;
- user-selected arbitrary start location;
- detailed verification verdicts;
- preserved-bit count/ratio as explanatory and limitation evidence;
- technically correct PCM sample handling across the currently supported sample widths;
- strict media validation already implemented;
- the existing regression test suite, except tests that become obsolete because an intentionally removed feature no longer exists.

Do not reduce test count for its own sake. Tests for retained behaviour remain useful even when they exceed the minimum assignment demonstration cases.

## Video and streaming boundary

The assignment explicitly identifies video as an optional extension, so anticipating larger carrier address spaces is reasonable. The protocol should not unnecessarily box out a later video carrier implementation.

However, video and streaming/chunked carrier access are not current mandatory deliverables and must not drive additional infrastructure now.

Current decision:

- do not implement streaming WAV access now;
- do not implement video-carrier support now unless separately authorised;
- retain enough fixed-width geometry headroom that either can be added later without another variable-width integer scheme;
- revisit seekable/chunked carrier access only when there is a concrete carrier size or video implementation requiring it.

The correct boundary is: design so video is not artificially excluded, but do not build video infrastructure in advance.

## Documentation and API scope

Existing protocol/history documents remain useful records and do not need to be deleted merely to make the repository smaller. They should, however, stop generating new protocol stages without a concrete requirement.

Similarly, narrowing the public Python API is optional cleanup rather than a priority reduction. Do not spend assignment time reorganising exports unless the GUI/integration work benefits directly.

## Implementation priority

If a reduction pass is performed, use this order:

1. replace carrier-derived widths with the selected fixed-width schema;
2. move MIME/filename into existing metadata and delete the separate content-header path;
3. remove protocol `flags` only if already touching the affected wire-format code;
4. remove or rewrite tests and documentation only where they describe infrastructure deleted by steps 1-3;
5. freeze protocol work and prioritise GUI integration, required image/audio demonstrations, Party A -> Party B workflow, sample cases, and submission evidence.

Do not reopen the settled bootstrap, session-key, whole-record-encryption, or start-location architecture during this reduction pass without a new concrete requirement or discovered defect.
