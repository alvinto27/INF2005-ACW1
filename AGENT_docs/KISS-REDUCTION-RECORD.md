# KISS Reduction Record

This record describes the completed reduction of the version 2 protocol. The
[Reduction Specification](REDUCTION-SPEC.md) states the goal and scope. The former
implementation work order has been folded into this record, which states the
outcome and measurements. The older [Version 2 Stage Record](PROTOCOL-V2-STAGE-RECORD.md)
remains a history of the larger design; this record is the current format and outcome.

## Baseline before the reduction

Before the reduction phases, branch `yx` was clean at `51fb9e8` with 54 passing
tests. `nbconvert` was not installed, so the notebook could not be re-run
headlessly; the dependency was added and the outputs were refreshed later.

## Outcome

The protocol keeps receiver-gated encryption, the RSA-OAEP bootstrap, AES-256-GCM,
RSA-PSS signatures, masked-media integrity, and PNG/WAV adapters. It removes
carrier-dependent integer widths, the unused `flags` field, and the separate
caller-side typed-content header. The test suite has **57 passing tests**.

## Phases

| Phase | Result | Commit |
| --- | --- | --- |
| 1 | Replaced carrier-derived protocol integer widths with fixed u64 fields | `76b1e13` |
| 2 | Removed `flags` from the wire format and API | `5442b40` |
| 3 | Moved typed MIME and filename claims into existing metadata | `04fb47f` |
| 3 follow-up | Rejected `;` and `=` in typed metadata values | `ff9bd20` |
| Notebook | Refreshed committed outputs and recorded `nbconvert` | `602b7b4` |
| Tests | Audited the reduced wire format and security coverage | `829c53e` |
| 5a | Updated current protocol, README, and streaming-plan prose | `7445538` |
| 5b | Updated records, indexes, maps, and this outcome record | `4b69a3d` |

Later documentation corrections follow in subsequent commits, so this table does not have to chase its own hash.

## Current wire formats

Every serialised protocol integer uses unsigned 64-bit big-endian encoding via
`encode_protocol_field`. Enumerated fields and the media-id length remain fixed
one-byte fields.

### Payload record

```text
media_id_length    u8
media_id           media_id_length bytes of UTF-8
timestamp          u64
nonce              16 bytes
media_hash         32 bytes
user_length        u64
user_payload       user_length bytes
metadata_length    u64
metadata           metadata_length bytes of UTF-8
```

The generated 36-byte media ID gives a record overhead of **109 bytes** before
user payload and metadata. The payload record is encrypted as a whole.

### Bootstrap and authenticated data

```text
bootstrap plaintext:
version             u8
lsb_count           u8
start_unit          u64
ciphertext_length   u64
session_key         32 bytes
aead_nonce          12 bytes

GCM additional data:
version || lsb_count || start_unit(u64) || ciphertext_length(u64)
```

The bootstrap plaintext is **62 bytes** and the GCM additional data is **18
bytes**. The fixed RSA-2048 bootstrap span remains **2,048 carrier units**.

### Signing input

```text
SIGNING_DOMAIN
version(u8) || media_code(u8) || lsb_count(u8)
total_units(u64) || start_unit(u64) || footprint(u64) || ciphertext_length(u64)
media_context
ciphertext
```

The signing version comes from `PROTOCOL_VERSION`, not from received bootstrap
data. The signature is checked before record decryption.

### Typed payload metadata

The notebook keeps file bytes raw in `user_payload` and stores the MIME and bare
filename claims beside the existing metadata keys:

```text
kind=png;flow=typed-content;mime=image/png;name=generated.png
```

The convention is deliberately not a new envelope. Values cannot contain `;`
or `=` because there is no escaping layer. The receiver still sniffs recovered
bytes, compares the result with the signed claim, rejects unsafe names, and
selects a handler only after the check.

## Measurements

These figures were recomputed with the reduced code. Capacity values use empty
metadata, start unit **2,048**, and a **2,048-unit** bootstrap span.

| Measurement | Result |
| --- | ---: |
| Record overhead for the generated media ID | 109 bytes |
| Empty packet overhead: record + GCM tag + RSA-PSS signature | 381 bytes |
| Bootstrap plaintext | 62 bytes |
| GCM additional data | 18 bytes |
| Minimum carrier units, `k=1/2/3/8` | 5,096 / 3,572 / 3,064 / 2,429 |
| Notebook demonstration record | 176 bytes |
| Notebook demonstration ciphertext | 192 bytes |
| Notebook demonstration packet | 448 bytes |

| `k` | Banana PNG, 6,021,120 units | WAV, 32,000 samples |
| ---: | ---: | ---: |
| 1 | 752,003 | 3,363 |
| 2 | 1,504,387 | 7,107 |
| 3 | 2,256,771 | 10,851 |
| 8 | 6,018,691 | 29,571 |

The preserved-bit count depends mainly on packet size, with LSB depth able to
shift it slightly through alignment: `k * footprint` equals the packet bit count
plus up to `k - 1` pad bits. The refreshed demonstration reports the same
preserved-bit count for its `k=1` and `k=8` cases because both divide cleanly.

## Decisions and reasons

- **Use u64 everywhere for protocol integers.** One fixed rule is easier to
  inspect and keeps the wire format independent of carrier size.
- **Keep the protocol version at 2.** No released artefact needs migration, so
  the changed version-2 format does not require an invented version 3.
- **Remove `flags`.** It had only one legal value and no implemented mode. The
  wire format was already being changed, so removing it avoided dead policy code.
- **Keep one-byte fixed fields.** Media-ID length, version, media code, and LSB
  count are bounded or enumerated; they were not carrier-derived fields.
- **Use existing metadata for MIME and filename.** The library remains
  media-neutral and payload-agnostic. Deleting the nested header removes a
  format without adding another wrapper.
- **Keep delimiter validation.** The simple metadata convention has no escaping;
  rejecting `;` and `=` prevents ambiguous typed claims.
- **Keep the security order.** Bootstrap opening, structural checks, bounds,
  signature verification, GCM opening, record parsing, and masked-hash comparison
  remain distinct. The signature-before-decryption test stays in the suite.

## Deliberate omissions

This reduction does not add streaming or chunked carrier access, video support,
a new protocol version, a new content wrapper, automatic packet discovery, or
public-key-only verification. It does not change the receiver private-key gate,
whole-record encryption, selected start location, or PNG/WAV carrier rules.
Notebook outputs were refreshed through the registered kernel; they were not
edited by hand. `nbconvert==7.17.1` is now listed for reproducible notebook
execution.

## Post-review fixes

Five small post-review commits corrected documentation, diagnostics, tests, and
notebook robustness without changing the protocol design:

- **`d667444` — alignment and field wording.** The preserved-bit claim now says
  `k * footprint` is the packet bit count plus up to `k - 1` pad bits, not exactly
  the packet bit count. The earlier wording generalised a measured coincidence:
  `k=1` and `k=8` divide the byte-aligned 448-byte demonstration packet cleanly,
  so their preserved-bit counts match; `k=3`, `k=5`, and `k=6` carry 1, 1, and 4
  pad bits. The u64 wording was narrowed to general lengths, positions, counters,
  and timestamps, with enumeration and prefix fields remaining u8. Stale figures
  in notebook markdown cell 42 were corrected to 3384, 3384, and 423.
- **`5b854df` — named packet sizes.** `serialized_record_length` now uses
  `NONCE_SIZE` and `SHA256_DIGEST_SIZE` instead of literals.
- **`29a3f58` — corrected a false capacity diagnostic.** Oversized metadata was
  reported as `carrier is too small for the protocol`. That phrase is now reserved
  for the structural guard in `core.encode_carrier`, which uses empty metadata;
  `max_user_payload_length` reports `record overhead exceeds record capacity` and
  includes both compared values. The refusal still precedes embedding, so no
  unsafe operation occurred; only the message blamed the wrong thing.
- **`7c1152e` — named regression coverage.** The oversized-metadata test now names
  the property it defends and derives both capacity values from the helpers. The
  suite is now 55 tests.
- **`a86de7b` — verified before interpretation.** The notebook previously read
  `result.payload` before checking `result.valid`, so failed verification could
  raise `AttributeError` instead of rejecting deliberately. It now exits early
  with the label, verdict, and detail. The GCM claim was also narrowed: GCM
  authenticates ciphertext and additional data under the supplied key and nonce;
  a substituted key or nonce gives `Cannot Decrypt`, and the protocol makes no
  key-commitment claim.
- **`f65515e` — closed an impossible-record measurement hole.**
  `encode_protocol_field` enforced the u64 bound, but `serialized_record_length`
  checked only non-negativity, so the capacity helper could measure a record the
  serialiser cannot produce, such as a 256-byte media-id prefix or a `2^64`
  payload length. No live defect existed: `encode_carrier` always supplies a
  36-byte media ID and real byte strings do not approach the bound. It was closed
  anyway because capacity must be an exact inverse of the wire format. The bound
  now lives in one shared validator, `PayloadRecord` rejects an out-of-range
  timestamp at construction, and the suite is now 57 tests.

## Audit of related records

### Work Not Built

The current claims that required correction were updated in
[Work Not Built](WORK-NOT-BUILT.md): the typed-content link now targets
[Typed Payload Metadata](PROTOCOL-DESIGN.md#typed-payload-metadata), the nested
content-header claim is gone, and the Banana/WAV capacity figures now match the
reduced code. The GUI, live transfer, explanations, innovation statement, and
submission package remain outside this repository as stated there.

### Orchestration Handoff

The handoff was a historical snapshot at child tip `e920382`. Its 55-test count,
stage 6b status, old hashes, old notebook environment, and statement that there
was no next stage were true for that snapshot. It is not a current baseline
claim, and changing those facts would damage the historical meaning. The
standalone repository does not carry workspace-orchestration instructions; use
this reduction record for current status.

## Lessons

- A general mechanism can be correct and still be too large for the assignment;
  fixed fields made the protocol easier to read without weakening its security.
- Removing a nested format is safer than replacing it with a second custom
  format when signed and encrypted metadata already exists.
- Current summaries must be separated from stage history. Old measurements can
  remain valid for the commit that produced them while being wrong for today's
  wire format.
- A refreshed notebook output does not refresh nearby prose automatically.
  Capacity figures, headings, links, and status text need a separate audit.
- A measured coincidence is not a rule. Equal preserved-bit counts at `k=1` and
  `k=8` were true for the demonstration, but the notebook prose had stated the
  alignment nuance correctly all along.

## Verification

```text
cyber_venv/bin/python -m unittest -q
57 tests passed

python3 scripts/check-docs.py
0 errors across 14 Markdown files and 159 links
```
