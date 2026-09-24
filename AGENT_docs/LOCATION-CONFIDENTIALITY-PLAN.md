# Location Confidentiality Plan

**Historical status: protocol version 2 stage 6b was implemented.** The headerless packet is encrypted, and an RSA-OAEP bootstrap carries its geometry and AES-GCM session material to the receiver. The receiver verifies with the sender public key and its private key. The KISS reduction later superseded the stage 6b wire-format details: current fields are fixed unsigned 64-bit values, `flags` are removed, and typed payload claims use metadata. See the [KISS Reduction Specification](REDUCTION-SPEC.md), [KISS Reduction Record](KISS-REDUCTION-RECORD.md), and [Protocol Design](PROTOCOL-DESIGN.md#protocol-design) for current behaviour.

The goal is to protect the payload start location, length, and LSB depth from everyone except the intended receiver, while the user still chooses all three by hand.

The one deferred decision, 14, is now superseded by the [Streaming Carrier Plan](STREAMING-CARRIER-PLAN.md#streaming-carrier-plan). See [Open decisions](#12-open-decisions).

## 1. The problem

Version 1 finds the packet by scanning the carrier for a public 16-byte marker under each LSB count from 1 to 8. See [Payload discovery](PROTOCOL-DESIGN.md#payload-discovery).

The marker is a public constant, so the scan is available to everybody. Measured on the sample carriers, an attacker with no key finds the packet in 0.01 to 0.43 seconds. Brief [§5](../docs/INF2005-ACW1-spec_v5-f2f.md#5-mandatory-scope) asks the team to explain how the start location is secured against guessing and unauthorised extraction. Version 1 has no real answer.

Deleting the marker alone does not work. The receiver then cannot find the packet either. Something must tell the receiver where to look, and only the receiver.

### The marker is not the only locator

An early draft of this plan deleted the marker but left the payload record in the clear. That draft did not work, and the measurement is the reason this plan encrypts the whole record.

`stego/core.py` builds the media identifier as `IMG-` or `AUD-` followed by 32 hexadecimal characters. The record serialises that identifier first, behind a one-byte length. The length is always 36, so every packet begins with the same five bytes: `24 49 4D 47 2D`.

Measured against a packet at a secret start unit of 3,412,907 in a 6,021,120-unit carrier, with no key and without touching the bootstrap:

| Sweep | Result |
| --- | --- |
| All 8 bit offsets of the 1-LSB stream for `24 'IMG-'` | start unit recovered exactly, error 0 units, in **0.002 s** |

That is faster than the marker sweep it was meant to replace. A shorter pattern is cheaper to scan. Removing a 16-byte marker and leaving the record in the clear would have made the attack about five times quicker.

**Rule taken from this.** If location confidentiality is the objective, nothing recognisable may remain at the user-selected location. The sweep beats the key whenever the format leaves anything to sweep for.

## 2. The trade that cannot be avoided

Version 1 lets anyone with the sender's public key discover the packet and check the signature. Version 2 gives that up.

```text
version 1    sender public key  ->  discover packet  ->  verify authenticity
version 2    receiver private key  ->  recover location  ->  reach packet  ->  verify authenticity
```

These two goals conflict:

- Nobody except the receiver knows where the signature is.
- Anybody can verify the signature independently.

To a file, an attacker and an honest third party look the same. Therefore the location is either public to both or secret to one keyholder.

An attempt to break the dependency fails. The masked media hash preimage contains the start unit and footprint, and the mask is applied to that range, so the hash cannot be recomputed without the location. Masking the low bits of the whole carrier instead would make the hash location-independent, but the location would still be needed to find the signature, and the hash would cover far less:

| LSB count | Bits covered now | Bits covered if masked globally | Loss |
| ---: | ---: | ---: | ---: |
| 1 | 48,166,460 | 42,147,840 | 12.5% |
| 3 | 48,161,460 | 30,105,600 | 37.5% |
| 8 | 48,148,960 | 0 | 100% |

Measured on the 1280x1568 sample carrier.

**Accepted.** Brief [§7](../docs/INF2005-ACW1-spec_v5-f2f.md#7-required-security-workflow) makes party B both the receiver and the verifier, so receiver-gated verification matches the workflow the assignment describes.

Consequence for the API: `verify_png` and `verify_wav` take the receiver's private key in addition to the sender's public key.

## 3. Design

```text
public bootstrap, unit 0, 1 LSB
    RSA-OAEP( version, flags, lsb_count, start_unit, ciphertext_length,
              session_key, aead_nonce )
        -> tells only the receiver where and how to extract

secret packet, user-selected start unit, user-selected LSB count
    AES-256-GCM( complete payload record )  ||  RSA-PSS signature
        -> two high-entropy blocks and nothing else
```

### 3.1 Public constants

| Constant | Value | Reason |
| --- | --- | --- |
| `BOOTSTRAP_START_UNIT` | 0 | fixed and public. There is no discovery step |
| `BOOTSTRAP_LSB_COUNT` | 1 | least change to the cover |
| `bootstrap_span` | serialised bootstrap envelope size in bytes, multiplied by 8 | 2,048 units for RSA-2048 |
| `PROTOCOL_VERSION` | 2 | version-1 files are not readable under this scheme |

### 3.2 The packet header is removed

Version 1 writes a 23-byte header of `magic ‖ version ‖ media_code ‖ lsb_count ‖ payload_length`. The bootstrap carries the version, the LSB count, and the length, so the header holds nothing new, and the marker is the beacon this plan exists to remove.

`START_MAGIC`, `PACKET_HEADER_FORMAT`, `PACKET_HEADER_SIZE`, `MAX_MAGIC_CANDIDATES`, and the eight-LSB discovery scan are all deleted.

The embedded packet becomes exactly:

```text
record_ciphertext_with_tag || signature
```

### 3.3 Bootstrap

The bootstrap is RSA-OAEP with SHA-256, encrypted to the receiver's public key. Its plaintext is byte-aligned, and the carrier-bounded fields use the derived width of section [5](#5-capacity-and-field-widths):

```text
version             u8      = 2
flags               u8      reserved, must be 0
lsb_count           u8      1 to 8
start_unit          W bytes big-endian
ciphertext_length   W bytes big-endian
session_key         32      AES-256-GCM
aead_nonce          12
```

There is no terminator and no plaintext marker. OAEP decryption returns the exact plaintext length.

### 3.4 Signing input

```text
SIGNING_DOMAIN
|| version             u8
|| flags               u8
|| media_code          u8
|| lsb_count           u8
|| total_units         W bytes
|| start_unit          W bytes
|| footprint           W bytes
|| ciphertext_length   W bytes
|| media_context
|| record_ciphertext_with_tag
```

`flags` is signed. Section [4](#4-field-binding-audit) explains why that is mandatory.

The signature covers the ciphertext, not the plaintext. Section [4](#4-field-binding-audit) also explains why that still authenticates the plaintext.

### 3.5 The whole payload record is encrypted

```text
record plaintext = media_id || timestamp || record_nonce || media_hash
                   || user_payload || metadata

AES-256-GCM
    key   = session_key            from the bootstrap
    nonce = aead_nonce             from the bootstrap
    aad   = version || flags || lsb_count || start_unit || ciphertext_length
    data  = record plaintext
```

Every field is encrypted, including `media_id`, `media_hash`, and `metadata`. Nothing structural remains at the secret location. Section [1](#1-the-problem) holds the measurement that makes this mandatory rather than optional.

The bootstrap layout fields go into the GCM additional authenticated data. They are covered by the tag as well as by the signature. That costs no bytes on the wire and puts two independent bindings on the fields whose forgery this plan must prevent.

**Brief conformance.** [FR3](../docs/INF2005-ACW1-spec_v5-f2f.md#6-functional-requirements) requires the payload to contain the media identifier, timestamp, hash, nonce, and team metadata. It requires the payload to *contain* them, not to expose them, so encryption satisfies it. [FR9](../docs/INF2005-ACW1-spec_v5-f2f.md#6-functional-requirements) requires the system to "recompute the relevant media or payload hash and compare it with the embedded or signed value". It states no ordering, so comparing after decryption satisfies it.

An earlier record in this repository claimed that FR9 needs `media_hash` readable before decryption. That claim was stronger than the brief and is withdrawn.

### 3.6 The masked hash covers two regions

Both the bootstrap region and the packet region are overwritten, so the mask clears both, each at its own LSB count:

```text
masked[0 : BOOTSTRAP_SPAN]                  &= 0xFE           bootstrap, k = 1
masked[start_unit : start_unit + footprint] &= ~((1<<k)-1)     packet, user k
```

The span is runtime data, not a constant, so it reaches three separate places. Section [5.3](#53-the-reserved-region-is-runtime-data) covers the fourth, which is capacity.

| Place | Requirement | If it is missed |
| --- | --- | --- |
| Mask range | clear the low bit over the span as well as the packet range | the hash covers bits the bootstrap overwrote, so every verification reports `Tampered` |
| `MEDIA_HASH_CONTEXT_FORMAT` | commit to the span, at the derived width | the hash does not pin the geometry it was computed under |
| `preserved_bit_count` | subtract the bootstrap's one bit per unit over the span | the reported fidelity number is false |

### The preserved-bit metric is a published claim

`preserved_bit_count` is not internal arithmetic. It is returned in `VerificationResult.preserved_bits` with a ratio, and the notebook reports it as the fidelity evidence for FR11 and FR12. A wrong value is a wrong claim about the carrier.

The bootstrap writes one bit per unit across the span, so the correction is independent of the user's LSB count:

```text
preserved = 8 * (total_units - footprint - BOOTSTRAP_SPAN)
            + (8 - lsb_count) * footprint
            + 7 * BOOTSTRAP_SPAN
```

Measured on the 1280x1568 sample carrier with a 1 KiB payload, the uncorrected formula overstates untouched bits by 2,048 at every LSB count. That is 0.004% of the carrier, so no test that compares ratios to two decimal places will catch it. It needs a test that asserts the exact integer.

The notebook reports the exact `preserved_bits` integer beside the ratio and prints the bootstrap's 2,048 written bits separately, so the span correction is visible rather than hidden by a rounded percentage.

### The two mask regions must be proven disjoint

`calculate_masked_media_hash` must reject a start unit below the span, rather than trusting encode to have validated it. The check belongs beside the masking code because that is where the assumption lives. An overlapping start unit would clear bits the packet never wrote, and the failure would surface far away as `Tampered`.

### A key-size mismatch cannot reach the hash

If the sender used a 3,072-bit receiver key and the receiver tries a 2,048-bit key, the two sides derive different spans and would mask different ranges. That never happens, because the read length in decode step 3 is derived from the same envelope size: the receiver reads the wrong number of units, OAEP fails, and the verdict is `Payload Missing` at step 4. The hash is never reached, so the misleading `Tampered` verdict is not reachable by this route.

This is worth stating because it is easy to break. Reading a fixed number of units instead of a key-derived number would turn a clear `Payload Missing` into a confusing `Tampered`.

### 3.7 Where encryption lives

Version 1 kept all cryptography out of the payload path. The payload was opaque bytes and the caller encrypted them if it wanted to. Version 2 cannot keep that arrangement, because decision 10 encrypts the whole `PayloadRecord` and the caller never sees that record: `core.py` builds it. **Encryption moves inside the library and becomes unconditional.** Section [11](#11-decisions) records this as a deliberate cost of location confidentiality rather than a drift.

Three layers, each with one owner:

| Layer | Module | Knows | Does not know |
| --- | --- | --- | --- |
| Primitives | `crypto.py` | RSA-OAEP and AES-GCM | the protocol, its fields, carriers |
| Format | `bootstrap.py` | the bootstrap field layout, the span, the additional-data encoding | carriers, media |
| Sequencing | `core.py` | the order of operations and the verdicts | how either cipher works |

Body encryption needs no module of its own. The record bytes already come from `packet.py`, the session key and nonce already come from the bootstrap, and the additional authenticated data is a bootstrap concern. It is one primitive in `crypto.py` and one call in `core.py`.

**Why the additional data forces a single owner.** The GCM tag covers the bootstrap layout fields, which makes the two envelopes one cryptographic unit. If two modules could encode those fields, the sender and the verifier would eventually disagree. `bootstrap.py` owns the encoding, and `crypto.py` takes `aad` as opaque bytes, so a reviewer checks the binding by reading one file.

`keys.py` was renamed to `crypto.py` ahead of this work, because it gains symmetric operations and a module called `keys` holding AES-GCM would describe two thirds of its contents. The rename is a separate change so that the diff adding the envelope functions carries no import churn. See decision 15 and stage 2c.

The module docstring still describes RSA-PSS signing and PEM handling only. It is accurate today and must be widened when the envelope functions land, not before.

## 4. Field binding audit

Every bootstrap field is attacker-writable, because the receiver's public key is public. Each field must therefore be either signed directly or implied by something already authenticated.

| Field | Bound how | An attacker who changes it gets |
| --- | --- | --- |
| `version` | signed. The signing input uses the sender's constant, not the value read from the bootstrap | signature failure. A later version cannot be downgraded |
| `flags` | signed, and in the GCM additional data | signature failure |
| `lsb_count` | signed, and in the GCM additional data | wrong bits extracted, then signature failure |
| `start_unit` | signed, and in the GCM additional data | wrong region extracted, then signature failure |
| `ciphertext_length` | signed, and in the GCM additional data | wrong span, then signature failure |
| `session_key` | implied by the GCM tag | `Cannot Decrypt` |
| `aead_nonce` | implied by the GCM tag | `Cannot Decrypt` |

### Why `flags` must be signed

`flags` controls how the packet bytes are interpreted. Without it in the signing input, an attacker can:

1. take a legitimate file whose body is ciphertext;
2. write a fresh, valid bootstrap with the receiver's public key, keeping the layout fields;
3. clear the encryption flag.

The signed bytes never move. RSA-PSS verifies. The masked hash matches. The decoder skips decryption and hands ciphertext to the caller as the message, with the verdict `Authentic`.

Nothing is forged. The signature authenticated the bytes but not their meaning. That is the same defect class as an unsigned content type, one layer lower.

In this plan `flags` must always be 0, because encryption is unconditional. It is signed anyway, so the next field anyone adds there arrives already covered.

### Why signing the ciphertext still authenticates the plaintext

The signature covers `record_ciphertext_with_tag`, so a reader may object that the sender never signed a plaintext.

The chain holds because the GCM tag binds the key. An attacker who wants the receiver to accept a different plaintext must find a key and nonce that turn the signed ciphertext into a different message with a valid tag. That is a 2^-128 problem.

`session_key` and `aead_nonce` are therefore left unsigned. Substituting either cannot produce a wrong answer, only a failure, so the question is what to call that failure. See [Verdicts](#8-verdicts).

### A trap in the version field

The signing input must keep using the sender's `PROTOCOL_VERSION` constant. It must not use the version byte read from the bootstrap. Reading it from the bootstrap looks tidier and silently removes the downgrade protection. This needs a comment in the code.

## 5. Capacity and field widths

### 5.1 The payload limit is the carrier

Version 1 caps payloads with `MAX_PAYLOAD_LENGTH = 16 MiB`. That constant is unrelated to the file in hand, and it rejects payloads that fit:

| Carrier | LSB count | Actually fits | 16 MiB cap |
| --- | ---: | ---: | --- |
| Banana 1280x1568 | 8 | 6,018,701 B | within the cap |
| Phone photo 4000x3000 | 8 | 35,997,579 B | **rejects 19 MB that fit** |
| DSLR 6000x4000 | 8 | 71,997,579 B | **rejects 55 MB that fit** |

Brief [§5](../docs/INF2005-ACW1-spec_v5-f2f.md#5-mandatory-scope) lists a required case: "Cover-object and payload-capacity check: is the payload size larger than the cover-object size?" The brief asks whether the payload fits the cover object. Answering "no, because of a constant in our header" answers a different question.

`MAX_PAYLOAD_LENGTH` is removed. The limit becomes:

```text
max_user_payload = (total_units - start_unit) * lsb_count / 8
                   - record_overhead      93 + 2W bytes
                   - gcm_tag               16 bytes
                   - signature            256 bytes
```

Three user choices in, one honest answer out. The rejection message must name the carrier units, the start unit, the LSB count, and the computed maximum, because that message is the capacity check the brief asks to see demonstrated. A usable carrier may have a user capacity of exactly zero; an unusable carrier is refused instead of being clamped to the same value.

**Removing the cap tightens the allocation guard rather than weakening it.** `ciphertext_length` arrives from the attacker-writable bootstrap, so it must be bounded before anything is allocated. The carrier capacity is a tight bound taken from the file already in memory. The old constant was the looser guard in every case that mattered: far too large for a thumbnail, far too small for a photograph.

### 5.2 The capacity helper must migrate with the header

Stage 1 shipped `max_payload_length(total_units, start_unit, lsb_count)` as the exact inverse of the version 1 layout. It subtracts `PACKET_HEADER_SIZE + RSA_SIGNATURE_SIZE`, which is correct only while the packet header exists.

Stage 4b deletes the header. **The helper changes in the same commit.** At this intermediate stage the packet is plaintext record plus signature, so capacity increases by 23 bytes. Stage 4c then adds the 16-byte GCM tag, leaving the final 7-byte gain over version 1. The two final-format errors below explain why these changes must follow the actual wire format, not only its planned end state.

| Overhead | Bytes |
| --- | ---: |
| Version 1 packet: header 23 + signature 256 | 279 |
| Stage 4b packet: signature 256 only | 256 |
| Version 2 packet: GCM tag 16 + signature 256 | 272 |
| Version 2 user payload: also record overhead `93 + 2W` | `272 + (93 + 2W)`; 369 B at W=2, 371 B at W=3 |

**Error one: the header is deleted and the helper is not touched.** It returns `available - 279` where the truth is `available - 272`, so it understates by 7 bytes and refuses payloads that fit. That is the same defect stage 1 removed, smaller by a factor of two million, and still wrong.

**Error two, the dangerous one: a caller reads the result as a user payload maximum.** The version 1 return value is the maximum *serialised record* length, not the maximum *user payload* length. Those two quantities differ by the record overhead, which is `93 + 2W` in the current format. A caller that treats the old return value as a user payload budget overstates it by that overhead, accepts the payload, and fails during encode. Section [5.3](#53-the-reserved-region-is-runtime-data) explains why a check that reports success and then fails is worse than no check at all.

**Requirement for stage 4.** Two capacity quantities exist in version 2 and they differ by the current record overhead, `93 + 2W` bytes. Each function name must say which one it returns. Do not keep a single name whose meaning changes with the protocol version.

**Which quantity a rejection reports.** `build_embedding_layout` receives the serialised record length, so its message reports the record maximum. It has never seen a metadata length and cannot compute the user payload maximum.

That leaves a gap. The message a user should see is about their own file, not about an internal record. Brief [§5](../docs/INF2005-ACW1-spec_v5-f2f.md#5-mandatory-scope) asks whether the payload is larger than the cover object, and a user reading `max_record_length` has to subtract an overhead they know nothing about.

**Stage 4c must add a user-facing capacity refusal** at the encode entry points, reporting the user payload maximum, the carrier size, the chosen start unit and the LSB count. The layout-level message stays as an internal check. Two messages, because there are two questions and only one of them is the user's.

### 5.3 The reserved region is runtime data

`BOOTSTRAP_SPAN` is the **serialised bootstrap envelope size** in bytes multiplied by 8, because the bootstrap is written at 1 LSB. It is not a compile-time constant. It is known only after a key is loaded:

| Scheme | Bootstrap envelope | Span at 1 LSB | Receiver key size |
| --- | ---: | ---: | ---: |
| RSA-2048 | 256 B | 2,048 units | 256 B |
| RSA-3072 | 384 B | 3,072 units | 384 B |
| RSA-4096 | 512 B | 4,096 units | 512 B |
| X25519 with AES-GCM | 113 B | 904 units | **32 B** |

**Say envelope size, not key size.** For RSA-OAEP the two are equal, because the ciphertext length equals the modulus length. That coincidence does not generalise. An X25519 envelope carries an ephemeral public key, a ciphertext, and a tag, so it is 113 bytes while the receiver key is 32. Deriving the span from the key size would give 256 units instead of 904 and corrupt every read.

RSA is the only scheme planned for version 2, so no code is affected today. The terminology is corrected now so that the documented X25519 fallback of section [9](#9-sizes) is not implemented against a definition that is true only by accident.

The span does **not** enter the capacity formula of section [5.1](#51-the-payload-limit-is-the-carrier), because that formula measures from the chosen start unit to the end of the carrier. The span constrains which start units are legal; it does not change the room available once a start unit is chosen.

It does enter two other questions, and both must be answered after the receiver key is loaded:

| Question | Needs the span |
| --- | --- |
| Is this carrier usable at all? | yes: the unit count must exceed the span plus a minimum footprint |
| What is the most this carrier could hold? | yes: the best case is a start unit equal to the span |
| How much fits at the start unit the user chose? | no: the chosen start unit already accounts for it |

**Ordering requirement.** Encode must load the receiver key and set the span from the envelope size before it answers either of the first two questions. Answering them earlier overstates capacity by `span x lsb_count / 8` bytes.

That error looks harmless and is not. At 1 LSB with RSA-2048 it is 256 bytes, which on a large carrier is noise. On a small carrier it changes the answer:

| Carrier | LSB count | Ignoring the span | Accounting for it |
| --- | ---: | ---: | --- |
| Illustrative 4,000-unit carrier | 1 | 228 B free | **does not fit** |
| Illustrative 4,000-unit carrier | 8 | 3,728 B | 1,680 B |
| 32,000-sample WAV | 1 | 3,728 B | 3,472 B |

A check that reports success and then fails during encode is worse than no check, because it moves the failure past the point where the user can still act on it. Stage 6b turns the table's “does not fit” result into an explicit refusal before encoding; the record-level figures remain unchanged. A zero user capacity now means the protocol fits and leaves no user bytes.

**Consequence for the code.** No helper may take a carrier and an LSB count alone and return a capacity. Any such function assumes a start unit of 0, which is correct in version 1 and silently wrong in version 2. The start unit stays a required argument with no default.

### 5.4 One derived width

```python
def carrier_field_width(total_units: int) -> int:
    """Bytes needed for any carrier-bounded quantity. One rule, one place."""
    return max(1, (total_units.bit_length() + 7) // 8)
```

Because the LSB count never exceeds 8, the largest possible packet byte count is `total_units * lsb_count / 8`, which is at most `total_units`. A width derived from the unit count therefore covers positions, footprints, and lengths alike. The same bound covers the `user_payload_length` and `metadata_length` fields in `PayloadRecord`; their largest possible values are no greater than the carrier's unit count, so W bytes is sufficient for either field.

| Carrier | Units | W | Signed prefix |
| --- | ---: | ---: | --- |
| Banana | 6,021,120 | 3 | 4 + 4x3 = 16 B |
| Phone photo | 36,000,000 | 4 | 4 + 4x4 = 20 B |
| DSLR | 72,000,000 | 4 | 4 + 4x4 = 20 B |

The width is applied in all three formats, so that no lower ceiling returns through a back door:

| Format | Version 1 | Version 2 |
| --- | --- | --- |
| Bootstrap plaintext | not present | `start_unit` and `ciphertext_length` at W bytes |
| `SIGNING_CONTEXT_FORMAT` | `">BBBQQQI"` | `">BBBB"` then four W-byte fields |
| `MEDIA_HASH_CONTEXT_FORMAT` | `">BBQQQ"` | `">BB"` then three W-byte fields |

Both sides know the carrier geometry before they build or read either format, so both derive the same width.

### 5.5 Two invariants that variable widths create

**Derive the width in one place.** If the sender and the verifier derive `W` differently, every signature breaks. `bit_length(N)` and `bit_length(N - 1)` disagree whenever the unit count is a power of two, and the two expressions look interchangeable. One function, called from all three formats, never re-derived inline. A test at a power-of-two unit count belongs with it.

**The signing input must stay injective given the carrier.** It is: `W` is fixed once the unit count is known, `media_context` has a fixed length per medium, and `ciphertext_length` sits in the fixed-width prefix ahead of the variable tail. No two field tuples can serialise to the same bytes. A future field appended without a length prefix would break this, so the property is written down here.

**The payload record keeps the same invariant.** W is fixed by the carrier, both length fields occupy fixed-width big-endian slots, and each variable tail follows its own length. Therefore no two record field tuples can serialise to the same bytes.

### 5.6 Remaining ceilings

| Ceiling | Decision |
| --- | --- |
| `MAX_PAYLOAD_LENGTH` | removed. The carrier is the limit |
| `PayloadRecord.user_payload_length` and `metadata_length` as `u32` | replaced by the derived width |
| `total_units`, `start_unit`, `footprint` as `u64` | replaced by the derived width |
| `MEDIA_HASH_CONTEXT_FORMAT` three `u64` fields | replaced by the derived width |
| `PACKET_HEADER_FORMAT` `u32` length | deleted with the header |
| `MAX_MAGIC_CANDIDATES` | deleted with the scan |
| `MAX_MEDIA_ID_BYTES` = 255 | kept. A one-byte length prefix on an internally generated 36-byte value. Not a payload ceiling |
| Capacity-helper zero clamp | removed. An unusable carrier now raises; zero means an exact-fit protocol object |
| `PNG_MEDIA_CONTEXT_FORMAT` `">II"` | kept. Four billion pixels per side |
| `WAV_MEDIA_CONTEXT_FORMAT` `">HBIQ"` | kept. The frame count is already 64-bit |
| `MAX_WAV_FRAME_BYTES` = 64 MiB | **superseded.** Kept only for whole-file WAV helpers; the streamed WAV path has no cap. See [Streaming Carrier Plan, section 10](STREAMING-CARRIER-PLAN.md#10-whole-file-wav-cap) |

## 6. Encode

| Step | Action |
| ---: | --- |
| 1 | Load the carrier and count addressable units |
| 2 | Load the sender signing private key and the receiver encryption public key |
| 3 | Set `BOOTSTRAP_SPAN` from the serialised envelope size. Refuse a carrier smaller than the span plus a minimum footprint. **This step must precede any capacity answer.** See section [5.3](#53-the-reserved-region-is-runtime-data) |
| 4 | The user chooses the start unit, the LSB count, and the payload |
| 5 | Refuse a start unit below `BOOTSTRAP_SPAN`, and name the reserved region in the error |
| 6 | Check the payload against the carrier-derived capacity of section [5.1](#51-the-payload-limit-is-the-carrier). Name all four numbers in any rejection |
| 7 | Build the layout |
| 8 | Generate a fresh session key and nonce. Encrypt the whole record with the bootstrap layout as additional authenticated data |
| 9 | Compute the masked media hash with both regions masked |
| 10 | Sign the signing input of section [3.4](#34-signing-input) |
| 11 | Build the bootstrap plaintext and seal it with RSA-OAEP to the receiver |
| 12 | Write the bootstrap at unit 0 at 1 LSB |
| 13 | Write `record_ciphertext_with_tag ‖ signature` at the user's start unit and LSB count |

Step 9 runs before anything is written, and the mask clears bits instead of reading them, so there is no circular dependency.

## 7. Decode

| Step | Action | Verdict if it fails |
| ---: | --- | --- |
| 1 | Load the carrier and count units | `Cannot Verify` |
| 2 | Load the receiver private key and the sender public key | — |
| 3 | Read `envelope_bytes x 8` units from unit 0 at 1 LSB | `Cannot Verify` |
| 4 | RSA-OAEP decrypt | `Payload Missing` |
| 5 | Parse the plaintext and check the version | `Cannot Verify` |
| 6 | Validate every recovered field against the carrier | `Cannot Verify` |
| 7 | Extract `record_ciphertext_with_tag ‖ signature` | `Cannot Verify` |
| 8 | Verify RSA-PSS with the sender public key | `Signature Invalid` |
| 9 | AES-GCM decrypt with the bootstrap layout as additional data | `Cannot Decrypt` |
| 10 | Parse the record | `Cannot Verify` |
| 11 | Recompute the masked hash over both regions and compare with the recovered value | `Tampered` |
| 12 | — | `Authentic` |

### `InvalidTag` is not a `ValueError`

Measured during stage 3: every AES-GCM failure, whether from a changed key, nonce, additional-data value or ciphertext byte, raises `cryptography.exceptions.InvalidTag`. Its base class is `Exception`, not `ValueError`.

`decode_carrier` currently catches `ValueError` to convert a failure into `Cannot Verify`. **Step 9 must catch `InvalidTag` explicitly.** If it does not, the one failure this verdict exists for escapes the verdict machinery entirely and surfaces as an uncaught exception instead of a verdict.

### Where the key size is pinned

`bootstrap_span` accepts any RSA key size, because the envelope formula is general. `seal_to_public_key` calls `validate_rsa_public_key`, which pins RSA-2048. The span function is therefore general while sealing is not.

That asymmetry is deliberate. `validate_rsa_public_key` is the single place the key size is pinned, so supporting the RSA-3072 and RSA-4096 rows of section [9](#9-sizes) is a change in one function rather than a search across the package.

### Ordering invariant

No code may act on `flags` before step 8. A signed field does not help if something interprets it earlier. The check has to sit where it cannot be skipped.

### Step 6 is load-bearing

Every value from the bootstrap is untrusted input until step 8 passes. Step 6 checks that the LSB count is 1 to 8, that the start unit is at or above `BOOTSTRAP_SPAN`, and that the start unit plus the footprint fits inside the carrier. It bounds `ciphertext_length` by the carrier capacity before anything is allocated.

### Step 4 is recognition, not authentication

Successful OAEP decoding serves as a private bootstrap-recognition mechanism for the intended receiver. It does not authenticate the bootstrap sender, because anyone holding the receiver's public key can produce a valid ciphertext.

OAEP decoding requires a leading zero byte, a 32-byte label-hash equality, and a `0x01` separator. Random low bits from an ordinary photograph fail that structure, so an unprotected file is recognised as such, and no marker is needed.

## 8. Verdicts

Version 1 verdicts keep their meaning. See [Verification verdicts](PROTOCOL-DESIGN.md#verification-verdicts). One verdict is added.

| Verdict | Meaning |
| --- | --- |
| `Cannot Decrypt` | The signature verified. The body cipher then failed, so no record was recovered and carrier integrity is not established |

The name carries the ordering. Nothing reaches `Cannot Decrypt` without passing every earlier stage.

It is reachable when an attacker rewrites the bootstrap with a correct layout and a wrong session key or nonce. Those two fields are not signed, so the signature still verifies. The carrier was not shown to be altered, so `Tampered` would be false. Verification of the packet bytes did succeed, so `Cannot Verify` would discard a fact the receiver earned.

Note the difference from an earlier draft. Now that the whole record is encrypted, this state yields no media hash and no media identifier, so it does not report on carrier integrity at all. The verdict says only that the bytes came from the sender and the delivery parameters were wrong.

| Field | Value | Reason |
| --- | --- | --- |
| `valid` | `False` | a caller that writes `if result.valid:` must not proceed. Fail closed |
| `verdict` | `Cannot Decrypt` | names the stage that failed |
| `detail` | the signature verified; the AES-GCM tag rejected the body | the facts that were established |
| `payload` | `None` | nothing was recovered |

`Payload Missing` gains an ambiguity. A file addressed to a different receiver is indistinguishable from a file with no payload. The detail must not claim absence. It states that nothing was readable with the supplied key.

## 9. Sizes

Bootstrap region cost at 1 LSB:

| Scheme | Ciphertext | Units | Sample PNG | 32,000-sample WAV |
| --- | ---: | ---: | ---: | ---: |
| RSA-2048 OAEP | 256 B | 2,048 | 0.034% | 6.4% |
| RSA-3072 OAEP | 384 B | 3,072 | 0.051% | 9.6% |
| X25519 with AES-GCM | 113 B | 904 | 0.015% | 2.8% |

Smallest usable carrier, empty payload, 1 LSB:

| Scheme | Bootstrap | Packet | Total |
| --- | ---: | ---: | ---: |
| RSA-2048 | 2,048 | 2,952 | 5,000 units |
| X25519 | 904 | 2,952 | 3,856 units |

The packet figure includes the 16-byte GCM tag.

RSA-OAEP is chosen for version 2 because it adds no new primitive and keeps the explanation short. X25519 is recorded as the fallback if small audio carriers ever matter: it needs 113 bytes instead of 256 and it is available in the existing dependency.

The demonstration notebook uses a 32,000-sample WAV cover. Its separate 4,000-sample tone is typed payload data, not the cover. The multi-byte WAV capacity test fixture was raised from 2,000 to 6,000 samples so it can prove exactness above the reserved span. The protocol is not changed for a fixture.

## 10. Security model

**Not claimed.** The bootstrap is not hidden. An attacker knows where it is, how large it is, and what it is for. A uniformly random block at a fixed public offset is at least as easy to detect statistically as the version-1 marker.

**Claimed.** The exact packet location cannot be recovered from public protocol structure or locator metadata without the receiver key. Statistical steganalysis remains out of scope and may reveal evidence or approximate regions of embedding. Brief [§8](../docs/INF2005-ACW1-spec_v5-f2f.md#8-optional-challenge) lists steganalysis as an optional challenge, separate from the mandatory scope.

This wording replaces an earlier claim that locating the packet without a key was "not possible". The packet is still a contiguous replaced-bit region holding high-entropy data, so a steganalyst may infer approximate regions of embedding, particularly at higher LSB counts or with a large footprint. The claim is about protocol structure and locator metadata, not about statistics.

| Property | Version 1 | Version 2 |
| --- | --- | --- |
| Locate the packet from protocol structure, with no key | 0.002 to 0.43 s, measured | not available |
| Read the payload | needed the wrapped key | needs the receiver private key |
| Detect that a file is protected | trivial, public marker | trivial, random block at offset 0 |
| Forge a payload | needs the sender private key | needs the sender private key |
| Stop extraction without detection | overwrite the packet | overwrite the bootstrap, which is cheaper |
| Third party verifies authenticity | yes | no |

The bootstrap region is public and unauthenticated, and its bits are masked out of the media hash. An attacker can therefore destroy extraction cheaply and without leaving a tamper signal. There is no fix while the region is public. **This denial of service is accepted.** The receiver's verdict stays honest; it simply cannot say who caused it.

## 11. Decisions

| # | Decision | Call | Reason |
| ---: | --- | --- | --- |
| 1 | Verification requires the receiver private key | accept | unavoidable, and it matches brief §7 |
| 2 | Delete the packet header and marker | yes | redundant, and it defeats location confidentiality |
| 3 | Put the session key in the bootstrap | yes | the bootstrap is already an envelope to the receiver, so one asymmetric operation serves the whole file |
| 4 | RSA-OAEP rather than X25519 | RSA-OAEP | less conceptual surface for the assignment |
| 5 | Carrier-derived byte widths | yes, in all three formats | no arbitrary maximum, and no bit-packing faults |
| 6 | A public third-party verification mode | no | two modes is two protocols |
| 7 | Small WAV fixture | lengthen the fixture | not a protocol matter |
| 8 | Sign `flags` | yes | otherwise a signed packet can be reinterpreted |
| 9 | Always encrypt | yes, as a security invariant | a plaintext mode restores structural scanning |
| 10 | Encrypt the whole payload record | yes | the plaintext record is a second locator, measured at 0.002 s |
| 11 | Split the result into a verdict and a body status | no | one added verdict carries the same meaning with less API |
| 12 | Bind the session key and nonce with a signed commitment | no | substitution already fails at the tag, so this is only a naming choice, and the informative name wins |

Decision 12 was reconsidered in the owner review and reaffirmed: the session key and nonce remain implied by the GCM tag, with no signed commitment added. The existing rationale remains the reason on record.

| 12b | Bootstrap layout as GCM additional authenticated data | yes | no bytes on the wire, and a second binding on the fields that matter most |
| 13 | Fixed-width layout fields in the signing input | no | it would reintroduce a ceiling the bootstrap had removed |
| 14 | `MAX_WAV_FRAME_BYTES` | **superseded** | chunked carrier access removed the cap from the streamed WAV path; see [Streaming Carrier Plan, section 10](STREAMING-CARRIER-PLAN.md#10-whole-file-wav-cap) |
| 15 | Rename `keys.py` to `crypto.py` | yes | it gains AES-GCM, so the old name would describe two thirds of its contents |
| 16 | The caller-side payload seal in the notebook | delete it | the library now encrypts everything around it, so keeping it is encryption inside encryption, and a reader cannot tell which layer is load-bearing |

### The byte-only payload API is withdrawn

[Masked Media Integrity Design](PROTOCOL-DESIGN.md#decisions-and-what-was-rejected) recorded a byte-only payload API, with confidentiality left to the caller and no library change. Version 2 withdraws it.

The reason is not that the old decision was wrong. It was right for a protocol whose only goal was integrity. Location confidentiality is a goal version 1 never had, and it cannot be reached from outside the library, because the structure that leaks the location is the record that `core.py` builds. Section [1](#1-the-problem) holds the measurement: 0.002 seconds to recover a secret start unit from a plaintext record.

The content-type header stays caller-side and is unaffected. Version 2 encrypts the record; it still does not describe the bytes inside `user_payload`.

### Reasoning that was rejected, kept on purpose

**Decision 10 was withdrawn once, then reinstated.** The first withdrawal was correct in its stated reason and wrong in its conclusion. The only argument offered for encrypting the record was that the old rule about a readable `media_hash` had become void. That is not a reason; it only says nothing prevents it.

The mistake was the question. Encrypting the record was judged against version-1 criteria, hash readability and clean layering, while version 2 introduces a goal version 1 never had. Against location confidentiality, plaintext structure is not a layering preference but a hole. A version-1 judgement was carried into a version-2 design and never re-derived.

**"It is elegant" is not a reason either.** Decision 5 was re-examined when the signing input still used fixed 64-bit fields, because a derived width in the bootstrap removes no ceiling if the signed format keeps one. The answer was to extend the derived width to every format, not to keep it in one place for appearance.

## 12. Open decisions

### Decision 14: `MAX_WAV_FRAME_BYTES`

`MAX_WAV_FRAME_BYTES = 64 MiB` caps the **cover object**, not the payload. That is about six minutes of CD-quality stereo audio, so a seven-minute song cannot be used as a carrier. It is the same shape of arbitrary limit that section [5.1](#51-the-payload-limit-is-the-carrier) removes from the payload, one level up.

| Option | Cost |
| --- | --- |
| Keep it, documented as a memory guard, with the six-minute figure stated | an arbitrary cover-object limit survives |
| Raise it | still arbitrary, only further away |
| Remove it and bound by available memory | a malformed WAV header can request a large allocation before anything validates it |

The constant exists because the loader reads a declared frame count before it can check anything, so it is a resource guard rather than a format rule.

**Status: superseded.** The architectural change named here is implemented: whole-carrier arrays were replaced with seekable chunked access, and the streamed `encode_wav` and `verify_wav` path has no file-size cap. The constant remains only as the allocation guard for the whole-file helpers `WavPcmData` and `load_pcm_wav_from_path`. The [Streaming Carrier Plan](STREAMING-CARRIER-PLAN.md#10-whole-file-wav-cap) is the current record; the analysis above is kept as history.

The decision was left open instead of settled twice, so the history holds no false reason. It closed without deleting the constant: the streamed path no longer needs it, and the whole-file helpers still do.

## 13. What this breaks

| Area | Change |
| --- | --- |
| `stego/constants.py` | remove the marker, header format, candidate limit, and payload cap. Bump the version to 2. Add bootstrap constants. Replace the fixed-width signing and hash context formats |
| `stego/bits.py` | `validate_payload_length` takes carrier capacity instead of comparing against a constant |
| `stego/packet.py` | header build and parse deleted. Record serialisation unchanged, but it is now encrypted before embedding |
| `stego/layout.py` | two-region masking, with a disjointness check. `flags` in the signing input. Derived widths in both context formats. A single width function. `preserved_bit_count` takes the bootstrap span and subtracts one bit per unit across it |
| `stego/core.py` | discovery scan deleted. `verify_*` takes a receiver private key. Record encryption and decryption. Carrier-derived capacity check. `Cannot Decrypt` |
| `stego/layout.py` capacity | `max_payload_length` loses the header term and gains the GCM tag term. Names must distinguish the serialised-record maximum from the user-payload maximum. See section [5.2](#52-the-capacity-helper-must-migrate-with-the-header) |
| `stego/media.py` | unchanged |
| `stego/keys.py` | renamed to `stego/crypto.py`, and gains RSA-OAEP seal and open plus AES-GCM seal and open. Mechanical rename first, new functions later, so the two are reviewable apart |
| `stego/bootstrap.py` | new. Bootstrap field layout, span derivation, additional-data encoding, build, seal, open, parse |
| Notebook confidentiality cells | the caller-side payload seal is deleted, per decision 16. The content-header cells stay |
| `test_stego.py` | marker and discovery tests deleted. Added: bootstrap round trip, reserved-region refusal, untrusted-field validation, bootstrap tampering, power-of-two width, capacity boundary at several LSB counts |
| Notebook | every section. The "verify with only a public key" narrative changes. The 4,000-sample typed tone is clarified without lengthening it |
| Existing files | version-1 files become unreadable. No migration is planned, and the repository stores no old artefacts |
| [Typed Payload Metadata](PROTOCOL-DESIGN.md#typed-payload-metadata) | the sealed blob is replaced by the bootstrap. The FR9 claim about a readable `media_hash` is withdrawn. `metadata` is no longer readable. Capacity loses the bootstrap span |

## 14. Staging

Each stage is one commit and one review. A stage is not finished until it has an entry in the [Protocol Version 2 Stage Record](PROTOCOL-V2-STAGE-RECORD.md), which holds what each stage actually changed and measured. This plan holds intent; that record holds outcome.

| Stage | Scope | Gate |
| ---: | --- | --- |
| 0 | This record, with map and index rows | `check-docs.py` reports no errors |
| 1 | Carrier-derived capacity, `MAX_PAYLOAD_LENGTH` removed, rejection message names all four numbers | capacity boundary tests at several LSB counts, proving the limit function is the exact inverse of the layout builder |
| 2a | Derived width function, derived widths in both context formats, `flags` in the signing input | a power-of-two width test, an exact-length and golden-byte test for each format, version-1 round trips still pass |
| 2b | Two-region masking with a disjointness refusal, corrected `preserved_bit_count`, both taking the span as a required argument | tests for both masked regions, a refusal when the regions overlap, an exact-integer preserved-bit test |
| 2c | Rename `keys.py` to `crypto.py`. Mechanical only, no new functions | every test passes with no behaviour change, and nothing still imports the old name |
| 3 | `bootstrap.py`: build, seal, open, parse | round-trip and malformed-input tests |
| 4a | Name the two capacity quantities and thread the span through the capacity path. No cryptography, no API change | boundary tests for both quantities, and a refusal naming the reserved region |
| 4b | Delete the marker, the scan, the candidate limit and the header format. Decode and file-verification wrappers take start unit, LSB count, and complete serialised record length as required arguments. **Update the capacity helper in the same commit**, per section [5.2](#52-the-capacity-helper-must-migrate-with-the-header) | round trips pass with all three geometry values supplied; executable sources contain no deleted names; capacity tests prove exactness for the headerless, unencrypted layout |
| 4c | The bootstrap carries the geometry, the record is encrypted, `verify_*` takes the receiver private key, `Cannot Decrypt` arrives, `PROTOCOL_VERSION` becomes 2 | complete: 50 tests, including the full verdict matrix and bootstrap-tamper case |
| 5 | Notebook narrative, verdict matrix, fidelity integer, and caller-side seal removal | fresh-kernel execution has no error outputs, the fidelity output shows the exact integer and 2,048-bit bootstrap term, and 50 tests plus `check-docs.py` pass |
| 6a | Replace `PayloadRecord`'s fixed uint32 length fields with the carrier-derived width; keep the one-byte media-id prefix | record round trips at W=1, 2, 3, and 4; width transitions, >uint32 declared lengths, power-of-two agreement, exact capacities, and 54 tests pass |
| 6b | Reject an actual carrier that cannot hold the minimum protocol object; do not derive a minimum from no carrier | 55 tests pass; minima encode and verify, one-below minima refuse without modifying input, and zero capacity is reserved for exact fits |

Stage 1 is deliberately first and separable. It is useful on its own, because the carrier-derived payload limit fixes a real defect in version 1 independently of anything else in this plan.

The derived width function moved from stage 1 to stage 2. Nothing calls it until the signing and hash formats change, and a function with no caller is a function with no test of its use.

Stage 4 is split three ways, because encode and decode must change together or nothing round-trips, and one commit carrying that whole switch cannot be reviewed.

The step that breaks the deadlock is 4b. Geometry moves in three hops: it is in the file and public today, it becomes an out-of-band argument the caller supplies, and only then does it move back into the file as encrypted bootstrap content. The middle state round-trips and stays green with no bootstrap in existence, so the marker, the scan and the header can be deleted on their own and reviewed on their own.

That also absorbs the old stage 5. Keeping the header through the encryption switch would mean building a transitional carrier holding two locators, one public and one secret, and then deleting one of them immediately.

The middle state supplies geometry separately from the carrier. That needs three values, not two: removing the header also removes the record length needed to locate the signature and bound extraction. Stage 4b therefore adds required `start_unit`, `lsb_count`, and `payload_length` arguments to `decode_carrier`, `verify_png`, and `verify_wav`. A temporary record-prefix reader would add code that stage 4c immediately deletes, so it is not used.

This intermediate state does not provide location confidentiality. Removing explicit locator fields does not remove the predictable plaintext record prefix measured in section [1](#1-the-problem). The earlier claim that out-of-band geometry was stronger than either version ignored that prefix. Stage 4c must both encrypt the record and carry the geometry in the receiver bootstrap.

Stage 4b also removes candidate-limit and ambiguity checks because there is no scan or candidate selection left. It checks only the supplied location; it does not establish that the carrier contains only one packet. Without a recognition step, it no longer emits `Payload Missing`.

Stage 2c is a rename with no new code. It comes before stage 3 so that the diff introducing the envelope functions is not mixed with import churn across the package.

Stage 2 is split. Stage 2a is byte-layout work that needs no new concept and leaves every function signature unchanged, so it can be reviewed as a format diff. Stage 2b introduces the bootstrap span as an argument, which is a new idea and deserves its own review. Bundling them would put four unrelated changes in one commit.
