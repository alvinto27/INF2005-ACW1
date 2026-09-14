# Location Confidentiality Plan

**Status: proposed. Nothing in this plan is built.** It describes protocol version 2. The repository implements version 1, which is described in [Masked Media Integrity Design](INTEGRITY-DESIGN.md).

The goal is to protect the payload start location, length, and LSB depth from everyone except the intended receiver, while the user still chooses all three by hand.

One decision is deferred. See [Open decisions](#12-open-decisions).

## 1. The problem

Version 1 finds the packet by scanning the carrier for a public 16-byte marker under each LSB count from 1 to 8. See [Payload discovery](INTEGRITY-DESIGN.md#payload-discovery).

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
| `BOOTSTRAP_SPAN` | receiver key size in bytes, multiplied by 8 | 2,048 units for RSA-2048 |
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

`MEDIA_HASH_CONTEXT_FORMAT` gains the bootstrap span and uses the derived width. The span is a public constant, but it changes with the receiver key size, so the hash must commit to it.

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
| Banana 1280x1568 | 8 | 6,018,699 B | within the cap |
| Phone photo 4000x3000 | 8 | 35,997,579 B | **rejects 19 MB that fit** |
| DSLR 6000x4000 | 8 | 71,997,579 B | **rejects 55 MB that fit** |

Brief [§5](../docs/INF2005-ACW1-spec_v5-f2f.md#5-mandatory-scope) lists a required case: "Cover-object and payload-capacity check: is the payload size larger than the cover-object size?" The brief asks whether the payload fits the cover object. Answering "no, because of a constant in our header" answers a different question.

`MAX_PAYLOAD_LENGTH` is removed. The limit becomes:

```text
max_user_payload = (total_units - start_unit) * lsb_count / 8
                   - record_overhead      101 bytes
                   - gcm_tag               16 bytes
                   - signature            256 bytes
```

Three user choices in, one honest answer out. The rejection message must name the carrier units, the start unit, the LSB count, and the computed maximum, because that message is the capacity check the brief asks to see demonstrated.

**Removing the cap tightens the allocation guard rather than weakening it.** `ciphertext_length` arrives from the attacker-writable bootstrap, so it must be bounded before anything is allocated. The carrier capacity is a tight bound taken from the file already in memory. The old constant was the looser guard in every case that mattered: far too large for a thumbnail, far too small for a photograph.

### 5.2 One derived width

```python
def carrier_field_width(total_units: int) -> int:
    """Bytes needed for any carrier-bounded quantity. One rule, one place."""
    return max(1, (total_units.bit_length() + 7) // 8)
```

Because the LSB count never exceeds 8, the largest possible packet byte count is `total_units * lsb_count / 8`, which is at most `total_units`. A width derived from the unit count therefore covers positions, footprints, and lengths alike.

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

### 5.3 Two invariants that variable widths create

**Derive the width in one place.** If the sender and the verifier derive `W` differently, every signature breaks. `bit_length(N)` and `bit_length(N - 1)` disagree whenever the unit count is a power of two, and the two expressions look interchangeable. One function, called from all three formats, never re-derived inline. A test at a power-of-two unit count belongs with it.

**The signing input must stay injective given the carrier.** It is: `W` is fixed once the unit count is known, `media_context` has a fixed length per medium, and `ciphertext_length` sits in the fixed-width prefix ahead of the variable tail. No two field tuples can serialise to the same bytes. A future field appended without a length prefix would break this, so the property is written down here.

### 5.4 Remaining ceilings

| Ceiling | Decision |
| --- | --- |
| `MAX_PAYLOAD_LENGTH` | removed. The carrier is the limit |
| `payload_length` as `u32` | replaced by the derived width |
| `total_units`, `start_unit`, `footprint` as `u64` | replaced by the derived width |
| `MEDIA_HASH_CONTEXT_FORMAT` three `u64` fields | replaced by the derived width |
| `PACKET_HEADER_FORMAT` `u32` length | deleted with the header |
| `MAX_MAGIC_CANDIDATES` | deleted with the scan |
| `MAX_MEDIA_ID_BYTES` = 255 | kept. A one-byte length prefix on an internally generated 36-byte value. Not a payload ceiling |
| `PNG_MEDIA_CONTEXT_FORMAT` `">II"` | kept. Four billion pixels per side |
| `WAV_MEDIA_CONTEXT_FORMAT` `">HBIQ"` | kept. The frame count is already 64-bit |
| `MAX_WAV_FRAME_BYTES` = 64 MiB | **deferred.** See [Open decisions](#12-open-decisions) |

## 6. Encode

| Step | Action |
| ---: | --- |
| 1 | Load the carrier and count addressable units |
| 2 | Load the sender signing private key and the receiver encryption public key |
| 3 | Set `BOOTSTRAP_SPAN` from the receiver key size. Refuse a carrier that is too small |
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
| 3 | Read `key_bytes x 8` units from unit 0 at 1 LSB | `Cannot Verify` |
| 4 | RSA-OAEP decrypt | `Payload Missing` |
| 5 | Parse the plaintext and check the version | `Cannot Verify` |
| 6 | Validate every recovered field against the carrier | `Cannot Verify` |
| 7 | Extract `record_ciphertext_with_tag ‖ signature` | `Cannot Verify` |
| 8 | Verify RSA-PSS with the sender public key | `Signature Invalid` |
| 9 | AES-GCM decrypt with the bootstrap layout as additional data | `Cannot Decrypt` |
| 10 | Parse the record | `Cannot Verify` |
| 11 | Recompute the masked hash over both regions and compare with the recovered value | `Tampered` |
| 12 | — | `Authentic` |

### Ordering invariant

No code may act on `flags` before step 8. A signed field does not help if something interprets it earlier. The check has to sit where it cannot be skipped.

### Step 6 is load-bearing

Every value from the bootstrap is untrusted input until step 8 passes. Step 6 checks that the LSB count is 1 to 8, that the start unit is at or above `BOOTSTRAP_SPAN`, and that the start unit plus the footprint fits inside the carrier. It bounds `ciphertext_length` by the carrier capacity before anything is allocated.

### Step 4 is recognition, not authentication

Successful OAEP decoding serves as a private bootstrap-recognition mechanism for the intended receiver. It does not authenticate the bootstrap sender, because anyone holding the receiver's public key can produce a valid ciphertext.

OAEP decoding requires a leading zero byte, a 32-byte label-hash equality, and a `0x01` separator. Random low bits from an ordinary photograph fail that structure, so an unprotected file is recognised as such, and no marker is needed.

## 8. Verdicts

Version 1 verdicts keep their meaning. See [Verification verdicts](INTEGRITY-DESIGN.md#verification-verdicts). One verdict is added.

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
| RSA-2048 | 2,048 | 2,872 | 4,920 units |
| X25519 | 904 | 2,872 | 3,776 units |

The packet figure includes the 16-byte GCM tag.

RSA-OAEP is chosen for version 2 because it adds no new primitive and keeps the explanation short. X25519 is recorded as the fallback if small audio carriers ever matter: it needs 113 bytes instead of 256 and it is available in the existing dependency.

The demonstration notebook generates a 4,000-sample tone, which is below the RSA-2048 minimum. The fixture is lengthened. The protocol is not changed for a fixture.

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
| 12b | Bootstrap layout as GCM additional authenticated data | yes | no bytes on the wire, and a second binding on the fields that matter most |
| 13 | Fixed-width layout fields in the signing input | no | it would reintroduce a ceiling the bootstrap had removed |
| 14 | `MAX_WAV_FRAME_BYTES` | **deferred** | see [Open decisions](#12-open-decisions) |

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

**Status: deferred.** A larger architectural change has been raised that may remove the need for the constant. The decision waits for that proposal, so that a limit is not documented as permanent and then deleted in the next change.

## 13. What this breaks

| Area | Change |
| --- | --- |
| `stego/constants.py` | remove the marker, header format, candidate limit, and payload cap. Bump the version to 2. Add bootstrap constants. Replace the fixed-width signing and hash context formats |
| `stego/bits.py` | `validate_payload_length` takes carrier capacity instead of comparing against a constant |
| `stego/packet.py` | header build and parse deleted. Record serialisation unchanged, but it is now encrypted before embedding |
| `stego/layout.py` | two-region masking. `flags` in the signing input. Derived widths in both context formats. A single width function |
| `stego/core.py` | discovery scan deleted. `verify_*` takes a receiver private key. Record encryption and decryption. Carrier-derived capacity check. `Cannot Decrypt` |
| `stego/media.py` | unchanged |
| `test_stego.py` | marker and discovery tests deleted. Added: bootstrap round trip, reserved-region refusal, untrusted-field validation, bootstrap tampering, power-of-two width, capacity boundary at several LSB counts |
| Notebook | every section. The "verify with only a public key" narrative changes. The tone fixture is lengthened |
| Existing files | version-1 files become unreadable. No migration is planned, and the repository stores no old artefacts |
| [Payload Envelope Design](PAYLOAD-ENVELOPE-DESIGN.md) | the sealed blob is replaced by the bootstrap. The FR9 claim about a readable `media_hash` is withdrawn. `metadata` is no longer readable. Capacity loses the bootstrap span |

## 14. Staging

Each stage is one commit and one review.

| Stage | Scope | Gate |
| ---: | --- | --- |
| 0 | This record, with map and index rows | `check-docs.py` reports no errors |
| 1 | Derived width function, carrier-derived capacity, `MAX_PAYLOAD_LENGTH` removed | capacity boundary tests at several LSB counts, and a power-of-two width test |
| 2 | `layout.py`: two-region masking, `flags` in the signing input, derived widths in both context formats | tests for both masked regions, version-1 tests updated |
| 3 | `bootstrap.py`: build, seal, open, parse | round-trip and malformed-input tests |
| 4 | `core.py`: encode and decode flows, record encryption with additional authenticated data, reserved-region validation, `Cannot Decrypt` | verdict matrix including the bootstrap-tamper case |
| 5 | Delete the marker, the scan, the candidate limit, and the header format | nothing references them |
| 6 | Notebook: new narrative, lengthened tone, new verdict matrix | executes end to end with no error outputs |

Stage 1 is deliberately first and separable. It is useful on its own, because the carrier-derived payload limit fixes a real defect in version 1 independently of anything else in this plan.
