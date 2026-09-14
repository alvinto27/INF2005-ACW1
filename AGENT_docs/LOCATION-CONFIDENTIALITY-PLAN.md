# Location Confidentiality Plan

**Status: proposed. Nothing in this plan is built.** It describes protocol version 2. The repository implements version 1, which is described in [Masked Media Integrity Design](INTEGRITY-DESIGN.md).

The goal is to protect the payload start location, length, and LSB depth from anyone except the intended receiver, while the user still chooses all three by hand.

One open decision remains. See [Open decision](#open-decision).

## 1. The problem

Version 1 finds the packet by scanning the carrier for a public 16-byte marker under each LSB count from 1 to 8. See [Payload discovery](INTEGRITY-DESIGN.md#payload-discovery).

The marker is a public constant, so the scan is available to everybody. Measured on the sample carriers, an attacker with no key finds the packet in 0.01 to 0.43 seconds. Brief [§5](../docs/INF2005-ACW1-spec_v5-f2f.md#5-mandatory-scope) asks the team to explain how the start location is secured against guessing and unauthorised extraction. Version 1 has no real answer.

Deleting the marker alone does not work. The receiver then cannot find the packet either. Something must tell the receiver where to look, and only the receiver.

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

An attempt to break the dependency fails. The masked media hash preimage contains `start_unit` and `footprint`, and the mask is applied to that range, so the hash cannot be recomputed without the location. Masking the low bits of the whole carrier instead would make the hash location-independent, but the location would still be needed to find the signature, and the hash would cover far less:

| LSB count | Bits covered now | Bits covered if masked globally | Loss |
| ---: | ---: | ---: | ---: |
| 1 | 48,166,460 | 42,147,840 | 12.5% |
| 3 | 48,161,460 | 30,105,600 | 37.5% |
| 8 | 48,148,960 | 0 | 100% |

Measured on the 1280x1568 sample carrier.

**Accepted.** Brief [§7](../docs/INF2005-ACW1-spec_v5-f2f.md#7-required-security-workflow) makes party B both the receiver and the verifier, so receiver-gated verification matches the workflow the assignment describes.

Consequence for the API: `verify_png` and `verify_wav` take the receiver's private key in addition to the sender's public key.

## 3. Design

### 3.1 Public constants

| Constant | Value | Reason |
| --- | --- | --- |
| `BOOTSTRAP_START_UNIT` | 0 | fixed and public. There is no discovery step |
| `BOOTSTRAP_LSB_COUNT` | 1 | least change to the cover |
| `BOOTSTRAP_SPAN` | receiver key size in bytes, multiplied by 8 | 2,048 units for RSA-2048 |
| `PROTOCOL_VERSION` | 2 | version-1 files are not readable under this scheme |

### 3.2 The packet header is removed

Version 1 writes a 23-byte header of `magic ‖ version ‖ media_code ‖ lsb_count ‖ payload_length`. The bootstrap carries the version, the LSB count, and the payload length, so the header holds nothing new. The marker is the beacon this plan exists to remove.

The embedded packet becomes exactly:

```text
payload_bytes || signature
```

`START_MAGIC`, `PACKET_HEADER_FORMAT`, `PACKET_HEADER_SIZE`, `MAX_MAGIC_CANDIDATES`, and the eight-LSB discovery scan are all deleted.

### 3.3 Bootstrap

The bootstrap is RSA-OAEP with SHA-256, encrypted to the receiver's public key. Its plaintext is byte-aligned, and the numeric field widths come from the carrier:

```text
version         u8      = 2
flags           u8      reserved
lsb_count       u8      1 to 8
start_unit      W bytes big-endian
payload_length  L bytes big-endian
session_key     32      AES-256-GCM
nonce           12
```

```text
W = ((N - 1).bit_length() + 7) // 8        N = addressable carrier units
L = ((max_payload_for_carrier).bit_length() + 7) // 8
```

Both sides know the carrier geometry before they read the bootstrap, so both derive the same widths. This sets no protocol maximum on the position. Byte alignment is used instead of bit packing because the budget makes bit packing pointless: RSA-2048 OAEP with SHA-256 allows 190 plaintext bytes, and the fields above need 53 for the sample carrier.

There is no terminator and no plaintext marker. OAEP decryption returns the exact plaintext length.

### 3.4 Signing input

```text
SIGNING_DOMAIN
|| version         u8
|| flags           u8
|| media_code      u8
|| lsb_count       u8
|| total_units     u64
|| start_unit      u64
|| footprint       u64
|| payload_length  u32
|| media_context
|| payload_bytes
```

`flags` is new. Section [4](#4-field-binding-audit) explains why it must be there.

### 3.5 Payload bytes are unchanged

```text
payload_bytes = media_id || timestamp || record_nonce || media_hash || user_payload || metadata
```

`media_hash` stays inside `payload_bytes`, in the clear, under the RSA-PSS signature. Only `user_payload` becomes AES-GCM ciphertext.

The reason is separation, not necessity. Carrier authenticity and message confidentiality are two different questions. Encrypting `media_hash` would chain the first question to the second and buy nothing:

| Benefit | Detail |
| --- | --- |
| Verdict precision | The system can report an authentic carrier with an unreadable body. If the hash were encrypted, every cipher failure would look like tampering |
| Failure isolation | A fault in the cipher layer cannot move an authenticity verdict |
| Small change | The payload record and its serialisation are untouched from version 1 |

### 3.6 The masked hash covers two regions

Both the bootstrap region and the packet region are overwritten, so the mask clears both, each at its own LSB count:

```text
masked[0 : BOOTSTRAP_SPAN]                  &= 0xFE          bootstrap, k = 1
masked[start_unit : start_unit + footprint] &= ~((1<<k)-1)    packet, user k
```

`MEDIA_HASH_CONTEXT_FORMAT` gains the bootstrap span. The span is a public constant, but it changes with the receiver key size, so the hash must commit to it.

## 4. Field binding audit

Every bootstrap field is attacker-writable, because the receiver's public key is public. Therefore each field must be either signed directly or implied by something that is already authenticated.

| Field | Bound how | An attacker who changes it gets |
| --- | --- | --- |
| `version` | signed. The signing input uses the sender's constant, not the value read from the bootstrap | signature failure. A later version cannot be downgraded |
| `flags` | signed | signature failure |
| `lsb_count` | signed | wrong bits extracted, then signature failure |
| `start_unit` | signed | wrong region extracted, then signature failure |
| `payload_length` | signed | wrong span, then signature failure |
| `session_key` | implied by the AES-GCM tag | `Cannot Decrypt` |
| `nonce` | implied by the AES-GCM tag | `Cannot Decrypt` |

### Why `flags` must be signed

`flags` controls how `payload_bytes` is interpreted. Without it in the signing input, an attacker can:

1. take a legitimate file whose body is ciphertext;
2. write a fresh, valid bootstrap with the receiver's public key, keeping `start_unit`, `lsb_count`, and `payload_length`;
3. set the encryption flag to zero.

The signed bytes never move. RSA-PSS verifies. The masked hash matches. The decoder skips decryption and hands ciphertext to the caller as the message, with the verdict `Authentic`.

Nothing is forged. The signature authenticated the bytes but not their meaning. That is the same defect class as an unsigned content type, one layer lower.

### A trap in the version field

The signing input must keep using the sender's `PROTOCOL_VERSION` constant. It must not use the version byte read from the bootstrap. Reading it from the bootstrap looks tidier and silently removes the downgrade protection. This needs a comment in the code.

## 5. Encode

| Step | Action |
| ---: | --- |
| 1 | Load the carrier and count addressable units `N` |
| 2 | Load the sender signing private key and the receiver encryption public key |
| 3 | Set `BOOTSTRAP_SPAN` from the receiver key size. Refuse a carrier that is too small |
| 4 | The user chooses `start_unit`, `lsb_count`, and the payload |
| 5 | Refuse `start_unit` below `BOOTSTRAP_SPAN`, and name the reserved region in the error |
| 6 | Build the layout. Refuse a footprint that does not fit |
| 7 | Encrypt `user_payload` with a fresh AES-256-GCM key |
| 8 | Compute the masked media hash with both regions masked |
| 9 | Sign the signing input of section [3.4](#34-signing-input) |
| 10 | Build the bootstrap plaintext and seal it with RSA-OAEP to the receiver |
| 11 | Write the bootstrap at unit 0 at 1 LSB |
| 12 | Write `payload_bytes ‖ signature` at the user's `start_unit` at the user's LSB count |

Step 8 runs before anything is written, and the mask clears bits instead of reading them, so there is no circular dependency.

## 6. Decode

| Step | Action | Verdict if it fails |
| ---: | --- | --- |
| 1 | Load the carrier and count `N` | `Cannot Verify` |
| 2 | Load the receiver private key and the sender public key | — |
| 3 | Read `key_bytes x 8` units from unit 0 at 1 LSB | `Cannot Verify` |
| 4 | RSA-OAEP decrypt | `Payload Missing` |
| 5 | Parse the plaintext and check `version == 2` | `Cannot Verify` |
| 6 | Validate every recovered field against the carrier | `Cannot Verify` |
| 7 | Extract `payload_bytes ‖ signature` | `Cannot Verify` |
| 8 | Verify RSA-PSS with the sender public key | `Signature Invalid` |
| 9 | Recompute the masked hash over both regions and compare | `Tampered` |
| 10 | AES-GCM decrypt `user_payload` | `Cannot Decrypt` |
| 11 | — | `Authentic` |

### Ordering invariant

Steps 8 and 9 settle authenticity. Step 10 cannot change it.

No code may act on `flags` before step 8. A signed field does not help if something interprets it earlier. The check has to sit where it cannot be skipped.

### Step 6 is load-bearing

Every value from the bootstrap is untrusted input until step 8 passes. Step 6 checks that `lsb_count` is 1 to 8, that `start_unit` is at or above `BOOTSTRAP_SPAN`, and that `start_unit + footprint` fits inside `N`.

### Step 4 is recognition, not authentication

Successful OAEP decoding serves as a private bootstrap-recognition mechanism for the intended receiver. It does not authenticate the bootstrap sender, because anyone holding the receiver's public key can produce a valid ciphertext.

OAEP decoding requires a leading zero byte, a 32-byte label-hash equality, and a `0x01` separator. Random low bits from an ordinary photograph fail that structure, so an unprotected file is recognised as such. That makes OAEP a recogniser, and the marker is not needed.

## 7. Verdicts

Version 1 verdicts keep their meaning. See [Verification verdicts](INTEGRITY-DESIGN.md#verification-verdicts). One verdict is added.

| Verdict | Meaning |
| --- | --- |
| `Cannot Decrypt` | The signature verified and the masked hash matched. Only the body cipher failed |

The name carries the ordering. Nothing reaches `Cannot Decrypt` without passing every earlier stage.

It is reachable when an attacker rewrites the bootstrap with a correct layout and a wrong `session_key` or `nonce`. Those two fields are not signed, so the signature still verifies. The carrier was not tampered with, so `Tampered` would be false. Verification did succeed, so `Cannot Verify` would discard a fact the receiver earned.

Result fields for this verdict:

| Field | Value | Reason |
| --- | --- | --- |
| `valid` | `False` | a caller that writes `if result.valid:` must not use an unreadable body. Fail closed |
| `verdict` | `Cannot Decrypt` | names the stage that failed |
| `detail` | signature and masked hash passed; the AES-GCM tag rejected the body | the facts that were established |
| `payload` | present, with `user_payload` still ciphertext | a careful caller can read the authentic record and the layout |

`Payload Missing` gains an ambiguity. A file addressed to a different receiver is indistinguishable from a file with no payload. The verdict detail must not claim absence. It states that nothing was readable with the supplied key.

## 8. Sizes

Bootstrap region cost at 1 LSB:

| Scheme | Ciphertext | Units | Sample PNG | 32,000-sample WAV |
| --- | ---: | ---: | ---: | ---: |
| RSA-2048 OAEP | 256 B | 2,048 | 0.034% | 6.4% |
| RSA-3072 OAEP | 384 B | 3,072 | 0.051% | 9.6% |
| X25519 with AES-GCM | 113 B | 904 | 0.015% | 2.8% |

Smallest usable carrier, empty payload, 1 LSB:

| Scheme | Bootstrap | Packet | Total |
| --- | ---: | ---: | ---: |
| RSA-2048 | 2,048 | 2,856 | 4,904 units |
| X25519 | 904 | 2,856 | 3,760 units |

RSA-OAEP is chosen for version 2 because it adds no new primitive and keeps the explanation short. X25519 is recorded as the fallback if small audio carriers ever matter: it needs 113 bytes instead of 256 and it is available in the existing dependency.

The demonstration notebook generates a 4,000-sample tone, which is below the RSA-2048 minimum. The fixture is lengthened. The protocol is not changed for a fixture.

## 9. Security model

**Not claimed.** The bootstrap is not hidden. An attacker knows where it is, how large it is, and what it is for. A uniformly random block at a fixed public offset is at least as easy to detect statistically as the version-1 marker.

**Claimed.** An attacker who holds the whole file and knows the entire protocol cannot learn the payload start location, length, LSB depth, or contents.

| Property | Version 1 | Version 2 |
| --- | --- | --- |
| Locate the packet with no key | 0.01 to 0.43 s, measured | not possible |
| Read the payload | needed the wrapped key | needs the receiver private key |
| Detect that a file is protected | trivial, public marker | trivial, random block at offset 0 |
| Forge a payload | needs the sender private key | needs the sender private key |
| Stop extraction without detection | overwrite the packet | overwrite the bootstrap, which is cheaper |
| Third party verifies authenticity | yes | no |

The bootstrap region is public and unauthenticated, and its bits are masked out of the media hash. An attacker can therefore destroy extraction cheaply and without leaving a tamper signal. There is no fix while the region is public. **This denial of service is accepted.** The receiver's verdict stays honest; it simply cannot say who caused it.

## 10. Decisions

| # | Decision | Call | Reason |
| ---: | --- | --- | --- |
| 1 | Verification requires the receiver private key | accept | unavoidable, and it matches brief §7 |
| 2 | Delete the packet header and marker | yes | redundant, and it defeats location confidentiality |
| 3 | Put the AES session key in the bootstrap | yes | the bootstrap is already an envelope to the receiver. One asymmetric operation |
| 4 | RSA-OAEP rather than X25519 | RSA-OAEP | less conceptual surface for the assignment |
| 5 | Carrier-derived byte widths | yes | no arbitrary maximum, and no bit-packing faults |
| 6 | A public third-party verification mode | no | two modes is two protocols |
| 7 | Small WAV fixture | lengthen the fixture | not a protocol matter |
| 8 | Sign `flags` | yes | otherwise a signed packet can be reinterpreted |
| 9 | Always encrypt `user_payload` | **open** | see [Open decision](#open-decision) |
| 10 | Encrypt the whole payload record | withdrawn | the only argument for it was that nothing blocked it |
| 11 | Split the result into a verdict and a body status | withdrawn | one added verdict carries the same meaning with less API |

### Rejected reasoning, kept on purpose

Decision 10 was proposed because the earlier rule that `media_hash` must stay readable had become void. That is not a reason to change anything. It only says nothing prevents it. Section [3.5](#35-payload-bytes-are-unchanged) holds the positive reason for leaving the record in the clear.

## Open decision

**Decision 9. Always encrypt `user_payload`, or keep it switchable behind the signed `flags` bit?**

| | Switchable | Always |
| --- | --- | --- |
| Body code paths | 2 | 1 |
| Mode confusion | prevented, because `flags` is signed | impossible, because there is no mode |
| `Cannot Decrypt` | reachable in one mode | always live, therefore always tested |
| Notebook setup | a receiver key pair sometimes | a receiver key pair always |

Recommendation: always encrypt. The bootstrap already needs a receiver key for every operation, so a plaintext body saves no setup and only adds a second path to test. Keep `flags` as a signed reserved byte that must be zero, so that the next field anyone adds is covered by the signature from the start.

## 11. What this breaks

| Area | Change |
| --- | --- |
| `stego/constants.py` | remove the marker, header format, and candidate limit. Bump the version to 2. Add bootstrap constants |
| `stego/packet.py` | header build and parse deleted |
| `stego/layout.py` | two-region masking. `flags` in the signing input. Hash context format changes |
| `stego/core.py` | discovery scan deleted. `verify_*` takes a receiver private key. `Cannot Decrypt` added |
| `stego/media.py` | unchanged |
| `test_stego.py` | marker and discovery tests deleted. Bootstrap, reserved-region, untrusted-field, and bootstrap-tamper tests added |
| Notebook | every section. The "verify with only a public key" narrative changes. The tone fixture is lengthened |
| Existing files | version-1 files become unreadable. No migration is planned, and the repository stores no old artefacts |
| [Payload Envelope Design](PAYLOAD-ENVELOPE-DESIGN.md) | the sealed blob is replaced by the bootstrap. Capacity loses the bootstrap span |

## 12. Staging

Each stage is one commit and one review.

| Stage | Scope | Gate |
| ---: | --- | --- |
| 0 | This record, with map and index rows | `check-docs.py` reports no errors |
| 1 | `layout.py`: two-region masking, `flags` in the signing input, hash context format | tests for both masked regions; version-1 tests updated |
| 2 | `bootstrap.py`: build, seal, open, parse, carrier-derived widths | round-trip and malformed-input tests |
| 3 | `core.py`: encode and decode flows, reserved-region validation, `Cannot Decrypt` | verdict matrix including the bootstrap-tamper case |
| 4 | Delete the marker, the scan, the candidate limit, and the header format | nothing references them |
| 5 | Notebook: new narrative, lengthened tone, new verdict matrix | executes end to end with no error outputs |

Stage 1 lands before stage 2 exists, so the masking change can be reviewed on its own rather than inside a rewrite.
