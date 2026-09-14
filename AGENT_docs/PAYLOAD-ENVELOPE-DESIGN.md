# Payload Envelope Design

Protocol version 2 encrypts the complete payload record inside the library, including `user_payload`. This record describes what the caller places inside those encrypted bytes: an optional sealed envelope for an additional confidentiality layer, and a content header that declares what the bytes are.

The content header remains caller-side. The caller-side seal was removed from the stage 5 demonstration under decision 16, while the content-header layer survives. This record therefore documents the caller-added layers, not the library's record encryption. See [Masked Media Integrity Design](INTEGRITY-DESIGN.md).

**The encryption layer does not survive protocol version 2.** That version encrypts the whole payload record inside the library, unconditionally, so the caller-side seal described below becomes encryption inside encryption. The seal and its notebook demonstration are removed when version 2 lands; see decision 16 in the [Location Confidentiality Plan](LOCATION-CONFIDENTIALITY-PLAN.md#11-decisions).

**The content-type header is unaffected.** Version 2 encrypts the record; it still does not describe the bytes inside `user_payload`, so that layer stays caller-side and stays necessary.

The working demonstration is in the Confidentiality from the protocol and Typed payloads sections of the [demonstration notebook](../notebooks/FR1-12%20Prototype.ipynb).

## 1. Layering

```text
user_payload
└─ sealed blob          wrapped key · caller seal nonce · ciphertext with tag
   └─ content header    version · mime · name        (plaintext, inside the seal)
      └─ body           the file bytes
```

The content header is inside the optional caller-side seal. Protocol version 2 makes the receiver's private key the gate: an observer learns nothing about the packet from protocol structure, and the record length is encrypted in the bootstrap. The header is never in `metadata`; it describes the body bytes, while `metadata` remains a separate team-defined record field.

## 2. Sealed blob

This caller-side layer is designed and recorded but is no longer shown in the notebook. Stage 5 removes it because protocol version 2 already encrypts and signs the complete record inside the library; adding this seal would encrypt the content twice. Decision 16 in the [Location Confidentiality Plan](LOCATION-CONFIDENTIALITY-PLAN.md#11-decisions) records that choice.

A random AES-256-GCM key encrypts the content header and the body together. RSA-OAEP with SHA-256 wraps that key with the receiver's public key.

| Field | Size | Notes |
| --- | --- | --- |
| Wrapped AES key | 256 bytes | RSA-2048, OAEP, SHA-256, MGF1-SHA-256, no label |
| Nonce | 12 bytes | fresh random value for every payload |
| Ciphertext with tag | remainder | 16-byte GCM tag included |

The fixed prefix is 268 bytes.

Hybrid encryption is required, not preferred. RSA-2048 OAEP with SHA-256 can encrypt at most 190 bytes directly, which is smaller than most payloads.

### Record visibility

Nothing in the payload record stays readable. Two protections carry separate fields:

```text
record     AES-256-GCM   media_id, timestamp, record nonce,
                          media_hash, user_payload, metadata
bootstrap  RSA-OAEP      version, flags, lsb_count, start_unit,
                          ciphertext_length, session_key, aead nonce
```

The receiver decrypts the record, recomputes the masked media hash, and compares it with the recovered value. The [Location Confidentiality Plan, section 3.5](LOCATION-CONFIDENTIALITY-PLAN.md#35-the-whole-payload-record-is-encrypted) records why FR9 requires the comparison, not plaintext access before decryption.

### Key handling in the demonstration

The receiver's private key is written to a password-protected PEM file, then loaded again in the receiver phase. The receiver verifies with a sender public key and the receiver private key. The geometry is recovered from the RSA-OAEP bootstrap; it is not transported as three plaintext values.

## 3. Content header

```text
version    u8, value 1
mime_len   u8
mime       UTF-8, lowercase ASCII
name_len   u8
name       UTF-8, can be empty
body       the remaining bytes
```

Rules and the reason for each:

| Rule | Reason |
| --- | --- |
| Big-endian, length-prefixed | agrees with the packet format. There are no delimiters to escape |
| Version byte first | a later change does not need a new packet format |
| Body length implicit | removes one field that can disagree with the data |
| Empty `mime` means `application/octet-stream` | an unknown type is a permitted answer |
| `mime` and `name` limited to 255 bytes | one-byte length fields |
| `name` must be a bare filename | the reader refuses `/`, `\`, and `..` |

## 4. The declared type is a claim, not a fact

A signature proves that the sender said the bytes were a PNG. It does not prove that the bytes are a PNG. A signature can make a false claim look trustworthy, which is worse than no signature if the receiver relaxes because of it.

Therefore the receiver chooses a handler from the declared type, then confirms with the bytes before it renders anything:

```text
sniffed is None   ->  agrees only when the declared type has no known magic bytes
sniffed is set    ->  agrees only when it equals the declared type
```

The four outcomes:

| Declared | Sniffed | Agrees | Reason |
| --- | --- | --- | --- |
| `text/plain` | none | yes | text has no magic bytes. Absence is not a contradiction |
| `image/png` | none | no | claims a type with known magic bytes, and the bytes are absent |
| `image/png` | `image/png` | yes | the claim and the bytes agree |
| `text/plain` | `image/png` | no | the bytes claim a known binary type that the sender denied |

The check is inside the function that renders. It is not at the call site. A check that the caller can forget is not a check.

Types recognised by magic bytes: `image/png`, `image/jpeg`, `audio/wav`, `application/pdf`.

## 5. Handler table

| Declared type | Action |
| --- | --- |
| `text/plain` | print the text. On invalid UTF-8, save the bytes and report the path |
| `image/png`, `image/jpeg` | save, then display |
| `audio/wav`, `audio/mpeg` | save, then play |
| anything else, or empty | save and report the path |
| declared type disagrees with the bytes | save and report the path. Do not render |

The function that writes the file derives its own safe filename. It does not trust the name it was given, even after the reader validated it. The function that writes is the function that must be safe.

## 6. Capacity

Capacity if a caller adds the recorded optional seal on top of the library's encryption, with empty metadata and packet start at the reserved 2,048-unit RSA-2048 bootstrap span. This is measured from the reserved span, not unit 0. The notebook no longer demonstrates this layer; decision 16 records its removal. The total hypothetical overhead is per carrier: current record overhead (`93 + 2W`) + 16-byte library GCM tag + 256-byte RSA-PSS signature + 268-byte caller-side seal prefix + 16-byte caller-side seal tag, giving 655 bytes for Banana (W=3) and 653 bytes for the WAV (W=2). A later start or nonempty metadata reduces these values.

| `k` | Banana PNG, 6,021,120 units | Demonstration WAV, 32,000 samples |
| ---: | ---: | ---: |
| 1 | 751,729 | 3,091 |
| 2 | 1,504,113 | 6,835 |
| 3 | 2,256,497 | 10,579 |
| 8 | 6,018,417 | 29,299 |

Use the capacity helpers with the actual start and record overhead when accepting a user payload. These figures are hypothetical caller-side sealing overhead, not a new protocol overhead; the seal was removed from the Stage 5 demonstration.

The image carrier holds a small image or a short audio clip at `k=1`. The demonstration audio carrier holds text only. That limit comes from the short 8-bit mono tone the notebook generates, not from the design. Capacity grows in proportion to the sample count, so a longer cover removes the difference.

For an audio cover, one carrier unit is one PCM sample, not one byte. See [Carrier units](INTEGRITY-DESIGN.md#carrier-units). Therefore a multi-byte cover holds `1 / sample_width` of what its file size suggests: a 16-bit cover holds half, a 24-bit cover a third, and a 32-bit cover a quarter. Longer audio buys capacity; deeper samples do not.

## 7. Limitations

- The type declaration protects an honest receiver from a mistake. It does not protect anyone from a sender who signs a hostile file. Software that renders the payload must still validate the file itself.
- Compression must happen before encryption, because encrypted bytes do not compress. Compression before encryption leaks information about the plaintext through the ciphertext length. Nothing in this design lets an attacker inject chosen data into the plaintext, so the risk is theoretical here, but it is real in designs that do.
- The header describes one file. Several files need an archive as the body, with `mime` set to the archive type. The header needs no change for that.
- The demonstration sends the message content as a placeholder string. The team still chooses the message it demonstrates.
