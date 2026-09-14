# Payload Envelope Design

The protocol carries `user_payload` as opaque bytes. It does not encrypt them, and it does not describe them. This record holds the design that the caller puts inside those bytes: a sealed envelope for confidentiality, and a content header that declares what the bytes are.

Both layers are caller-side. The `stego` package does not change for either one. This follows the byte-only payload decision in [Masked Media Integrity Design](INTEGRITY-DESIGN.md).

**The encryption layer does not survive protocol version 2.** That version encrypts the whole payload record inside the library, unconditionally, so the caller-side seal described below becomes encryption inside encryption. The seal and its notebook demonstration are removed when version 2 lands; see decision 16 in the [Location Confidentiality Plan](LOCATION-CONFIDENTIALITY-PLAN.md#11-decisions).

**The content-type header is unaffected.** Version 2 encrypts the record; it still does not describe the bytes inside `user_payload`, so that layer stays caller-side and stays necessary.

The working demonstration is in the Confidentiality payload and Typed encrypted payloads sections of the [demonstration notebook](../notebooks/FR1-12%20Prototype.ipynb).

## 1. Layering

```text
user_payload
└─ sealed blob          wrapped key · nonce · ciphertext with tag
   └─ content header    version · mime · name        (plaintext, inside the seal)
      └─ body           the file bytes
```

The content header is inside the seal. Therefore an observer who finds the packet learns the payload length, but not the file type and not the filename.

The header is never in `metadata`. `metadata` is readable to anyone who finds the packet.

## 2. Sealed blob

A random AES-256-GCM key encrypts the content header and the body together. RSA-OAEP with SHA-256 wraps that key with the receiver's public key.

| Field | Size | Notes |
| --- | --- | --- |
| Wrapped AES key | 256 bytes | RSA-2048, OAEP, SHA-256, MGF1-SHA-256, no label |
| Nonce | 12 bytes | fresh random value for every payload |
| Ciphertext with tag | remainder | 16-byte GCM tag included |

The fixed prefix is 268 bytes.

Hybrid encryption is required, not preferred. RSA-2048 OAEP with SHA-256 can encrypt at most 190 bytes directly, which is smaller than most payloads.

### What stays readable, and why

Only the content header and the body are encrypted. These payload fields stay in the clear:

| Field | Reason |
| --- | --- |
| `media_id`, `timestamp`, `nonce` | brief [FR3](../docs/INF2005-ACW1-spec_v5-f2f.md#6-functional-requirements) requires them in the payload |
| `media_hash` | brief [FR9](../docs/INF2005-ACW1-spec_v5-f2f.md#6-functional-requirements) compares it before decryption. If it were encrypted, verification would need a private key |
| `metadata` | the team defines this field for its own use |

The claim above about FR9 ordering is withdrawn: the brief requires a hash comparison, not a plaintext hash before decryption. See [Location Confidentiality Plan, section 3.5](LOCATION-CONFIDENTIALITY-PLAN.md#35-the-whole-payload-record-is-encrypted). These fields remain readable in the current intermediate format, not because the brief requires that exposure.

Stage 4b verification needs the stego file, the sender's public key, and separately supplied start unit, LSB count, and complete serialised record length. The signature and the media hash are checked before caller-side decryption is attempted.

### Key handling in the demonstration

The receiver's private key is written to a password-protected PEM file, then loaded again in the receiver phase. The receiver verifies with a public key loaded from a PEM path, not with a live sender object. In stage 4b, the demonstration also retains the three geometry values as a clearly labelled stand-in for a separate transfer. The geometry is not recovered from the file, and this intermediate state does not claim location confidentiality.

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

Stage 4b space for sealed plaintext (content header plus body), at start unit 0 with empty metadata. Deduct 256 signature bytes, 101 record bytes, the 268-byte seal prefix, and the 16-byte GCM tag: 641 bytes in total. There is no packet header. A later start or nonempty metadata reduces these values.

| `k` | Banana PNG, 1280x1568 | Demonstration WAV, 32,000 samples |
| ---: | ---: | ---: |
| 1 | 751,999 | 3,359 |
| 2 | 1,504,639 | 7,359 |
| 3 | 2,257,279 | 11,359 |
| 8 | 6,020,479 | 31,359 |

The old table understated the fixed overhead by one byte. Removing the 23-byte packet header and correcting that count gives a 22-byte increase over the old published values. Use the capacity helpers with the actual start and record overhead when accepting a user payload.

The image carrier holds a small image or a short audio clip at `k=1`. The demonstration audio carrier holds text only. That limit comes from the short 8-bit mono tone the notebook generates, not from the design. Capacity grows in proportion to the sample count, so a longer cover removes the difference.

For an audio cover, one carrier unit is one PCM sample, not one byte. See [Carrier units](INTEGRITY-DESIGN.md#carrier-units). Therefore a multi-byte cover holds `1 / sample_width` of what its file size suggests: a 16-bit cover holds half, a 24-bit cover a third, and a 32-bit cover a quarter. Longer audio buys capacity; deeper samples do not.

## 7. Limitations

- The type declaration protects an honest receiver from a mistake. It does not protect anyone from a sender who signs a hostile file. Software that renders the payload must still validate the file itself.
- Compression must happen before encryption, because encrypted bytes do not compress. Compression before encryption leaks information about the plaintext through the ciphertext length. Nothing in this design lets an attacker inject chosen data into the plaintext, so the risk is theoretical here, but it is real in designs that do.
- The header describes one file. Several files need an archive as the body, with `mime` set to the archive type. The header needs no change for that.
- The demonstration sends the message content as a placeholder string. The team still chooses the message it demonstrates.
