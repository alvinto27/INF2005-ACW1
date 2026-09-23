# Flask decoding and verification

## Architecture

`POST /decode` in `stego_web/routes.py` delegates to
`stego_web/services/current_protocol.py`. The adapter loads uploaded key bytes,
uses a request-scoped temporary file for the fixed `stego` media API, and calls
`verify_png` or `verify_wav`. Cryptographic and integrity decisions stay in
`stego/core.py`; the Flask layer only validates multipart inputs and serializes
the result.

The browser controller is `stego_web/static/verify.js`. It inserts response text
with DOM `textContent`, handles JSON and transport failures, prevents duplicate
submits, and renders authenticated payload bytes only under the typed-payload
rules below.

## Request contract

`POST /decode` accepts four required multipart inputs:

- `stego`: received strict RGB PNG or uncompressed PCM WAV;
- `sender_public_key`: trusted RSA-2048 public PEM;
- `receiver_private_key`: intended receiver's encrypted RSA-2048 private PEM; and
- `receiver_key_password`: password for that private key.

The protocol does not request media type, LSB count, start unit, record length,
shared location secret, or original cover. Media type is detected from content;
the RSA-OAEP bootstrap supplies geometry and AES session material.

Missing or invalid request fields use HTTP 400, an unreadable receiver bootstrap
uses the protocol's `Payload Missing` verdict with HTTP 422, oversized uploads
use HTTP 413, and processed verification outcomes use HTTP 200. Callers must
inspect the JSON verdict instead of treating HTTP success as authenticity.

## Verification order

1. Detect and strictly parse the carrier family.
2. Load the trusted sender public key and password-protected receiver private key.
3. Read the fixed one-LSB bootstrap span and open it with RSA-OAEP.
4. Validate the recovered version, LSB count, start unit, and ciphertext length.
5. Extract ciphertext and RSA-PSS signature from that exact layout.
6. Verify the signature over protocol version, media interpretation, geometry,
   and ciphertext before attempting record decryption.
7. Open AES-256-GCM using the recovered bootstrap fields as authenticated data.
8. Parse the encrypted payload record and recompute the masked-media SHA-256 hash.
9. Return `Authentic` only when signature, authenticated decryption, payload
   structure, alignment padding, and masked-media integrity all succeed.

The decoder reads one bootstrap and does not search the carrier for alternative
packets after failure. A pristine carrier and a wrong receiver key are deliberately
indistinguishable and both return `Payload Missing`.

## Result and payload handling

Results include the verdict and explanation, carrier type and size, protocol
version, recovered start unit and LSB count, signature and integrity state,
sender-key fingerprint, preserved-bit count/ratio, and authenticated record
fields. Unperformed checks are `null`, distinct from `false`.

An `Authentic` result additionally includes Base64-encoded raw user payload bytes
and parsed typed metadata. The adapter recognizes PNG, JPEG, WAV, MP3, and PDF
magic. The browser permits inline text/image/audio preview only when:

- metadata parses without duplicates or delimiter ambiguity;
- the signed MIME claim agrees with recognized payload bytes; and
- the MIME type is one of `text/plain`, `image/png`, `image/jpeg`, `audio/wav`,
  or `audio/mpeg`.

All authenticated payloads remain downloadable under a sanitized basename. A
MIME mismatch disables rendering but does not rewrite the cryptographic verdict:
it remains an authentic false claim made by the signing key.

## Tests and limitations

Run `python -m unittest -v`. `test_webapp.py` covers PNG messages, binary WAV
payloads, all LSB counts, geometry recovery, sender/receiver key separation,
preserved-bit tampering, MIME disagreement, required-input failures, key setup,
and request-size limits. `test_stego.py` contains the deeper protocol boundary
and negative-verdict tests.

- Authenticity is relative to the sender public key supplied by the receiver;
  there is no certificate directory or trust-on-first-use policy.
- A wrong receiver key and absent payload intentionally share one outcome.
- Container metadata outside decoded RGB channels or PCM samples is not covered.
- Overwritten cover LSB values cannot be recovered or authenticated.
- The web adapter temporarily writes uploads to an isolated directory because
  the fixed protocol media API accepts paths; that directory is deleted when the
  request ends, but production deployment still needs host-level storage controls.
- The active decoder does not import legacy `STG1` media. See
  [Protocol Compatibility](PROTOCOL-COMPATIBILITY.md).
