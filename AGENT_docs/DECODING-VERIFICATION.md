# Flask decoding and verification

## Architecture

`POST /decode` in `stego_web/routes.py` delegates to
`stego_web/services/current_protocol.py`. The adapter loads uploaded key bytes,
uses a request-scoped temporary file for the fixed `stego` media API, and calls
`verify_png` or `verify_wav` for protocol version 3. Cryptographic and integrity decisions stay in
`stego/core.py`; the Flask layer only validates multipart inputs and serializes
the result.

A readable version 2 bootstrap returns `Cannot Verify` with detail
`unsupported bootstrap version`. The decoder does not retry with version 2.

The browser controller is `stego_web/static/verify.js`. It inserts response text
with DOM `textContent`, handles JSON and transport failures, prevents duplicate
submits, and renders authenticated payload bytes only under the typed-payload
rules below.

## Request contract

`POST /decode` accepts four required multipart inputs:

- `stego`: received 8-bit RGB or RGBA PNG, or uncompressed PCM WAV;
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
8. Parse the encrypted payload record and recompute the version 3 full media SHA-256 hash over masked RGB units, RGBA alpha bytes, and all bytes of each declared PCM sample.
9. Return `Authentic` only when signature, authenticated decryption, payload
   structure, alignment padding, and full-media integrity all succeed.

The decoder reads one bootstrap and does not search the carrier for alternative
packets after failure. A pristine carrier and a wrong receiver key are deliberately
indistinguishable and both return `Payload Missing`.

## Result and payload handling

Results include the verdict and explanation, carrier type and size, protocol
version, recovered start unit and LSB count, signature and integrity state,
sender-key fingerprint, preserved-bit count/ratio, and authenticated record
fields. Unperformed checks are `null`, distinct from `false`.

An `Authentic` result additionally includes `payload_url` and parsed typed
metadata. The server stores the decrypted bytes as plaintext in
`instance/recovered-payloads`; delete them manually. The adapter recognizes PNG,
JPEG, WAV, MP3, and PDF magic. The browser fetches payload bytes by URL and
permits inline text/image/audio preview only when:

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
- PNG ancillary chunks and WAV chunks outside the declared PCM samples are not covered. Version 3 limitations for transparent pixel colours and RGB `tRNS` are listed in the [v3 hash record](PROTOCOL-V3-FULL-MEDIA-HASH.md#6-on-disk-effect-and-known-limits).
- Overwritten cover LSB values cannot be recovered or authenticated.
- `GET /payload/<id>` serves the recovered payload with a MIME allowlist,
  `nosniff`, a restrictive Content Security Policy, and `Cache-Control: no-store`.
  Non-previewable payloads use `application/octet-stream` and download attachment.
- The web adapter temporarily writes carrier uploads to an isolated directory
  because the fixed protocol media API accepts paths; that directory is deleted
  when the request ends. Recovered payloads are plaintext on disk, so production
  deployment still needs host-level storage controls.
- The active decoder does not import legacy `STG1` media. See
  [Protocol Compatibility](PROTOCOL-COMPATIBILITY.md).
