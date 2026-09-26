# Work Not Built

This record lists work that still needs a team decision, demonstration, or implementation. Current protocol rules belong in [Current Protocol](CURRENT-PROTOCOL.md). Current media conversion rules belong in [Carrier and Payload Flow](CARRIER-AND-PAYLOAD-FLOW.md). Current web behavior belongs in [Web Application Guide](WEB-APPLICATION-GUIDE.md).

## Built now

- The Flask application uses protocol version 3. It accepts common still-image and audio sources for encode and writes canonical PNG or WAV. Strict PNG and PCM WAV inputs bypass conversion. The web app refuses real video tracks. Verification remains PNG/WAV-only.
- The source converter uses PyAV. It supports PNG, JPEG, WebP, AVIF, BMP, TIFF, and GIF images, with documented depth, frame, size, metadata, EXIF, ICC, and CMYK rules. It supports audio sources with exactly one mono or stereo stream. Lossless integer sample widths are kept. Lossy or floating-point audio becomes 16-bit PCM. The converter keeps all decoded samples, including codec delay or padding.
- The library and notebook support the optional video carrier. The Flask application does not accept video covers.
- The protocol encrypts and signs typed payload records. The web app returns authenticated payloads only after verification and MIME checks. Current response rules and previews are in the [Web Application Guide](WEB-APPLICATION-GUIDE.md).
- Pillow is not used by the application. It is used only by tests and the demonstration notebook.

## Not built or not assembled

### Web source limits

- The web application has no video carrier support. Real video covers are refused. Audio streams inside sources with a real video track are also refused by the web app, though the library audio converter can select audio and ignore video streams.
- JPEG XL and HEIC/HEIF source conversion are not supported.
- There is no colour-managed CMYK-to-RGB conversion. CMYK sources are refused because a CMYK ICC profile is not valid on an RGB PNG, and PyAV does not provide the approved colour-managed conversion path.
- The web source-format label is informational. The protocol does not authenticate the original compressed source file, its source metadata, or its encoder settings. It authenticates the canonical carrier data and signed record. See the [authenticity boundary](CURRENT-PROTOCOL.md#hash-rule-and-carrier-interpretation).

### Demonstration and assessment work

- The team must show both image and audio workflows live, display or play recovered payloads, and explain why receiver-private-key verification replaces the old shared-secret and original-cover inputs.
- The demonstration must show a file moving from party A to party B, for example by email. The notebook does not simulate this transfer.
- Each member must explain their own technical contribution and answer questions about it. This individual criterion remains each member's responsibility.
- The team must choose and explain an innovation for FR13. Receiver-gated location confidentiality and encrypted typed payloads are available, but the team must choose the innovation it will present.
- The team must prepare an honest reflection on technical limits, ethics, originality, and AI use. The team must write and sign this reflection.
- The submission package still needs the required source code, sample files, test evidence, declaration of originality, and agreed contribution and distribution statement. The team must choose whether it will submit screenshots, logs, output files, or a combination.
- The demonstration must stay within the assignment time limit and give every member speaking or demonstration time.

### Repository integration

The `yx` branch has not been merged into `main`. The team must agree on the merge and complete it separately. Do not treat this migration record as a merge decision.

## Known limits

Authenticity does not cover overwritten carrier LSBs, PNG ancillary data, WAV data outside declared PCM samples, the original compressed source file, or every video container field. It depends on the sender public key supplied for verification. Fully transparent RGBA pixel colours can change without changing the displayed image. A strict RGB PNG with a `tRNS` colour key is refused by the direct PNG adapter; the web source converter accepts it by turning the key into RGBA alpha. See [Current Protocol](CURRENT-PROTOCOL.md#limits-and-compatibility) for the full limits.

No file-size comparison for `samples/Banana.png` is recorded here. Do not use old figures from this record. Measure again before presenting a file-size or detectability claim.
