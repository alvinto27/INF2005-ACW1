# Work Not Built

This record lists work that still needs a team decision, demonstration, or implementation. Current protocol rules belong in [Current Protocol](CURRENT-PROTOCOL.md). Current media conversion rules belong in [Carrier and Payload Flow](CARRIER-AND-PAYLOAD-FLOW.md). Current web behavior belongs in [Web Application Guide](WEB-APPLICATION-GUIDE.md).

## Built now

- The library and Flask application use protocol version 3. Current carrier formats and source-conversion rules are in [Current Protocol](CURRENT-PROTOCOL.md), [Carrier and Payload Flow](CARRIER-AND-PAYLOAD-FLOW.md), and [Video Carrier Design](VIDEO-CARRIER-DESIGN.md).
- The notebook demonstrates the sender and receiver flow. The Flask request, response, and payload-preview behavior is in the [Web Application Guide](WEB-APPLICATION-GUIDE.md).
- Pillow is used only by tests and the demonstration notebook; the application uses PyAV for media I/O.

## Not built or not assembled

### Web source limits

- Refused source formats include JPEG XL, HEIC/HEIF, JPEG 2000, PPM, TGA, EXR, AIFF, WMA, audio-only Matroska/WebM, and all other formats outside the fixed image, audio, and video allowlist. AVIF uses the `avif`/`avis` major or compatible ISO-BMFF brand; an AVIF compatible brand is accepted even when `mif1` is the major brand.
- There is no colour-managed CMYK-to-RGB conversion. CMYK sources are refused because a CMYK ICC profile is not valid on an RGB PNG, and PyAV does not provide the approved colour-managed conversion path.
- The web source-format label is informational. The protocol does not authenticate the original compressed source file, its source metadata, or its encoder settings. It authenticates the canonical carrier data and signed record. See the [authenticity boundary](CURRENT-PROTOCOL.md#hash-rule-and-carrier-interpretation).

### Demonstration and assessment work

- The team must show both image and audio workflows live, display or play recovered payloads, and explain why receiver-private-key verification replaces the old shared-secret and original-cover inputs.
- The notebook simulates a file moving from Party A to Party B through separate folders. Party A uses its sender private key and B's receiver public key; Party B verifies the copied image and audio files using B's private key and A's public key. The live email transfer remains a demo-day task.
- Each member must explain their own technical contribution and answer questions about it. This individual criterion remains each member's responsibility.
- The team must choose and explain an innovation for FR13. Receiver-gated location confidentiality and encrypted typed payloads are available, but the team must choose the innovation it will present.
- The team must prepare an honest reflection on technical limits, ethics, originality, and AI use. The team must write and sign this reflection.
- The submission package still needs the required source code, sample files, test evidence, declaration of originality, and agreed contribution and distribution statement. The team must choose whether it will submit screenshots, logs, output files, or a combination.
- The demonstration must stay within the assignment time limit and give every member speaking or demonstration time.

### Repository integration

The GUI redesign commit `3e17ec3` is an ancestor of `main`, merged by PR #11 (`3eb9464`).

## Known limits

See [Current Protocol](CURRENT-PROTOCOL.md#limits-and-compatibility) for authenticity limits and [Carrier and Payload Flow](CARRIER-AND-PAYLOAD-FLOW.md#source-conversion) for source-conversion limits. Do not use old file-size or detectability figures; measure again before presenting such a claim.
