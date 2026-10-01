# Work Not Built

This record lists work that still needs a team decision, demonstration, or implementation. Current protocol rules belong in [Current Protocol](CURRENT-PROTOCOL.md). Current media conversion rules belong in [Carrier and Payload Flow](CARRIER-AND-PAYLOAD-FLOW.md). Current web behavior belongs in [Web Application Guide](WEB-APPLICATION-GUIDE.md).

## Built now

- The Flask application uses protocol version 3. It accepts still PNG, JPEG, WebP, AVIF, BMP, TIFF, and GIF images; WAV with `pcm_*`, MP3, AAC ADTS, M4A with AAC/ALAC, FLAC, and Ogg with Vorbis/Opus audio; and MP4/MOV, Matroska/WebM, or AVI video with one decodable video stream and up to one audio stream. Audio-only Matroska/WebM is refused. It writes canonical PNG, WAV, or FFV1/PCM Matroska. Strict PNG and PCM WAV inputs bypass conversion; strict PCM WAV carriers accept any positive channel count. Verification accepts PNG, WAV, and Matroska video carriers.
- The source converter uses PyAV. It supports the listed still images with documented depth, frame, size, metadata, EXIF, ICC, and CMYK rules, and converts accepted audio to canonical WAV. Converted audio has exactly one mono or stereo stream. Lossless 8-, 16-, 24-, and 32-bit samples are kept. Lossless depths below 16 bits become 16-bit PCM without loss; other lossless depths above 16 bits are refused. Lossy or floating-point audio becomes 16-bit PCM. The converter keeps all decoded samples, including codec delay or padding.
- The library, notebook, and Flask application support the optional video carrier.
- The protocol encrypts and signs typed payload records. The web app returns authenticated payloads only after verification and MIME checks. Current response rules and previews are in the [Web Application Guide](WEB-APPLICATION-GUIDE.md).
- Pillow is not used by the application. It is used only by tests and the demonstration notebook.

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

The GUI redesign is present on `yx` and `Alvin` at commit `3e17ec3` (`Redesign of GUI`). PR #10 (`c259441`) merged the earlier `yx` work into `main`, but `main` does not yet contain this GUI redesign. This status record does not make a merge decision.

## Known limits

Authenticity does not cover overwritten carrier LSBs, PNG ancillary data, WAV data outside declared PCM samples, the original compressed source file, or every video container field. It depends on the sender public key supplied for verification. Fully transparent RGBA pixel colours can change without changing the displayed image. A strict RGB PNG with a `tRNS` colour key is refused by the direct PNG adapter; the web source converter accepts it by turning the key into RGBA alpha. See [Current Protocol](CURRENT-PROTOCOL.md#limits-and-compatibility) for the full limits.

No file-size comparison for `samples/Banana.png` is recorded here. Do not use old figures from this record. Measure again before presenting a file-size or detectability claim.
