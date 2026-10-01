# Known Limitations

This guide helps teammates and markers understand which web inputs are refused and where protocol authenticity has limits. [Protocol](protocol.md) explains the version-3 rules, and [Carrier and Payload Flow](carrier-and-payload-flow.md) covers source conversion.

## Web source limits

- Refused source formats include JPEG XL, HEIC/HEIF, JPEG 2000, PPM, TGA, EXR, AIFF, WMA, audio-only Matroska/WebM, and all other formats outside the fixed image, audio, and video allowlist. AVIF uses the `avif`/`avis` major or compatible ISO-BMFF brand; an AVIF compatible brand is accepted even when `mif1` is the major brand.
- There is no colour-managed CMYK-to-RGB conversion. CMYK sources are refused because a CMYK ICC profile is not valid on an RGB PNG, and PyAV does not provide a colour-managed conversion path.
- The web source-format label is informational. The protocol does not authenticate the original compressed source file, its source metadata, or its encoder settings. It authenticates the canonical carrier data and signed record. See the [authenticity boundary](protocol.md#hash-rule-and-carrier-interpretation).

## Known limits

[Protocol](protocol.md#limits-and-compatibility) describes the authenticity limits, while [Carrier and Payload Flow](carrier-and-payload-flow.md#source-conversion) explains source-conversion limits. Older file-size and detectability measurements may no longer apply, so measure them again before using them in a presentation.
