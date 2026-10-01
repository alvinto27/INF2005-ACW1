# Known Limitations

This record lists source-format and protocol limits. See [Protocol](protocol.md) for version 3 rules and [Carrier and Payload Flow](carrier-and-payload-flow.md) for source-conversion behavior.

## Web source limits

- Refused source formats include JPEG XL, HEIC/HEIF, JPEG 2000, PPM, TGA, EXR, AIFF, WMA, audio-only Matroska/WebM, and all other formats outside the fixed image, audio, and video allowlist. AVIF uses the `avif`/`avis` major or compatible ISO-BMFF brand; an AVIF compatible brand is accepted even when `mif1` is the major brand.
- There is no colour-managed CMYK-to-RGB conversion. CMYK sources are refused because a CMYK ICC profile is not valid on an RGB PNG, and PyAV does not provide the approved colour-managed conversion path.
- The web source-format label is informational. The protocol does not authenticate the original compressed source file, its source metadata, or its encoder settings. It authenticates the canonical carrier data and signed record. See the [authenticity boundary](protocol.md#hash-rule-and-carrier-interpretation).

## Known limits

See [Protocol](protocol.md#limits-and-compatibility) for authenticity limits and [Carrier and Payload Flow](carrier-and-payload-flow.md#source-conversion) for source-conversion limits. Do not use old file-size or detectability figures; measure again before presenting such a claim.
