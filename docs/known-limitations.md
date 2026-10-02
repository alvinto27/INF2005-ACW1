# Known limitations

This page collects what StegoVerify does not do, so that a reader can judge its claims fairly. It is a summary: the [protocol guide](protocol.md#limits-and-compatibility) gives the full authenticity limits, and [carrier and payload flow](carrier-and-payload-flow.md#source-conversion) gives the full source-conversion rules.

## What a verdict does not prove

- **Overwritten cover bits are gone.** Embedding replaces the chosen low bits, and they cannot be recovered or authenticated. With `k=8` across the whole carrier, the carrier bytes themselves give no integrity evidence; only the fixed bytes (such as RGBA alpha and the high bytes of multi-byte samples) are still checked.
- **Metadata is not covered.** The media hash covers decoded media content, not container metadata. PNG text chunks, WAV `LIST` chunks, Matroska tags, colour tags, and similar data can change without changing the verdict, so they should not be treated as evidence.
- **The original source is not covered.** When a JPEG, MP3, MP4, or other compressed file is converted before embedding, the protocol authenticates the converted, lossless carrier and the signed record. It does not authenticate the original compressed file, its metadata, or its encoder settings. The source-format label in the web app is for information only. See [hash rule and carrier interpretation](protocol.md#hash-rule-and-carrier-interpretation).
- **A key is not a person.** A valid signature proves which RSA key signed the record. The receiver must trust the sender's public key through some other channel; there is no key management, trust store, or PKI.
- **No replay protection.** Timestamps and nonces alone do not stop someone from re-sending an old, valid file.
- **One verdict for two cases.** A wrong receiver key and a file with no payload both return `Payload Missing`, because without the right key the bootstrap cannot be told apart from ordinary cover bits.
- **Not a snapshot.** Verification reads the file more than once. If the file changes during verification, the verdict can mix two versions of it.

## Refused source formats

- Only a fixed list of image, audio, and video formats is accepted (see the [README](../README.md#encode)). JPEG XL, HEIC/HEIF, JPEG 2000, PPM, TGA, EXR, AIFF, WMA, audio-only Matroska/WebM, and every other format outside that list are refused. AVIF is recognised by an `avif` or `avis` major or compatible ISO-BMFF brand, so an AVIF file whose major brand is `mif1` is still accepted.
- CMYK images are refused. A CMYK ICC profile is not valid on an RGB PNG, and PyAV has no colour-managed CMYK-to-RGB conversion, so we refuse these images rather than produce wrong colours.
- Animated images, floating-point or deeper-than-16-bit images, and converted audio with more than two channels are also refused.

## Compatibility

- Only protocol version 3 files can be verified. Files from versions 1 and 2, and from the older `STG1` implementation, are not accepted.
- Video files made with an early 30-byte media context during development do not verify with the current 32-byte context.
- On Windows, VLC's default Direct3D11 renderer can show stego `.mkv` videos with a yellow-green tint. The pixels are correct; switching VLC's video output to OpenGL shows the true colours. See [video output and limits](video-carrier.md#output-and-limits).

## Measurements

The time and memory figures in these guides come from one local machine at the time each feature was built. They show the scale involved, but they are not guarantees and may differ on other hardware or after later changes.
