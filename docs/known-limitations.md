# Known limitations

This page lists what StegoVerify does not check or support. The [protocol guide](protocol.md#limits-and-compatibility) and [carrier and payload flow](carrier-and-payload-flow.md#source-conversion) give the full rules.

## What a verdict does not prove

| Limitation | Detail |
| --- | --- |
| Overwritten bits are lost | Embedded bits replace the cover's low bits, which cannot be recovered or checked. At `k` = 8 across the whole carrier, only the fixed bytes (such as alpha and the high bytes of 16-bit samples) are checked. |
| Metadata is not checked | PNG text, WAV `LIST` chunks, Matroska tags, colour tags, and similar data can change without changing the verdict. |
| The original source is not checked | When a JPEG, MP3, MP4, or other file is converted, the converted carrier is checked, not the original file or its metadata. The source format shown by the web app is for information only. |
| A key is not a person | A valid signature shows which RSA key signed the record. The receiver must trust the sender's public key by some other means. There is no key management, trust store, or PKI. |
| No replay protection | An old, valid file can be sent again and still verifies. |
| Two cases share one verdict | A wrong receiver key and a file with no payload both give `Payload Missing`. |
| Not a snapshot | Verification reads the file more than once. If the file changes during verification, the verdict can be based on two versions of it. |

## Refused source formats

| Format | Reason |
| --- | --- |
| JPEG XL, HEIC/HEIF, JPEG 2000, PPM, TGA, EXR, AIFF, WMA, audio-only Matroska/WebM, and any other format not in the [accepted list](../README.md#encode) | Not supported |
| CMYK images | A CMYK ICC profile is not valid on an RGB PNG, and PyAV has no colour-managed conversion |
| Animated images | Only still images are supported |
| Floating-point images, or images over 16 bits per component | Cannot be stored in PNG without loss |
| Converted audio with more than two channels | Only mono and stereo are supported |

AVIF files are recognised by an `avif` or `avis` brand, so an AVIF file whose major brand is `mif1` is still accepted.

## Compatibility

- Only protocol version 3 files can be verified. Version 1 and 2 files, and files from the removed `STG1` implementation, cannot.
- Video files made with an early 30-byte development context do not verify.
- On Windows, VLC's default Direct3D11 output can show stego `.mkv` files with a yellow-green tint. The file is correct. Set VLC's video output to OpenGL (see [video output and limits](video-carrier.md#output-and-limits)).

## Measurements

The time and memory figures in these guides come from one local machine. They may differ on other hardware.
