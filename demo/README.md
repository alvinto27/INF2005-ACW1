# Demonstration files

The demonstration files are supplied to markers as a separate ZIP, `Demos.zip`. They are not published in this repository because some of the cover media may be copyrighted. Git ignores everything in this folder except this README.

| ZIP detail | Value |
| --- | --- |
| File | `Demos.zip` |
| Size | 202,084,610 bytes (about 193 MiB) |
| Contents | 78 entries, all inside one top-level folder, `Demos/` |
| SHA-256 | `b86689dde3f5dfcd0f13e9f66ac1b03622647c51582c25c6dbd19d9686212184` |

To use the ZIP, put it in this folder and extract it here. The files then appear under `demo/Demos/`.

## Keys

`Demos/Keys/` holds RSA keys made only for this demonstration. Do not use them for real data.

| Files | Password | Used for |
| --- | --- | --- |
| `sender-public-key.pem`, `sender-private-key.pem`, `receiver-public-key.pem`, `receiver-private-key.pem` | None | Every stego file in the ZIP |
| `12345678-sender-public.pem`, `12345678-sender-private.pem`, `12345678-receiver-public.pem`, `12345678-receiver-private.pem` | `12345678` (private keys only; public keys have no password) | The wrong-key cases: E2 and E3 |

`Key Instructions.txt` lists the same keys and passwords.

## Successful cases

Each folder holds the cover (carrier), the payload, the stego file, and a screenshot of the `Authentic` result. Verify every stego file with `sender-public-key.pem` and `receiver-private-key.pem`, with no password.

| Folder | Cover | Payload | Stego file |
| --- | --- | --- | --- |
| `(A1) vid-vid-stego` | 4-second MP4 video | 3-minute MP4 video | `stego.mkv` |
| `(A2) mp3-written-stego` | MP3 audio | Text typed into the page | `stego.wav` |
| `(A3) custom-payload-stego/png-pdf-stego` | PNG image | PDF document | `stego.png` |
| `(A3) custom-payload-stego/wav-webp-stego` | WAV audio | WebP image | `stego.wav` |
| `(D1) png-written-stego` | PNG image | Text typed into the page | `stego.png` |
| `(D2) voice-text-stego` | WAV voice recording | Text file | `stego.wav` |
| `(D3) jpeg-png-stego` | JPEG image | PNG image | `stego.png` |
| `(D4) wav-mp3-stego` | WAV audio | MP3 audio | `stego.wav` |
| `(D5) spiderpng-wav-stego` | PNG image | WAV audio | `stego.png` |
| `(D6) wav-wav-stego` | WAV audio | WAV voice recording | `stego.wav` |

Lossy covers (MP3, JPEG, MP4) are converted to a lossless output (WAV, PNG, MKV) before embedding. See the [carrier and payload flow](../docs/carrier-and-payload-flow.md).

Some folders also hold an extra copy of the cover or payload under the original file name.

## Failure cases

E1 holds an edited stego file. E2, E3, and E4 hold screenshots only. Reproduce each one with the files from the folder shown.

| Folder | Stego file | Sender public key | Receiver private key | Result |
| --- | --- | --- | --- | --- |
| `(E1) Tampered` | `Tampered.png`, a stego PNG with the word "tampered" drawn on it | `sender-public-key.pem` | `receiver-private-key.pem` | `Tampered`: the signature is valid, but the full-media hash does not match |
| `(E2) Signature Invalid` | A `stego.wav` | `12345678-sender-public.pem` (wrong sender) | `receiver-private-key.pem` | `Signature Invalid` |
| `(E3) Cannot Verify` | A `stego.wav` | `sender-public-key.pem` | `12345678-receiver-private.pem`, password left empty | `Cannot Verify`: the private key is encrypted and needs a password |
| `(E4) Payload Missing` | `spiderman.png` from D5 (the original cover, not a stego file) | `sender-public-key.pem` | `receiver-private-key.pem` | `Payload Missing` |

`(E1) Tampered/original image.jpg` is the cover before embedding. The stego file before the edit is not in the ZIP.

## Reproduce a result

1. Start the application with `python run.py` (see the [README](../README.md#quick-start) for setup).
2. Open the verify page at `http://127.0.0.1:5000/verify`.
3. Upload the stego file, the sender public key, and the receiver private key from the tables above. Enter a password only for a `12345678-` private key.
4. Compare the result with the screenshot in the same folder.

The original cover is not needed for verification. The cover is included for comparison.
