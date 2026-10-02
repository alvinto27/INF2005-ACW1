# Demonstration files

This folder holds the files from our demonstration. They are supplied as a separate ZIP; extract its contents here.

## Layout

| Path | Contents |
| --- | --- |
| One folder per case | The original cover, the stego file, any tampered copy, and screenshots of the verdicts |
| `Keys/` | RSA keys made only for this demonstration. Do not use them for real data. |

## Reproduce a verdict

1. Start the application with `python run.py` (see the [README](../README.md#quick-start) for setup).
2. Open the Verify page at `http://127.0.0.1:5000/verify`.
3. Upload the stego file, the sender's public key, and the receiver's private key.
4. An unchanged stego file gives `Authentic`. A changed file gives one of the other [verdicts](../docs/protocol.md#verification-verdicts).

The original cover is not needed for verification. It is included for comparison.
