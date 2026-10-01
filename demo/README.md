# Demonstration files

This folder holds the files from our demonstration, so that you can check each result yourself. They are supplied as a separate ZIP; extract its contents here.

## Layout

- Each demonstration case has its own folder, containing the original cover, the protected (stego) output, any tampered copy, and screenshots of the verdicts.
- The RSA keys are in `Keys/`. We generated them only for this assignment demonstration, so they must never be used for real data.

## Reproduce a verdict

1. Start the application with `python run.py` (see the [README](../README.md#quick-start) for setup).
2. Open the Verify page at `http://127.0.0.1:5000/verify`.
3. Upload the stego file, the sender public key, and the receiver private key.
4. An unchanged stego file should return `Authentic`. A changed file should return one of the failure verdicts listed in [Protocol — Verification verdicts](../docs/protocol.md#verification-verdicts).

You do not need the original cover to verify; it is included only so you can compare the files.
