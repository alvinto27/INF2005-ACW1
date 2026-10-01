# Demonstration Files

The separate demonstration ZIP will contain the files teammates and markers need to review and reproduce the demonstration. Extract its contents into this folder; this guide explains the expected layout and how to repeat a verdict.

## Expected layout

- Give each demonstration case its own folder. Include the original cover, protected (stego) output, any tampered file, and screenshots of the verdicts.
- Keep the RSA keys in `Keys/`. Make these keys only for this assignment demonstration; never use them for real data.

## Reproduce a verdict

1. Start the application by running `python run.py`.
2. Open the Verify page at `http://127.0.0.1:5000/verify`.
3. Upload the stego file, the sender public key, and the receiver private key.
4. An unchanged stego file should return `Authentic`. A changed file should return one of the failure verdicts listed in [Protocol — Verification verdicts](../docs/protocol.md#verification-verdicts).

The original cover is not an input to verification.
