# Demonstration Files

The separate demonstration ZIP supplies these files. Extract its contents into this folder.

## Expected layout

- Use one folder for each demonstration case. Put the original cover, protected (stego) output, any tampered file, and verdict screenshots for that case in its folder.
- Put the RSA keys in `Keys/`. These keys must be made only for this assignment demonstration. Do not use them for real data.

## Reproduce a verdict

1. Start the application with `python run.py`.
2. Open the Verify page at `http://127.0.0.1:5000/verify`.
3. Upload the stego file, the sender public key, and the receiver private key.
4. Expect `Authentic` for an unchanged stego file. For a changed file, expect one of the failure verdicts listed in [Current Protocol — Verification verdicts](../AGENT_docs/CURRENT-PROTOCOL.md#verification-verdicts).

The original cover is not an input to verification.
