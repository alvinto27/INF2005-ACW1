---
name: inf2005-acw1
description: Masked-media LSB steganography for PNG and WAV carriers.
---

# INF2005-ACW1

This repository provides a signed LSB steganography protocol for strict RGB PNG and uncompressed PCM WAV carriers. Read the [Agent Navigation Map](AGENT_docs/AGENT_MAP.md) and [documentation index](AGENT_docs/README.md) before changing files.

## Read first

1. [Agent Navigation Map](AGENT_docs/AGENT_MAP.md) — repository structure and map chain.
2. [Documentation index](AGENT_docs/README.md) — durable records and current repository documentation.
3. [README](README.md) — setup and the masked-media integrity invariant.

## Commands

```sh
python -m pip install -r requirements.txt
# Optional: install only when you need to run the demonstration notebook.
python -m pip install -r requirements-notebook.txt
python -m unittest -v
python3 scripts/check-docs.py
bash scripts/install-hooks.sh
```

## State

- This is a standalone Python module repository with no package build configuration or CI workflow.
- The `stego/` package requires Python 3.10+ and uses `cryptography`, NumPy, and Pillow.
- `test_stego.py` is the unit-test entry point.
- This independent repository is a tracked submodule in the `School-Repos` checkout.
- Work is initialized on the local `yx` branch. Do not merge it into `main` unless the repository owner requests it.

## Conventions

- Keep the shared protocol media-neutral and use the fixed PNG and WAV adapters for file I/O.
- Preserve the documented packet format and verification verdicts when changing protocol behavior.
- Keep runtime and test dependencies in `requirements.txt`, optional notebook dependencies in `requirements-notebook.txt`, and tests in `test_stego.py` unless the repository adopts a different layout.
- Store each durable record—such as an architecture note, plan, runbook, status record, release note, or ADR—in its own aptly named file under `AGENT_docs/`, and list it in `AGENT_docs/README.md`.
- `git commit --no-verify` intentionally bypasses the documentation hook when necessary.

## Map freshness

- Update `AGENT_docs/AGENT_MAP.md` in the same commit as any change that affects paths, entry points, documentation locations, or repository boundaries it describes.
- Before committing documentation or map changes, verify every map path and link. Run `python3 scripts/check-docs.py`; it checks mechanical link and anchor validity, but cannot judge whether a map description is semantically current.
- Run `bash scripts/install-hooks.sh` after a fresh clone and after adding a repository boundary that needs the shared hook.
