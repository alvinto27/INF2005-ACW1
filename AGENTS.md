---
name: inf2005-acw1
description: Python module for signing and verifying steganography payload metadata.
---

# INF2005-ACW1

This repository provides a byte-only signed payload protocol for a steganography application. Read the [Agent Navigation Map](docs/AGENT_MAP.md) and [documentation index](docs/README.md) before changing files.

## Read first

1. [Agent Navigation Map](docs/AGENT_MAP.md) — repository structure and map chain.
2. [Documentation index](docs/README.md) — durable records and current repository documentation.
3. [README](README.md) — setup, protocol behavior, and public API example.

## Commands

```sh
python -m pip install -r requirements.txt
python -m unittest -v
python3 scripts/check-docs.py
bash scripts/install-hooks.sh
```

## State

- This is a standalone Python module repository with no package build configuration or CI workflow.
- `payload_protocol.py` requires Python 3.10+ and uses `cryptography`.
- `test_payload_protocol.py` is the unit-test entry point.
- This independent repository is nested in the `School-Repos` checkout, but the parent does not track it as a submodule or gitlink.
- Work is initialized on the local `yx` branch. Do not merge it into `main` unless the repository owner requests it.

## Conventions

- Keep the payload protocol byte-only; do not add file I/O or steganography dependencies to it without an explicit requirement.
- Preserve the documented packet format and verification verdicts when changing protocol behavior.
- Keep dependencies in `requirements.txt` and tests in `test_payload_protocol.py` unless the repository adopts a different layout.
- Store each durable record—such as an architecture note, plan, runbook, status record, release note, or ADR—in its own aptly named file under `docs/`, and list it in `docs/README.md`.
- `git commit --no-verify` intentionally bypasses the documentation hook when necessary.

## Map freshness

- Update `docs/AGENT_MAP.md` in the same commit as any change that affects paths, entry points, documentation locations, or repository boundaries it describes.
- Before committing documentation or map changes, verify every map path and link. Run `python3 scripts/check-docs.py`; it checks mechanical link and anchor validity, but cannot judge whether a map description is semantically current.
- Run `bash scripts/install-hooks.sh` after a fresh clone and after adding a repository boundary that needs the shared hook.
