---
name: inf2005-acw1
description: Flask steganography application on the masked-media protocol version 3.
---

# INF2005-ACW1

This repository provides a localhost Flask steganography application on masked-media protocol version 3. Read the [Agent Navigation Map](AGENT_docs/AGENT_MAP.md), [documentation index](AGENT_docs/README.md), and [current protocol](AGENT_docs/CURRENT-PROTOCOL.md) before changing files.

## Read first

1. [Agent Navigation Map](AGENT_docs/AGENT_MAP.md) — repository structure and map chain.
2. [Documentation index](AGENT_docs/README.md) — durable records and current repository documentation.
3. [Current protocol](AGENT_docs/CURRENT-PROTOCOL.md) — active wire format, integrity checks, and compatibility rules.
4. [README](README.md) — setup, application flow, and integrity behavior.

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
- The active Flask routes use the `stego/` protocol through `stego_web/services/current_protocol.py`; the earlier `STG1` implementation and its web services have been removed.
- `test_stego.py` and `test_webapp.py` are the active test entry points.

## Conventions

- Keep the masked-media protocol media-neutral and use its fixed `stego/` PNG and WAV adapters for file I/O.
- Preserve protocol version 3 and its documented verification verdicts. The active Flask routes accept only protocol version 3; do not present older masked-media or `STG1` files as interoperable.
- Keep runtime and test dependencies in `requirements.txt`, optional notebook dependencies in `requirements-notebook.txt`, and tests in the existing two test modules unless the repository adopts a different layout.
- Annotate every function and method parameter and return type, including private helpers; use `-> None` when nothing is returned.
- Use plain built-in types and `|` unions, write `X | None` instead of `Optional`, and write `str | bytes | PathLike[str]` inline at each site rather than defining an alias. Annotate carrier arrays as `np.ndarray` without dtype or shape; let docstrings carry that detail, and do not import from `typing` unless there is no other way.
- Store each durable record—such as an architecture note, plan, runbook, status record, release note, or ADR—in its own aptly named file under `AGENT_docs/`, and list it in `AGENT_docs/README.md`. The `docs/` directory holds the supplied assignment specification and is not a place to add records.
- `git commit --no-verify` intentionally bypasses the documentation hook when necessary.

## Map freshness

- Update `AGENT_docs/AGENT_MAP.md` in the same commit as any change that affects paths, entry points, documentation locations, or repository boundaries it describes.
- Before committing documentation or map changes, verify every map path and link. Run `python3 scripts/check-docs.py`; it checks mechanical link and anchor validity, rejects local links that resolve outside this repository so the repository stays self-contained for anyone who clones it alone, but cannot judge whether a map description is semantically current.
- Run `bash scripts/install-hooks.sh` after a fresh clone and after adding a repository boundary that needs the shared hook.
