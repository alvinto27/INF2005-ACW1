#!/usr/bin/env python3
"""Check local Markdown links and GitHub-style heading anchors.

Scope: Markdown files at the repository root and recursively below docs/. The
checker deliberately excludes dependency, build, vendor, and Git directories;
this repository has no other documented component locations. It checks links
and anchors mechanically only. It does not validate prose, commands, or live
service state.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parent.parent
MARKDOWN_LINK = re.compile(r"(?<!!)\[[^\]]*\]\(([^)]+)\)")
HEADING = re.compile(r"^ {0,3}#{1,6}\s+(.*?)(?:\s+#+)?\s*$")


def markdown_files() -> list[Path]:
    files = list(ROOT.glob("*.md"))
    docs = ROOT / "docs"
    if docs.is_dir():
        files.extend(docs.rglob("*.md"))
    return sorted(path for path in files if path.is_file())


def slugify(heading: str) -> str:
    """Return the GitHub-style slug used for ordinary ATX headings."""
    text = re.sub(r"`([^`]*)`", r"\1", heading)
    text = re.sub(r"!?(?:\[[^\]]*\])\([^)]*\)", lambda match: match.group(0).split("][")[0].lstrip("!["), text)
    text = re.sub(r"[*_~]", "", text).strip().lower()
    text = re.sub(r"[^\w\- ]", "", text, flags=re.UNICODE)
    return re.sub(r"[ ]+", "-", text)


def anchors(path: Path) -> set[str]:
    found: set[str] = set()
    counts: dict[str, int] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        match = HEADING.match(line)
        if not match:
            continue
        base = slugify(match.group(1))
        count = counts.get(base, 0)
        counts[base] = count + 1
        found.add(base if count == 0 else f"{base}-{count}")
    return found


def destination(value: str) -> tuple[str, str]:
    value = value.strip()
    if value.startswith("<") and ">" in value:
        value = value[1:value.index(">")]
    else:
        value = value.split(maxsplit=1)[0] if value else value
    parsed = urlsplit(value)
    return unquote(parsed.path), unquote(parsed.fragment)


def main() -> int:
    files = markdown_files()
    anchor_cache: dict[Path, set[str]] = {}
    errors: list[str] = []
    link_count = 0

    for source in files:
        for match in MARKDOWN_LINK.finditer(source.read_text(encoding="utf-8")):
            target_text, fragment = destination(match.group(1))
            if target_text.startswith(("http://", "https://", "mailto:")):
                continue
            if not target_text and not fragment:
                continue
            link_count += 1
            target = source if not target_text else (source.parent / target_text).resolve()
            if not target.exists():
                errors.append(f"{source.relative_to(ROOT)}: missing link target: {match.group(1)}")
                continue
            if fragment and target.is_file() and target.suffix.lower() == ".md":
                available = anchor_cache.setdefault(target, anchors(target))
                if fragment not in available:
                    errors.append(f"{source.relative_to(ROOT)}: missing anchor '#{fragment}' in {target}")

    for error in errors:
        print(f"ERROR: {error}")
    print(f"Checked {len(files)} Markdown file(s) and {link_count} local link(s): {len(errors)} error(s).")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
