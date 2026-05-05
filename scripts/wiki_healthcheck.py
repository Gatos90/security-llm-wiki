#!/usr/bin/env python3
"""Check basic markdown wiki structure for LLM-friendly publishing."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path


REQUIRED_FRONTMATTER = {"title", "type", "status", "updated", "tags"}
REQUIRED_INDEX_LINKS = {
    "README",
    "SCHEMA",
    "log",
    "concepts/vulnerability-lifecycle",
    "concepts/cvss",
    "concepts/epss",
    "concepts/software-supply-chain",
    "concepts/exploitability",
    "ecosystems/open-source-advisory-sources",
    "mitigations/patch-management",
    "prompts/advisory-normalization",
}

WIKILINK_RE = re.compile(r"\[\[([^\]|#]+)(?:#[^\]|]+)?(?:\|[^\]]+)?\]\]")


def markdown_files(root: Path) -> list[Path]:
    return sorted(path for path in root.rglob("*.md") if ".git" not in path.parts)


def parse_frontmatter(text: str) -> dict[str, object] | None:
    if not text.startswith("---\n"):
        return None
    end = text.find("\n---\n", 4)
    if end == -1:
        return None
    block = text[4:end].splitlines()
    data: dict[str, object] = {}
    current_list_key: str | None = None
    for raw_line in block:
        line = raw_line.rstrip()
        if not line.strip():
            continue
        if line.startswith("  - ") and current_list_key:
            value = line[4:].strip()
            existing = data.setdefault(current_list_key, [])
            if isinstance(existing, list):
                existing.append(value)
            continue
        if ":" in line and not line.startswith(" "):
            key, value = line.split(":", 1)
            key = key.strip()
            value = value.strip()
            if value:
                data[key] = value
                current_list_key = None
            else:
                data[key] = []
                current_list_key = key
    return data


def page_targets(root: Path) -> set[str]:
    targets: set[str] = set()
    for path in markdown_files(root):
        rel = path.relative_to(root).with_suffix("").as_posix()
        targets.add(rel)
        if rel.endswith("/README"):
            targets.add(rel[: -len("/README")])
    return targets


def check_frontmatter(root: Path) -> list[str]:
    errors: list[str] = []
    for path in markdown_files(root):
        rel = path.relative_to(root)
        text = path.read_text(encoding="utf-8")
        frontmatter = parse_frontmatter(text)
        if frontmatter is None:
            errors.append(f"{rel}: missing YAML frontmatter")
            continue
        missing = REQUIRED_FRONTMATTER - set(frontmatter)
        if missing:
            errors.append(f"{rel}: missing frontmatter keys: {', '.join(sorted(missing))}")
        tags = frontmatter.get("tags")
        if not isinstance(tags, list) or not tags:
            errors.append(f"{rel}: tags must be a non-empty list")
    return errors


def check_wikilinks(root: Path) -> list[str]:
    errors: list[str] = []
    targets = page_targets(root)
    for path in markdown_files(root):
        rel = path.relative_to(root)
        text = path.read_text(encoding="utf-8")
        for match in WIKILINK_RE.finditer(text):
            target = match.group(1).strip().removesuffix(".md")
            if target not in targets:
                errors.append(f"{rel}: broken wikilink [[{target}]]")
    return errors


def check_index(root: Path) -> list[str]:
    index_path = root / "index.md"
    if not index_path.exists():
        return ["index.md: missing"]
    text = index_path.read_text(encoding="utf-8")
    missing = sorted(link for link in REQUIRED_INDEX_LINKS if f"[[{link}]]" not in text)
    return [f"index.md: missing rough index link [[{link}]]" for link in missing]


def check_data(root: Path) -> list[str]:
    errors: list[str] = []
    jsonl = root / "data" / "advisories.jsonl"
    index = root / "data" / "vulnerability-index.json"
    if not jsonl.exists():
        errors.append("data/advisories.jsonl: missing")
    else:
        for line_no, line in enumerate(jsonl.read_text(encoding="utf-8").splitlines(), start=1):
            if not line.strip():
                continue
            try:
                json.loads(line)
            except json.JSONDecodeError as exc:
                errors.append(f"data/advisories.jsonl:{line_no}: invalid JSON: {exc.msg}")
    if not index.exists():
        errors.append("data/vulnerability-index.json: missing")
    else:
        try:
            json.loads(index.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            errors.append(f"data/vulnerability-index.json: invalid JSON: {exc.msg}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description="Check markdown wiki health.")
    parser.add_argument("root", nargs="?", default=".", help="Repository root to check.")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    errors = []
    errors.extend(check_frontmatter(root))
    errors.extend(check_wikilinks(root))
    errors.extend(check_index(root))
    errors.extend(check_data(root))

    if errors:
        print("wiki healthcheck failed:")
        for error in errors:
            print(f"- {error}")
        return 1

    print("wiki healthcheck passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

