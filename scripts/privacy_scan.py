#!/usr/bin/env python3
"""Fail on obvious private or internal content before public publishing."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


TEXT_EXTENSIONS = {
    ".md",
    ".txt",
    ".json",
    ".jsonl",
    ".yaml",
    ".yml",
    ".py",
}

SKIP_DIRS = {
    ".git",
    "__pycache__",
    ".pytest_cache",
    ".venv",
    "venv",
}

SKIP_FILES = {
    "scripts/privacy_scan.py",
}


def _brand_pattern() -> str:
    return "".join(["Tele", "kom"])


RULES: list[tuple[str, re.Pattern[str]]] = [
    ("blocked organization marker", re.compile(rf"\b{_brand_pattern()}\b", re.IGNORECASE)),
    # Block Jira-like private ticket keys but allow public vulnerability identifiers such as CVE-2026-1234.
    ("jira-style ticket key", re.compile(r"\b(?!(?:CVE|CWE)-)[A-Z][A-Z0-9]{1,9}-\d{1,7}\b")),
    (
        "internal or private URL",
        re.compile(
            r"(?i)\b(?:"
            r"https?://[^\s)>\"]*(?:corp|internal|intranet|lan|local|localhost|private|"
            r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
            r"172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|"
            r"192\.168\.\d{1,3}\.\d{1,3})[^\s)>\"]*"
            r"|(?:[\w-]+\.)+(?:corp|internal|intranet|lan|local|private)(?::\d+)?(?:/[^\s)>\"]*)?"
            r"|localhost(?::\d+)?(?:/[^\s)>\"]*)?"
            r"|10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
            r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
            r"|192\.168\.\d{1,3}\.\d{1,3}"
            r")\b"
        ),
    ),
    ("aws access key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    (
        "generic secret assignment",
        re.compile(
            r"(?i)\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|secret|password|passwd|client[_-]?secret)"
            r"\s*[:=]\s*['\"]?[^'\"\s]{8,}"
        ),
    ),
    (
        "bearer token",
        re.compile(r"(?i)\bauthorization\s*[:=]\s*bearer\s+[a-z0-9._~+/\-]{12,}"),
    ),
    (
        "private key block",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    ),
    ("github token", re.compile(r"\bgh[opsu]_[A-Za-z0-9_]{20,}\b")),
    ("slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
]


def iter_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for path in root.rglob("*"):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.is_file() and path.relative_to(root).as_posix() in SKIP_FILES:
            continue
        if path.is_file() and path.suffix.lower() in TEXT_EXTENSIONS:
            files.append(path)
    return sorted(files)


def scan_file(path: Path, root: Path) -> list[str]:
    rel = path.relative_to(root)
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return [f"{rel}: cannot decode as UTF-8"]

    findings: list[str] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        for name, pattern in RULES:
            if pattern.search(line):
                findings.append(f"{rel}:{line_no}: {name}")
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description="Scan wiki text for obvious private/internal leakage.")
    parser.add_argument("root", nargs="?", default=".", help="Repository root to scan.")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    if not root.exists():
        print(f"error: root does not exist: {root}", file=sys.stderr)
        return 2

    findings: list[str] = []
    for path in iter_files(root):
        findings.extend(scan_file(path, root))

    if findings:
        print("privacy scan failed:")
        for finding in findings:
            print(f"- {finding}")
        return 1

    print("privacy scan passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
