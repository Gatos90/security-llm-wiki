#!/usr/bin/env python3
"""Fail on obvious private or internal content before public publishing."""

from __future__ import annotations

import argparse
import ipaddress
import re
import sys
from pathlib import Path
from urllib.parse import urlparse


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
    # Block Jira-like private ticket keys but allow public vulnerability identifiers and known public/vendor IDs.
    ("jira-style ticket key", re.compile(r"\b(?!(?:CVE|CWE|ZBX|DIVD|FG-IR|BIP|ZSL)-)(?<!GHSA-)(?<!FG-)[A-Z][A-Z0-9]{1,9}-\d{1,7}\b")),
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

URL_PATTERN = re.compile(r"https?://[^\s)>\"]+", re.IGNORECASE)
BARE_PRIVATE_HOST_PATTERN = re.compile(
    r"(?i)\b(?:[\w-]+\.)+(?:corp|internal|intranet|lan|local|private)(?::\d+)?(?:/[^\s)>\"]*)?"
)
HOST_SUFFIXES = ("corp", "internal", "intranet", "lan", "local", "private")


def _host_is_private(host: str | None) -> bool:
    if not host:
        return False
    host = host.strip("[]").lower().rstrip(".")
    if host == "localhost" or any(host.endswith(f".{suffix}") for suffix in HOST_SUFFIXES):
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local


def line_has_internal_or_private_url(line: str) -> bool:
    """Detect private hosts without flagging public URLs whose path contains words like 'internal'."""
    for match in URL_PATTERN.finditer(line):
        if _host_is_private(urlparse(match.group(0)).hostname):
            return True
    for match in BARE_PRIVATE_HOST_PATTERN.finditer(line):
        host = match.group(0).split("/", 1)[0].split(":", 1)[0]
        if _host_is_private(host):
            return True
    return False


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
        if line_has_internal_or_private_url(line):
            findings.append(f"{rel}:{line_no}: internal or private URL")
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
