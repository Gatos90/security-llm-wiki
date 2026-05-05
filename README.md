---
title: Public Security LLM Wiki
type: guide
status: draft
updated: 2026-05-05
tags:
  - security
  - llm
  - wiki
---

# Public Security LLM Wiki

This repository is a public-safe markdown wiki for security vulnerability knowledge that can be indexed, searched, summarized, and retrieved by LLM and AI systems.

The wiki intentionally contains only public information. Do not add private incident details, internal hostnames, customer identifiers, unreleased advisory material, credentials, tokens, proprietary detections, or non-public communications.

## Goals

- Preserve public security knowledge in predictable markdown and JSON formats.
- Make advisory, package, ecosystem, concept, mitigation, and report content easy for automated tools to parse.
- Separate raw source captures from normalized pages.
- Provide privacy and quality checks before publication.

## Start Here

- [[index]]
- [[SCHEMA]]
- [[concepts/vulnerability-lifecycle]]
- [[mitigations/patch-management]]
- [[ecosystems/open-source-advisory-sources]]

## Safety Rule

When in doubt, leave it out. Prefer linking to a public source over copying sensitive operational context.

## Local Checks

```bash
python3 scripts/privacy_scan.py .
python3 scripts/wiki_healthcheck.py .
```

