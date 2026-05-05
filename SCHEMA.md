---
title: Wiki Schema
type: schema
status: draft
updated: 2026-05-05
tags:
  - schema
  - metadata
---

# Wiki Schema

All markdown pages should begin with YAML frontmatter.

## Required Frontmatter

```yaml
---
title: Human Readable Title
type: concept|mitigation|ecosystem|advisory|package|report|prompt|index|schema|log
status: draft|reviewed|published|archived
updated: YYYY-MM-DD
tags:
  - example
---
```

## Advisory Page Shape

Recommended fields for normalized advisory pages:

- `id`: CVE, GHSA, OSV, or vendor advisory identifier.
- `aliases`: alternate public identifiers.
- `affected`: public package, product, platform, or image names.
- `ecosystem`: npm, Maven, PyPI, Docker, Linux, firmware, cloud, or other public ecosystem label.
- `severity`: public severity rating when available.
- `cvss`: public CVSS vector or score when available.
- `published`: public publication date.
- `modified`: last public update date.
- `sources`: public URLs only.
- `summary`: concise neutral description.
- `impact`: public impact summary.
- `mitigation`: public remediation guidance.
- `llm_notes`: short retrieval notes for model grounding.

## JSONL Advisory Record

`data/advisories.jsonl` uses one JSON object per line:

```json
{"id":"PLACEHOLDER-0000","source":"placeholder","ecosystem":"unknown","package":null,"summary":"Placeholder record for schema validation.","published":null,"modified":null,"references":[]}
```

## Link Conventions

- Use wikilinks for local markdown pages: `[[concepts/cvss]]`.
- Use public HTTPS URLs for external references.
- Do not link to internal systems or private dashboards.

