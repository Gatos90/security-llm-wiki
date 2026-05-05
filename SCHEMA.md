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

Canonical advisory pages live under:

- `advisories/cve/<CVE-ID>.md`
- `advisories/ghsa/<GHSA-ID>.md`
- `advisories/osv/<OSV-ID>.md`

Do not move CVE records under package, product, or version paths. Package pages are secondary entry points that link back to canonical advisory pages.

Recommended fields for normalized advisory pages:

- `id`: CVE, GHSA, OSV, or vendor advisory identifier.
- `aliases`: alternate public identifiers.
- `packages`: public package or product identities when stated or safely inferable.
- `purl`: Package URL when the stable package identity is inferable for npm, PyPI, Maven, Docker, or another supported package ecosystem.
- `affected`: public package, product, platform, or image names.
- `ecosystem`: npm, Maven, PyPI, Docker, Linux, firmware, cloud, or other public ecosystem label.
- `affected_ranges`: version ranges from public advisory data.
- `fixed_versions`: fixed versions from public advisory data.
- `severity`: public severity rating when available.
- `cvss`: public CVSS vector or score when available.
- `published`: public publication date.
- `modified`: last public update date.
- `sources`: public URLs only.
- `summary`: concise neutral description.
- `impact`: public impact summary.
- `mitigation`: public remediation guidance.
- `llm_notes`: short retrieval notes for model grounding.

`affected_ranges` and `fixed_versions` are data fields. They should not create package/version folder trees.

## Package Page Shape

Package and product pages live under `packages/<ecosystem>/<name>.md`. They are lookup pages for a public identity, not canonical vulnerability records.

Recommended fields:

- `ecosystem`: public ecosystem label such as `npm`, `pypi`, `maven`, `docker`, or `product`.
- `package`: public package or product name.
- `purl`: stable Package URL when inferable. Leave blank when the current public record only supports a product name.
- `aliases`: public advisory aliases associated with the package page.
- `advisories`: links to canonical advisory pages.

Use PURL as the stable package identity for package ecosystems. Keep display names and product names for human navigation.

## JSONL Advisory Record

`data/advisories.jsonl` uses one JSON object per line:

```json
{"id":"PLACEHOLDER-0000","source":"placeholder","ecosystem":"unknown","package":null,"summary":"Placeholder record for schema validation.","published":null,"modified":null,"references":[]}
```

Optional record fields include `aliases`, `packages`, `affected_ranges`, and `fixed_versions`.

## Machine-Readable Indexes

- `data/vulnerability-index.json`: advisory-oriented index for normalized records.
- `data/package-index.json`: package and product entry-point index. PURL is the stable identity when available.
- `data/alias-index.json`: alias resolver from public CVE, GHSA, OSV, and vendor identifiers to canonical advisory pages.

## Link Conventions

- Use wikilinks for local markdown pages: `[[concepts/cvss]]`.
- Use public HTTPS URLs for external references.
- Do not link to internal systems or private dashboards.
- Advisory pages should link to related package, ecosystem, concept, and mitigation pages when public data supports the relationship.
