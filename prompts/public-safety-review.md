---
title: Public Safety Review Prompt
type: prompt
status: draft
updated: 2026-05-05
tags:
  - prompt
  - privacy
---

# Public Safety Review Prompt

Use this prompt before publishing generated or normalized content.

```text
Review the following content for public publication safety.

Flag and remove:
- Credentials, tokens, passwords, private keys, or session values.
- Internal hostnames, private URLs, intranet paths, or non-public dashboards.
- Private ticket IDs, unpublished incident details, or customer-specific exposure.
- Proprietary detection logic or private exploit observations.
- Personal data not already present in a public advisory source.

Allow:
- Public CVE, GHSA, OSV, CISA KEV, vendor, maintainer, package registry, and news references.
- Generic mitigation guidance.
- Publicly documented affected versions and fixed versions.

Return:
- "PUBLIC-SAFE" if no issue is found.
- Otherwise, a list of unsafe passages and a redacted replacement.
```

