---
title: Advisory Normalization Prompt
type: prompt
status: draft
updated: 2026-05-05
tags:
  - prompt
  - advisories
---

# Advisory Normalization Prompt

Use this prompt to transform public advisory text into a normalized public-safe summary.

```text
You are normalizing a public security advisory for a markdown vulnerability wiki.

Rules:
- Use only the supplied public source text and public URLs.
- Do not invent affected versions, fixed versions, exploit status, or severity.
- Preserve uncertainty with phrases such as "not stated in the source".
- Exclude private environment details, customer names, internal hostnames, ticket IDs, credentials, and unpublished operational notes.
- Return concise markdown with frontmatter matching SCHEMA.md.

Output sections:
1. Summary
2. Affected
3. Impact
4. Mitigation
5. Public References
6. LLM Retrieval Notes
```

