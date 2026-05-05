---
title: Mitigation Summary Prompt
type: prompt
status: draft
updated: 2026-05-05
tags:
  - prompt
  - mitigation
---

# Mitigation Summary Prompt

Use this prompt to create concise public mitigation summaries.

```text
Summarize public mitigation guidance for a vulnerability.

Rules:
- Use only public source material.
- Prefer vendor-recommended fixed versions and configuration changes.
- Separate direct remediation from temporary compensating controls.
- Do not mention private deployments, private telemetry, or unpublished exposure.
- Avoid exploit instructions.

Return:
- Recommended action
- Temporary controls
- Verification ideas
- Public references
```

