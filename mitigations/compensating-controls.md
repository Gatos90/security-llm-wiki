---
title: Compensating Controls
type: mitigation
status: draft
updated: 2026-05-05
tags:
  - controls
  - remediation
---

# Compensating Controls

Compensating controls reduce risk when a direct patch or upgrade cannot be applied immediately. They should be treated as temporary unless public vendor guidance says otherwise.

Examples:

- Disable vulnerable features.
- Restrict network exposure.
- Require authentication for affected paths.
- Add input validation or filtering.
- Increase monitoring for public indicators of exploitation.
- Apply vendor-recommended configuration changes.

Related: [[mitigations/patch-management]], [[concepts/exploitability]]

