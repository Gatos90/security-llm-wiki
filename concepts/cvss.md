---
title: CVSS
type: concept
status: draft
updated: 2026-05-05
tags:
  - cvss
  - severity
---

# CVSS

The Common Vulnerability Scoring System is a public framework for describing technical severity. CVSS is useful for consistent triage, but it is not the same as real-world risk.

Useful handling rules:

- Preserve the public vector string and score when available.
- Track the version, such as CVSS v3.1 or CVSS v4.0.
- Explain any severity label as source-provided, derived, or unknown.
- Avoid converting CVSS directly into patch priority without considering exploitability, exposure, asset criticality, and available mitigations.

Related: [[concepts/exploitability]], [[concepts/epss]]

