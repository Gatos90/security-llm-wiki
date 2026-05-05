---
title: Dependency Upgrades
type: mitigation
status: draft
updated: 2026-05-05
tags:
  - dependencies
  - remediation
---

# Dependency Upgrades

Dependency upgrades remediate vulnerabilities in open-source packages by moving to a non-affected version or replacing the component.

Checklist:

- Identify direct and transitive affected packages.
- Confirm fixed versions from public advisory sources.
- Review changelogs and migration notes.
- Update manifests and lockfiles together.
- Rebuild artifacts that embed dependencies, including containers.
- Run tests that cover affected code paths.

Related: [[concepts/software-supply-chain]], [[ecosystems/npm-security]], [[ecosystems/maven-security]], [[ecosystems/pypi-security]]

