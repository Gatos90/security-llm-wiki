---
title: Software Supply Chain
type: concept
status: draft
updated: 2026-05-05
tags:
  - supply-chain
  - dependencies
---

# Software Supply Chain

Software supply chain security covers the public components, build systems, package registries, container images, and distribution paths used to deliver software.

Public vulnerability records often identify affected dependencies, but practical remediation may require understanding:

- Direct and transitive dependencies.
- Lockfiles and package manager resolution behavior.
- Container base image inheritance.
- Build-time versus runtime usage.
- Maintainer advisories and release notes.

Related: [[mitigations/dependency-upgrades]], [[ecosystems/open-source-advisory-sources]]

