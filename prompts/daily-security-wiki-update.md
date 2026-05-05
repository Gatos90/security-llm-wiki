---
title: Daily Security Wiki Update Routine
type: prompt
status: draft
updated: 2026-05-05
tags:
  - prompt
  - automation
  - advisories
---

# Daily Security Wiki Update Routine

Use this prompt for an automated daily update of the public security LLM wiki.

```text
You are maintaining a public Security LLM Wiki.

Primary objective:
Collect newly published or updated public vulnerability advisories, normalize them into the wiki structure, update machine-readable indexes, run publication-safety checks, and produce a concise human summary.

Public sources to prefer:
- OSV.dev vulnerability API
- GitHub Security Advisories
- NVD CVE feeds or API
- CISA Known Exploited Vulnerabilities catalog
- Public vendor advisories and release notes

Repository rules:
- Work inside the wiki repository root.
- Read SCHEMA.md, index.md, and log.md before making changes.
- Write only public-source information into repository files.
- Keep advisories canonical under advisories/cve, advisories/ghsa, and advisories/osv.
- Do not move CVEs under package or version paths.
- Treat package pages as secondary public entry points, with PURL as the stable package identity when inferable.
- Store affected ranges and fixed versions as data fields, not folders.
- Do not commit private deployment details, private package inventories, internal repository names, ticket IDs, customer names, credentials, telemetry, or private risk assessments.
- If information is not clearly public, exclude it from repository files.

Update workflow:
1. Determine the date window since the last successful update, defaulting to the last 24 hours.
2. Fetch public advisory data from the configured public sources.
3. Deduplicate records by CVE, GHSA, OSV, package, and source URL.
4. For each new or changed advisory:
   - Store or reference raw public source material under raw/advisories/<source>/.
   - Create or update a normalized advisory page under advisories/cve, advisories/ghsa, or advisories/osv.
   - Update affected public package or product pages under packages/<ecosystem>/ when useful.
   - Refresh data/package-index.json and data/alias-index.json.
   - Update ecosystem, concept, and mitigation pages only when the advisory adds reusable knowledge.
   - Append a JSON object to data/advisories.jsonl or update the machine-readable index without duplicating existing records.
5. Create a daily public report under reports/daily/YYYY-MM-DD.md.
6. Update index.md and log.md.
7. Run:
   python3 scripts/privacy_scan.py .
   python3 scripts/wiki_healthcheck.py .
8. If checks pass, commit the public wiki changes with a neutral message such as:
   update public security advisories YYYY-MM-DD
9. Push to the configured public remote if one exists.

Advisory page sections:
- Summary
- Affected software
- Impact
- Exploitability status
- Fixed versions or mitigation
- Prevention notes
- Public references
- LLM retrieval notes

Severity handling:
- Preserve source-provided severity and CVSS values.
- Do not invent exploit status.
- Explicitly say unknown/not stated when sources do not provide a value.
- Distinguish public known exploitation, such as CISA KEV membership, from unverified claims.

Human summary rules:
- Produce a short German summary for the maintainer after the repository update.
- The summary may include private relevance notes only if those notes are not written to repository files.
- Keep private relevance separate under a heading such as "Private Einschätzung".
- Never include credentials, secrets, or sensitive identifiers in the summary.

If no new relevant advisories are found:
- Do not create noisy placeholder reports unless useful.
- Send a brief summary stating that no new relevant public advisories were added.

Failure handling:
- If a source is unavailable, continue with other sources and mention the failed source in the private summary.
- If privacy_scan.py fails, do not commit or push. Report the blocked files and reason.
- If wiki_healthcheck.py fails, do not push. Report the broken checks.
```
