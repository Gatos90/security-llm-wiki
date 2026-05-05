#!/usr/bin/env python3
"""Fetch public vulnerability advisories and update the public Security LLM Wiki.

Uses only public sources and writes public-safe Markdown/JSONL content.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
USER_AGENT = "public-security-llm-wiki/0.1 (+https://github.com/)"
SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}
GHSA_RE = re.compile(r"GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}", re.IGNORECASE)


PACKAGE_HINTS = [
    {
        "needles": ("n8n", "n8n-io/n8n"),
        "ecosystem": "npm",
        "name": "n8n",
        "display": "n8n",
        "purl": "pkg:npm/n8n",
        "concepts": ["concepts/software-supply-chain"],
        "ecosystem_page": "ecosystems/npm-security",
    },
    {
        "needles": ("nginx-ui", "0xjacky/nginx-ui", "nginx ui"),
        "ecosystem": "product",
        "name": "nginx-ui",
        "display": "Nginx UI",
        "purl": None,
        "concepts": ["concepts/exploitability"],
        "ecosystem_page": "ecosystems/container-security",
    },
    {
        "needles": ("arelle", "arelle/arelle"),
        "ecosystem": "product",
        "name": "arelle",
        "display": "Arelle",
        "purl": None,
        "concepts": ["concepts/software-supply-chain"],
        "ecosystem_page": "ecosystems/pypi-security",
    },
    {
        "needles": ("openc3 cosmos", "openc3/cosmos"),
        "ecosystem": "product",
        "name": "openc3-cosmos",
        "display": "OpenC3 COSMOS",
        "purl": None,
        "concepts": ["concepts/software-supply-chain"],
        "ecosystem_page": "ecosystems/container-security",
    },
]


def http_json(url: str, timeout: int = 30) -> Any:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def slug(text: str) -> str:
    text = text.lower().strip()
    text = re.sub(r"[^a-z0-9._-]+", "-", text)
    return text.strip("-") or "unknown"


def dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if not value or value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


def extract_aliases(record: dict[str, Any]) -> list[str]:
    aliases: list[str] = []
    rid = record.get("id")
    if isinstance(rid, str) and rid:
        aliases.append(rid)
    for ref in record.get("references") or []:
        aliases.extend(match.upper() for match in GHSA_RE.findall(ref))
    aliases.extend(str(alias) for alias in record.get("aliases") or [] if alias)
    return dedupe(aliases)


def infer_packages(record: dict[str, Any]) -> list[dict[str, Any]]:
    text = " ".join(
        [
            str(record.get("package") or ""),
            str(record.get("summary") or ""),
            " ".join(str(ref) for ref in record.get("references") or []),
        ]
    ).lower()
    packages: list[dict[str, Any]] = []
    for hint in PACKAGE_HINTS:
        if any(needle in text for needle in hint["needles"]):
            packages.append(
                {
                    "ecosystem": hint["ecosystem"],
                    "name": hint["name"],
                    "display": hint["display"],
                    "purl": hint["purl"],
                    "path": f"packages/{hint['ecosystem']}/{slug(hint['name'])}",
                    "ecosystem_page": hint["ecosystem_page"],
                    "concepts": hint["concepts"],
                }
            )
    return packages


def package_path(package: dict[str, Any]) -> Path:
    return ROOT / f"{package['path']}.md"


def record_link(record: dict[str, Any]) -> str:
    rid = record["id"]
    if rid.startswith("CVE-"):
        return f"advisories/cve/{rid}"
    if rid.upper().startswith("GHSA-"):
        return f"advisories/ghsa/{slug(rid)}"
    return f"advisories/osv/{slug(rid)}"


def infer_fixed_versions(summary: str) -> list[str]:
    patterns = [
        r"patched in versions? ([^.]+(?:\.[0-9A-Za-z-]+)*(?:,\s*[0-9][0-9A-Za-z.-]*)*(?:,\s*and\s*[0-9][0-9A-Za-z.-]*)?)",
        r"patched in version ([0-9][0-9A-Za-z.-]*)",
    ]
    versions: list[str] = []
    for pattern in patterns:
        for match in re.findall(pattern, summary, flags=re.IGNORECASE):
            for version in re.split(r",|\band\b", match):
                version = version.strip().strip(".")
                if re.match(r"^[0-9][0-9A-Za-z.-]*$", version):
                    versions.append(version)
    return dedupe(versions)


def infer_affected_ranges(summary: str) -> list[str]:
    ranges: list[str] = []
    for match in re.findall(r"prior to versions? ([^.]+(?:\.[0-9A-Za-z-]+)*(?:,\s*[0-9][0-9A-Za-z.-]*)*(?:,\s*and\s*[0-9][0-9A-Za-z.-]*)?)", summary, flags=re.IGNORECASE):
        for version in re.split(r",|\band\b", match):
            version = version.strip().strip(".")
            if re.match(r"^[0-9][0-9A-Za-z.-]*$", version):
                ranges.append(f"< {version}")
    before = re.search(r"\bbefore ([0-9][0-9A-Za-z.-]*)", summary, flags=re.IGNORECASE)
    if before:
        ranges.append(f"< {before.group(1).strip('.')}")
    return dedupe(ranges)


def frontmatter(title: str, page_type: str, tags: list[str], updated: str, extra: dict[str, Any] | None = None) -> str:
    lines = ["---", f"title: {title}", f"type: {page_type}", "status: draft", f"updated: {updated}"]
    if extra:
        for key, value in extra.items():
            if value is None:
                continue
            if isinstance(value, list):
                lines.append(f"{key}:")
                for item in value:
                    lines.append(f"  - {item}")
            else:
                safe = str(value).replace("\n", " ")
                lines.append(f"{key}: {safe}")
    lines.append("tags:")
    for tag in tags:
        lines.append(f"  - {tag}")
    lines.append("---")
    return "\n".join(lines) + "\n\n"


def nvd_window_url(start: dt.datetime, end: dt.datetime) -> str:
    params = urllib.parse.urlencode(
        {
            "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "resultsPerPage": 200,
        }
    )
    return f"https://services.nvd.nist.gov/rest/json/cves/2.0?{params}"


def normalize_nvd(item: dict[str, Any]) -> dict[str, Any]:
    cve = item.get("cve", {})
    cve_id = cve.get("id", "UNKNOWN")
    descriptions = cve.get("descriptions", [])
    summary = next((d.get("value") for d in descriptions if d.get("lang") == "en"), "No English description available.")
    published = cve.get("published")
    modified = cve.get("lastModified")
    raw_refs = cve.get("references", [])
    if isinstance(raw_refs, dict):
        raw_refs = raw_refs.get("referenceData", [])
    refs = [r.get("url") for r in raw_refs if isinstance(r, dict) and r.get("url")]
    metrics = cve.get("metrics", {})
    severity = "UNKNOWN"
    cvss = None
    vector = None
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        values = metrics.get(key) or []
        if values:
            metric = values[0]
            data = metric.get("cvssData", {})
            severity = metric.get("baseSeverity") or data.get("baseSeverity") or severity
            cvss = data.get("baseScore")
            vector = data.get("vectorString")
            break
    cwes = [d.get("value") for w in cve.get("weaknesses", []) for d in w.get("description", []) if d.get("value")]
    return {
        "id": cve_id,
        "source": "NVD",
        "title": cve_id,
        "summary": summary,
        "published": published,
        "modified": modified,
        "severity": severity.upper() if severity else "UNKNOWN",
        "cvss": cvss,
        "cvss_vector": vector,
        "references": refs[:12],
        "cwes": sorted(set(cwes)),
        "ecosystem": "unknown",
        "package": None,
    }


def fetch_nvd(days: int) -> tuple[list[dict[str, Any]], str | None]:
    end = dt.datetime.now(dt.timezone.utc)
    start = end - dt.timedelta(days=days)
    url = nvd_window_url(start, end)
    try:
        data = http_json(url)
    except Exception as exc:  # noqa: BLE001
        return [], f"NVD fetch failed: {exc}"
    records = [normalize_nvd(item) for item in data.get("vulnerabilities", [])]
    records.sort(key=lambda r: (SEVERITY_ORDER.get(r["severity"], 0), r.get("published") or ""), reverse=True)
    return records, None


def fetch_cisa_kev() -> tuple[set[str], str | None]:
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    try:
        data = http_json(url)
    except Exception as exc:  # noqa: BLE001
        return set(), f"CISA KEV fetch failed: {exc}"
    return {v.get("cveID") for v in data.get("vulnerabilities", []) if v.get("cveID")}, None


def load_existing_ids(path: Path) -> set[str]:
    if not path.exists():
        return set()
    ids: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if obj.get("id"):
            ids.add(obj["id"])
    return ids


def advisory_path(record: dict[str, Any]) -> Path:
    rid = record["id"]
    if rid.startswith("CVE-"):
        return ROOT / "advisories" / "cve" / f"{rid}.md"
    if rid.upper().startswith("GHSA-"):
        return ROOT / "advisories" / "ghsa" / f"{slug(rid)}.md"
    return ROOT / "advisories" / "osv" / f"{slug(rid)}.md"


def write_advisory(record: dict[str, Any], today: str, kev_ids: set[str]) -> Path:
    path = advisory_path(record)
    path.parent.mkdir(parents=True, exist_ok=True)
    rid = record["id"]
    tags = ["advisory", record["severity"].lower(), "nvd"]
    if rid in kev_ids:
        tags.append("known-exploited")
    packages = infer_packages(record)
    aliases = extract_aliases(record)
    fixed_versions = infer_fixed_versions(record.get("summary") or "")
    affected_ranges = infer_affected_ranges(record.get("summary") or "")
    refs = "\n".join(f"- {u}" for u in dedupe(record["references"])) or "- Not stated in source data."
    cwes = ", ".join(record.get("cwes") or []) or "Not stated in source data."
    extra: dict[str, Any] = {
        "id": rid,
        "source": record["source"],
        "aliases": [alias for alias in aliases if alias != rid],
        "severity": record["severity"],
        "cvss": record.get("cvss"),
        "published": record.get("published"),
        "modified": record.get("modified"),
        "affected_ranges": affected_ranges,
        "fixed_versions": fixed_versions,
        "packages": [package["purl"] or package["name"] for package in packages],
    }
    md = frontmatter(
        rid,
        "advisory",
        tags,
        today,
        extra,
    )
    md += f"# {rid}\n\n"
    md += "## Summary\n\n" + record["summary"].strip() + "\n\n"
    md += "## Affected Software\n\n"
    if packages:
        for package in packages:
            purl = f" ({package['purl']})" if package.get("purl") else ""
            md += f"- [[{package['path']}|{package['display']}]]{purl}\n"
        if affected_ranges:
            md += f"- Affected ranges: {', '.join(affected_ranges)}\n"
        if fixed_versions:
            md += f"- Fixed versions: {', '.join(fixed_versions)}\n"
        md += "\nAffected ranges and fixed versions are advisory data. They are not modeled as folders.\n\n"
    else:
        md += "NVD does not always provide package-level ecosystem coordinates. Treat this page as CVE-level public intelligence unless package coordinates are added from another public source.\n\n"
    md += "## Severity\n\n"
    md += f"- Source severity: {record['severity']}\n"
    md += f"- CVSS score: {record.get('cvss') if record.get('cvss') is not None else 'Not stated in source data.'}\n"
    md += f"- CVSS vector: {record.get('cvss_vector') or 'Not stated in source data.'}\n"
    md += f"- CWE: {cwes}\n"
    md += f"- CISA KEV: {'yes' if rid in kev_ids else 'no'}\n\n"
    md += "## Exploitability Status\n\n"
    md += "Use public source status only. This page does not infer exploit availability beyond CISA KEV membership or explicit public references.\n\n"
    md += "## Recommended Action\n\n"
    md += "Review the public references for vendor-specific fixed versions or mitigations. Prioritize by severity, exposure, exploitability, and availability of a supported fix. See [[mitigations/patch-management]] and [[mitigations/dependency-upgrades]].\n\n"
    md += "## Related Concepts\n\n"
    related = ["concepts/vulnerability-lifecycle", "concepts/exploitability", "concepts/cvss"]
    for package in packages:
        related.append(package["ecosystem_page"])
        related.extend(package["concepts"])
    for target in dedupe(related):
        md += f"- [[{target}]]\n"
    md += "\n"
    md += "## Public References\n\n" + refs + "\n\n"
    md += "## LLM Retrieval Notes\n\n"
    md += f"Use this page as the canonical advisory page for {rid}. Package pages are secondary entry points. Do not assume private exposure unless a separate public source states it.\n"
    path.write_text(md, encoding="utf-8")
    return path


def append_jsonl(records: list[dict[str, Any]], existing: set[str], kev_ids: set[str]) -> int:
    path = ROOT / "data" / "advisories.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    added = 0
    with path.open("a", encoding="utf-8") as f:
        for record in records:
            if record["id"] in existing:
                continue
            obj = {
                "id": record["id"],
                "source": record["source"],
                "aliases": [alias for alias in extract_aliases(record) if alias != record["id"]],
                "ecosystem": record.get("ecosystem", "unknown"),
                "package": record.get("package"),
                "packages": [package["purl"] or package["name"] for package in infer_packages(record)],
                "affected_ranges": infer_affected_ranges(record.get("summary") or ""),
                "fixed_versions": infer_fixed_versions(record.get("summary") or ""),
                "summary": record["summary"],
                "severity": record["severity"],
                "cvss": record.get("cvss"),
                "published": record.get("published"),
                "modified": record.get("modified"),
                "known_exploited": record["id"] in kev_ids,
                "references": record["references"],
            }
            f.write(json.dumps(obj, sort_keys=True) + "\n")
            added += 1
    return added


def load_jsonl_records() -> list[dict[str, Any]]:
    jsonl = ROOT / "data" / "advisories.jsonl"
    if not jsonl.exists():
        return []
    records = []
    for line in jsonl.read_text(encoding="utf-8").splitlines():
        if line.strip():
            records.append(json.loads(line))
    return records


def refresh_jsonl_metadata(today_records: list[dict[str, Any]] | None = None) -> None:
    path = ROOT / "data" / "advisories.jsonl"
    records = load_jsonl_records()
    by_id = {record.get("id"): record for record in today_records or [] if record.get("id")}
    refreshed: list[dict[str, Any]] = []
    changed = False
    for record in records:
        rid = record.get("id")
        source_record = {**record, **by_id.get(rid, {})}
        aliases = [alias for alias in extract_aliases(source_record) if alias != rid]
        packages = infer_packages(source_record)
        updates = {
            "aliases": aliases,
            "packages": [package["purl"] or package["name"] for package in packages],
            "affected_ranges": infer_affected_ranges(source_record.get("summary") or ""),
            "fixed_versions": infer_fixed_versions(source_record.get("summary") or ""),
        }
        for key, value in updates.items():
            if record.get(key) != value:
                record[key] = value
                changed = True
        if packages:
            ecosystem = packages[0]["ecosystem"]
            package_name = packages[0]["name"]
            if record.get("ecosystem") in (None, "unknown"):
                record["ecosystem"] = ecosystem
                changed = True
            if record.get("package") in (None, ""):
                record["package"] = package_name
                changed = True
        refreshed.append(record)
    if changed:
        path.write_text("".join(json.dumps(record, sort_keys=True) + "\n" for record in refreshed), encoding="utf-8")


def update_index_json(today: str) -> None:
    records = load_jsonl_records()
    severity_counts: dict[str, int] = {}
    for r in records:
        sev = r.get("severity") or "UNKNOWN"
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
    data = {
        "schema_version": "0.1.0",
        "updated": today,
        "description": "Public vulnerability index for normalized wiki records.",
        "record_count": len(records),
        "severity_counts": severity_counts,
        "records": [
            {
                "id": r.get("id"),
                "aliases": extract_aliases(r),
                "severity": r.get("severity"),
                "published": r.get("published"),
                "packages": [package["purl"] or package["name"] for package in infer_packages(r)],
            }
            for r in records
        ],
    }
    (ROOT / "data" / "vulnerability-index.json").write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_package_pages_and_indexes(today: str, records: list[dict[str, Any]]) -> None:
    packages_by_key: dict[str, dict[str, Any]] = {}
    alias_index: dict[str, dict[str, Any]] = {}

    for record in records:
        rid = record.get("id")
        if not rid or rid == "PLACEHOLDER-0000":
            continue
        aliases = extract_aliases(record)
        packages = infer_packages(record)
        for alias in aliases:
            alias_index[alias] = {
                "canonical_advisory": record_link(record),
                "id": rid,
                "packages": [package["purl"] or package["name"] for package in packages],
            }
        for package in packages:
            key = package["purl"] or f"{package['ecosystem']}:{package['name']}"
            entry = packages_by_key.setdefault(
                key,
                {
                    **package,
                    "advisories": [],
                    "aliases": [],
                    "references": [],
                    "affected_ranges": [],
                    "fixed_versions": [],
                },
            )
            entry["advisories"].append(
                {
                    "id": rid,
                    "path": record_link(record),
                    "severity": record.get("severity") or "UNKNOWN",
                    "published": record.get("published"),
                }
            )
            entry["aliases"].extend(aliases)
            entry["references"].extend(record.get("references") or [])
            entry["affected_ranges"].extend(infer_affected_ranges(record.get("summary") or ""))
            entry["fixed_versions"].extend(infer_fixed_versions(record.get("summary") or ""))

    for entry in packages_by_key.values():
        entry["aliases"] = dedupe(entry["aliases"])
        entry["references"] = dedupe(entry["references"])
        entry["affected_ranges"] = dedupe(entry["affected_ranges"])
        entry["fixed_versions"] = dedupe(entry["fixed_versions"])
        entry["advisories"] = sorted(entry["advisories"], key=lambda item: item["id"])
        path = package_path(entry)
        path.parent.mkdir(parents=True, exist_ok=True)
        purl = entry.get("purl")
        extra = {
            "ecosystem": entry["ecosystem"],
            "package": entry["name"],
            "purl": purl,
            "aliases": entry["aliases"],
        }
        tags = ["packages", entry["ecosystem"], slug(entry["name"])]
        md = frontmatter(entry["display"], "package", tags, today, extra)
        md += f"# {entry['display']}\n\n"
        md += "This page is a secondary package or product entry point. Canonical advisory records remain under `advisories/cve`, `advisories/ghsa`, or `advisories/osv`.\n\n"
        md += "## Identity\n\n"
        md += f"- Ecosystem: {entry['ecosystem']}\n"
        md += f"- Public name: {entry['name']}\n"
        md += f"- PURL: {purl or 'Not inferable from current public records.'}\n"
        md += f"- Ecosystem notes: [[{entry['ecosystem_page']}]]\n\n"
        md += "## Advisory Links\n\n"
        for advisory in entry["advisories"]:
            md += f"- [[{advisory['path']}|{advisory['id']}]] - {advisory['severity']}"
            if advisory.get("published"):
                md += f" - published {advisory['published']}"
            md += "\n"
        md += "\n## Version Data\n\n"
        md += "- Affected ranges: " + (", ".join(entry["affected_ranges"]) if entry["affected_ranges"] else "Not stated in current public records.") + "\n"
        md += "- Fixed versions: " + (", ".join(entry["fixed_versions"]) if entry["fixed_versions"] else "Not stated in current public records.") + "\n\n"
        md += "Affected ranges and fixed versions are maintained as data fields and list values, not as package/version folders.\n\n"
        md += "## Public References\n\n"
        for ref in entry["references"][:12]:
            md += f"- {ref}\n"
        md += "\n## Retrieval Notes\n\nUse this page to find public advisories associated with this package or product identity. Use the linked advisory pages as canonical records.\n"
        path.write_text(md, encoding="utf-8")

    package_index = {
        "schema_version": "0.1.0",
        "updated": today,
        "description": "Secondary index of public package and product entry points. PURL is the stable package identity when inferable.",
        "packages": [
            {
                "name": entry["name"],
                "display": entry["display"],
                "ecosystem": entry["ecosystem"],
                "purl": entry.get("purl"),
                "path": entry["path"],
                "advisories": [advisory["id"] for advisory in entry["advisories"]],
                "aliases": entry["aliases"],
            }
            for entry in sorted(packages_by_key.values(), key=lambda item: (item["ecosystem"], item["name"]))
        ],
    }
    alias_data = {
        "schema_version": "0.1.0",
        "updated": today,
        "description": "Public advisory alias index. Aliases resolve to canonical advisory pages.",
        "aliases": dict(sorted(alias_index.items())),
    }
    data_dir = ROOT / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    (data_dir / "package-index.json").write_text(json.dumps(package_index, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (data_dir / "alias-index.json").write_text(json.dumps(alias_data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_daily_report(today: str, selected: list[dict[str, Any]], added_count: int, errors: list[str]) -> Path:
    path = ROOT / "reports" / "daily" / f"{today}.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    critical_high = [r for r in selected if r["severity"] in {"CRITICAL", "HIGH"}]
    md = frontmatter(f"Daily Public Security Report {today}", "report", ["reports", "daily", "advisories"], today)
    md += f"# Daily Public Security Report {today}\n\n"
    md += "This report summarizes public vulnerability advisories collected for the wiki update. It contains no private environment assessment.\n\n"
    md += "## Summary\n\n"
    md += f"- New normalized records added to JSONL: {added_count}\n"
    md += f"- Advisory pages written or refreshed: {len(selected)}\n"
    md += f"- Critical/High advisories in this run: {len(critical_high)}\n"
    if errors:
        md += "- Source warnings: " + "; ".join(errors) + "\n"
    md += "\n## Critical and High\n\n"
    if critical_high:
        for r in critical_high[:20]:
            md += f"- [[{record_link(r)}]] - {r['severity']} - {r['summary'][:220].strip()}\n"
    else:
        md += "- None identified in this run.\n"
    md += "\n## All Selected Advisories\n\n"
    for r in selected:
        target = record_link(r)
        md += f"- [[{target}]] - {r['severity']} - published {r.get('published') or 'unknown'}\n"
    md += "\n## Public-Safety Note\n\nOnly public advisory metadata and public references were used. Private relevance analysis, if any, must stay outside this repository.\n"
    path.write_text(md, encoding="utf-8")
    return path


def update_log(today: str, selected: list[dict[str, Any]], added_count: int) -> None:
    path = ROOT / "log.md"
    text = path.read_text(encoding="utf-8")
    entry = f"\n## {today}\n\n- Ran public advisory update.\n- Advisory pages written or refreshed: {len(selected)}.\n- New JSONL records added: {added_count}.\n"
    path.write_text(text.rstrip() + "\n" + entry + "\n", encoding="utf-8")


def run_check(cmd: list[str]) -> tuple[int, str]:
    proc = subprocess.run(cmd, cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
    return proc.returncode, proc.stdout.strip()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--days", type=int, default=2)
    parser.add_argument("--limit", type=int, default=12)
    parser.add_argument("--commit", action="store_true")
    args = parser.parse_args()

    today = dt.datetime.now().strftime("%Y-%m-%d")
    records, nvd_error = fetch_nvd(args.days)
    kev_ids, kev_error = fetch_cisa_kev()
    errors = [e for e in (nvd_error, kev_error) if e]

    selected = [r for r in records if r["severity"] in {"CRITICAL", "HIGH"}][: args.limit]
    if not selected:
        selected = records[: min(args.limit, len(records))]

    existing = load_existing_ids(ROOT / "data" / "advisories.jsonl")
    for record in selected:
        write_advisory(record, today, kev_ids)
    added_count = append_jsonl(selected, existing, kev_ids)
    refresh_jsonl_metadata(selected)
    update_index_json(today)
    write_package_pages_and_indexes(today, load_jsonl_records())
    report = write_daily_report(today, selected, added_count, errors)
    update_log(today, selected, added_count)

    for cmd in ([sys.executable, "scripts/privacy_scan.py", "."], [sys.executable, "scripts/wiki_healthcheck.py", "."]):
        code, output = run_check(list(cmd))
        print(output)
        if code != 0:
            print("check failed; not committing", file=sys.stderr)
            return code

    print(json.dumps({"selected": len(selected), "added_jsonl": added_count, "report": str(report.relative_to(ROOT)), "errors": errors}, indent=2))

    if args.commit:
        subprocess.run(["git", "add", "."], cwd=ROOT, check=True)
        status = subprocess.run(["git", "status", "--short"], cwd=ROOT, text=True, stdout=subprocess.PIPE, check=True).stdout.strip()
        if status:
            subprocess.run(["git", "commit", "-m", f"update public security advisories {today}"], cwd=ROOT, check=True)
        else:
            print("no changes to commit")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
