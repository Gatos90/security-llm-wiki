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


def http_json(url: str, timeout: int = 30) -> Any:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def slug(text: str) -> str:
    text = text.lower().strip()
    text = re.sub(r"[^a-z0-9._-]+", "-", text)
    return text.strip("-") or "unknown"


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
    return ROOT / "advisories" / "osv" / f"{slug(rid)}.md"


def write_advisory(record: dict[str, Any], today: str, kev_ids: set[str]) -> Path:
    path = advisory_path(record)
    path.parent.mkdir(parents=True, exist_ok=True)
    rid = record["id"]
    tags = ["advisory", record["severity"].lower(), "nvd"]
    if rid in kev_ids:
        tags.append("known-exploited")
    refs = "\n".join(f"- {u}" for u in record["references"]) or "- Not stated in source data."
    cwes = ", ".join(record.get("cwes") or []) or "Not stated in source data."
    md = frontmatter(
        rid,
        "advisory",
        tags,
        today,
        {
            "id": rid,
            "source": record["source"],
            "severity": record["severity"],
            "cvss": record.get("cvss"),
            "published": record.get("published"),
            "modified": record.get("modified"),
        },
    )
    md += f"# {rid}\n\n"
    md += "## Summary\n\n" + record["summary"].strip() + "\n\n"
    md += "## Affected Software\n\n"
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
    md += "- [[concepts/vulnerability-lifecycle]]\n- [[concepts/exploitability]]\n- [[concepts/cvss]]\n\n"
    md += "## Public References\n\n" + refs + "\n\n"
    md += "## LLM Retrieval Notes\n\n"
    md += f"Use this page to identify public CVE-level details for {rid}. Do not assume affected package coordinates or private exposure unless a separate public source states them.\n"
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
                "ecosystem": record.get("ecosystem", "unknown"),
                "package": record.get("package"),
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


def update_index_json(today: str) -> None:
    jsonl = ROOT / "data" / "advisories.jsonl"
    records = []
    for line in jsonl.read_text(encoding="utf-8").splitlines():
        if line.strip():
            records.append(json.loads(line))
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
        "records": [{"id": r.get("id"), "severity": r.get("severity"), "published": r.get("published")} for r in records],
    }
    (ROOT / "data" / "vulnerability-index.json").write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


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
            md += f"- [[advisories/cve/{r['id']}]] — {r['severity']} — {r['summary'][:220].strip()}\n"
    else:
        md += "- None identified in this run.\n"
    md += "\n## All Selected Advisories\n\n"
    for r in selected:
        target = f"advisories/cve/{r['id']}" if r["id"].startswith("CVE-") else f"advisories/osv/{slug(r['id'])}"
        md += f"- [[{target}]] — {r['severity']} — published {r.get('published') or 'unknown'}\n"
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
    update_index_json(today)
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
