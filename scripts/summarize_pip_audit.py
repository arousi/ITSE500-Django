#!/usr/bin/env python
"""Summarize a `pip-audit -f json` report into a Markdown table.

Used by CI (.github/workflows/ci.yml, "Dependency vulnerability audit" step)
to write a human-readable summary to $GITHUB_STEP_SUMMARY so advisories are
visible on the PR/run page without having to download the JSON artifact.

pip-audit's default JSON schema does not include a CVSS/severity score (the
underlying OSV/PyPA advisory feeds are inconsistent about publishing one), so
this script reports each vulnerable package with its advisory count and the
lowest available fix version rather than fabricating a severity label. To
manually triage severity for a specific advisory, look up its ID (a
PYSEC-/CVE-/GHSA- identifier) at https://osv.dev.

Usage:
    python scripts/summarize_pip_audit.py pip-audit-report.json
"""
import json
import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: summarize_pip_audit.py <pip-audit-report.json>", file=sys.stderr)
        return 2

    report_path = Path(sys.argv[1])
    if not report_path.exists() or report_path.stat().st_size == 0:
        print("## Dependency vulnerability audit\n")
        print("_No report generated (pip-audit may have failed to run; check the raw job log)._")
        return 0

    try:
        data = json.loads(report_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        print("## Dependency vulnerability audit\n")
        print("_Report was not valid JSON; check the raw job log._")
        return 0

    vulnerable = [dep for dep in data.get("dependencies", []) if dep.get("vulns")]

    print("## Dependency vulnerability audit (pip-audit)\n")
    if not vulnerable:
        print("No known vulnerabilities found.")
        return 0

    total_advisories = sum(len(dep["vulns"]) for dep in vulnerable)
    print(f"**{total_advisories} advisories found across {len(vulnerable)} packages.** "
          "This step is currently non-blocking -- review and schedule upgrades; "
          "look up each ID at https://osv.dev for severity/CVSS.\n")
    print("| Package | Installed | Advisories | Fix version(s) |")
    print("|---|---|---|---|")
    for dep in sorted(vulnerable, key=lambda d: len(d["vulns"]), reverse=True):
        ids = sorted({v["id"] for v in dep["vulns"]})
        fix_versions = sorted({fv for v in dep["vulns"] for fv in v.get("fix_versions", [])})
        print(
            f"| {dep['name']} | {dep['version']} | {len(dep['vulns'])} ({', '.join(ids)}) "
            f"| {', '.join(fix_versions) or '_none published_'} |"
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
