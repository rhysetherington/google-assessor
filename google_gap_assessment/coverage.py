"""Generate Docs/Coverage.md from the control mapping, so the page can never drift from the checks.

    python3 -m google_gap_assessment.coverage           # rewrite Docs/Coverage.md
    python3 -m google_gap_assessment.coverage --check   # fail if it is out of date
"""

from __future__ import annotations

import sys
from itertools import groupby
from pathlib import Path

import json

from .model import CONTROL_MAPPING

OUT = Path(__file__).resolve().parent.parent / "Docs" / "Coverage.md"
SCUBA = Path(__file__).parent / "data" / "scuba_policies.json"


def _table(controls: "list[dict]", workspace: bool) -> "list[str]":
    ref_head = "CISA SCuBA" if workspace else "CIS"
    lines = ["", f"| ID | Check | Severity | {ref_head} | NIST CSF 2.0 | SCF |", "|---|---|---|---|---|---|"]
    for c in controls:
        refs = c.get("scuba") if workspace else c.get("cis")
        shown = ", ".join(r.removeprefix("GWS.").removesuffix("v1") for r in refs) if refs else "-"
        lines.append(f"| {c['id']} | {c['name']} | {c['severity']} | {shown} | {c['nistCsf']} | {c['scf']} |")
    return lines


def render() -> str:
    controls = sorted(CONTROL_MAPPING.values(), key=lambda c: c["id"])
    lines = ["# Coverage", "",
             f"Generated from `google_gap_assessment/data/control_mapping.json` by `python3 -m google_gap_assessment.coverage`; do not edit by hand. {len(controls)} checks.", ""]
    for source, title, note in (
            ("workspace", "Google Workspace", "SCuBA references are the CISA Secure Cloud Business Applications baseline policies each check covers (`COMMONCONTROLS.5.2` is "
             "`GWS.COMMONCONTROLS.5.2v1`); a check with `-` is an addition of our own."),
            ("cloud", "Google Cloud", "CIS numbers refer to the CIS Google Cloud Platform Foundation Benchmark (v3.0.0 numbering) and appear only where a check tests the "
             "same setting. Confirm them against the edition you hold; the benchmark is renumbered between releases.")):
        group = [c for c in controls if c.get("source", "cloud") == source]
        if not group:
            continue
        lines += [f"## {title} ({len(group)} checks)", "", note]
        for domain, items in groupby(sorted(group, key=lambda c: (c["domain"], c["id"])), key=lambda c: c["domain"]):
            lines += ["", f"### {domain}"] + _table(list(items), source == "workspace")
        lines.append("")
    scuba = json.loads(SCUBA.read_text(encoding="utf-8"))
    covered = {ref.removesuffix("v1") for c in controls for ref in c.get("scuba", [])}
    lines += [f"## CISA SCuBA coverage ({len(covered)} of {len(scuba['policies'])} policies)", "",
              "Every Workspace baseline policy that is not covered, and why. The reasons: " + "; ".join(f"**{k}** = {v}" for k, v in scuba["reasons"].items()) + ".", "",
              "| Policy | Reason | Note |", "|---|---|---|"]
    lines += [f"| {pid.removeprefix('GWS.')} | {info['reason']} | {info['note']} |" for pid, info in scuba["not_covered"].items()]
    lines += ["", "## Not covered yet", "",
              "- Google Cloud: IAM policies, audit configuration and log sinks set on a folder or the organisation are not visible from a project.",
              "- Google Cloud: BigQuery dataset access, GKE cluster hardening, Cloud Functions / Cloud Run exposure, VPC Service Controls, Security Command Center "
              "findings, and the CIS log-metric alert recommendations (2.4 to 2.11).",
              "- Google Cloud: Cloud KMS is scanned only in the locations passed with `--kms-location` (default `global`)."]
    return "\n".join(lines) + "\n"


def main(argv: "list[str]") -> int:
    text = render()
    if "--check" in argv:
        if not OUT.exists() or OUT.read_text(encoding="utf-8") != text:
            print("Docs/Coverage.md is out of date. Run: python3 -m google_gap_assessment.coverage", file=sys.stderr)
            return 1
        return 0
    OUT.write_text(text, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
