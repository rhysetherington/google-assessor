"""Generate Docs/Coverage.md from the control mapping, so the page can never drift from the checks.

    python3 -m google_gap_assessment.coverage           # rewrite Docs/Coverage.md
    python3 -m google_gap_assessment.coverage --check   # fail if it is out of date
"""

from __future__ import annotations

import sys
from itertools import groupby
from pathlib import Path

from .model import CONTROL_MAPPING

OUT = Path(__file__).resolve().parent.parent / "Docs" / "Coverage.md"


def render() -> str:
    controls = sorted(CONTROL_MAPPING.values(), key=lambda c: c["id"])
    lines = ["# Coverage", "",
             f"Generated from `google_gap_assessment/data/control_mapping.json` by `python3 -m google_gap_assessment.coverage`; do not edit by hand. {len(controls)} checks.", "",
             "CIS numbers refer to the CIS Google Cloud Platform Foundation Benchmark (v3.0.0 numbering) and appear only where a check tests the same setting. "
             "Confirm them against the edition you hold; the benchmark is renumbered between releases."]
    for domain, group in groupby(sorted(controls, key=lambda c: (c["domain"], c["id"])), key=lambda c: c["domain"]):
        lines += ["", f"## {domain}", "", "| ID | Check | Severity | CIS | NIST CSF 2.0 | SCF |", "|---|---|---|---|---|---|"]
        for c in group:
            lines.append(f"| {c['id']} | {c['name']} | {c['severity']} | {', '.join(c['cis']) if c['cis'] else '-'} | {c['nistCsf']} | {c['scf']} |")
    lines += ["", "## Not covered yet", "",
              "- Inherited settings: IAM policies, audit configuration and log sinks set on a folder or the organisation are not visible from a project.",
              "- BigQuery dataset access, GKE cluster hardening, Cloud Functions / Cloud Run exposure, VPC Service Controls, Security Command Center findings, "
              "and the CIS log-metric alert recommendations (2.4 to 2.11).",
              "- Cloud KMS is scanned only in the locations passed with `--kms-location` (default `global`)."]
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
