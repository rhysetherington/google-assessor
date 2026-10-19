"""Optional evidence CSVs: the full list of affected items per gap (the reports show only the first 25)."""

from __future__ import annotations

import csv
import re
from pathlib import Path

from .validation import safe_name


def safe_csv_value(value: object) -> str:
    """Make a project-supplied string safe to put in a CSV that may be opened in Excel.

    A value starting with = + - @ (or a tab) is read as a formula, so a hostile resource name such as
    =HYPERLINK("http://...") would run when the file is opened. A leading apostrophe makes it plain text.
    """
    if value is None:
        return ""
    text = re.sub(r"[\r\n]+", " ", str(value))
    return "'" + text if re.match(r"[=+\-@\t]", text) else text


def write_files(assessment: dict, folder: Path) -> "list[Path]":
    """Write evidence/<FindingId>.csv per gap plus evidence/_index.csv; record each path on the finding as EvidenceFile."""
    with_evidence = [f for f in assessment["Findings"] if f["Status"] == "Gap" and f["AffectedCount"] > 0]
    if not with_evidence:
        return []
    directory = folder / "evidence"
    directory.mkdir(parents=True, exist_ok=True)
    written, index = [], []
    for f in with_evidence:
        relative = f"evidence/{safe_name(f['FindingId'], 'finding')}.csv"
        path = folder / relative
        with path.open("w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["FindingId", "Severity", "AffectedItem"])
            for item in f["AffectedObjects"]:
                w.writerow([f["FindingId"], f["Severity"], safe_csv_value(item)])
        f["EvidenceFile"] = relative
        written.append(path)
        index.append([f["FindingId"], safe_csv_value(f["Name"]), f["Severity"], f["AffectedCount"], relative, f["ScfControl"], f["NistCsf"],
                      safe_csv_value("; ".join(f["CisControl"])), safe_csv_value(f["Detail"])])
    index_path = directory / "_index.csv"
    with index_path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["FindingId", "Name", "Severity", "AffectedCount", "File", "ScfControl", "NistCsf", "CisControl", "Detail"])
        w.writerows(index)
    written.append(index_path)
    return written


def evidence_link(finding: dict, root: "Path | None") -> "str | None":
    """The relative evidence path, or None when there is none or the file is not next to the report being written."""
    rel = finding.get("EvidenceFile")
    if not rel or (root is not None and not (root / rel).exists()):
        return None
    return str(rel)
