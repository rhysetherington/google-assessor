"""Per-project accepted-risk file (JSON).

Shape: {"risks": [{"findingId": "LOG-002", "affected": ["proj - detail"], "reason": "...", "approvedBy": "...", "expires": "2027-01-31"}]}
"affected" and "expires" are optional.
"""

from __future__ import annotations

import json
from datetime import date, datetime
from pathlib import Path


def load(path: "str | None") -> "list[dict]":
    if not path:
        return []
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Accepted-risk file not found: {path}")
    risks = json.loads(p.read_text(encoding="utf-8")).get("risks") or []
    for r in risks:
        if not r.get("findingId") or not r.get("reason"):
            raise ValueError(f"Accepted-risk entries need 'findingId' and 'reason' ({path}).")
    return risks


def covers(finding: dict, risk: dict, today: "date | None" = None) -> bool:
    """True only if the whole gap is covered by this entry."""
    if risk["findingId"] != finding["FindingId"]:
        return False
    if risk.get("expires"):  # an expired acceptance stops applying so the gap resurfaces for re-approval
        try:
            expires = datetime.fromisoformat(str(risk["expires"])).date()
        except ValueError:
            return False
        if expires < (today or date.today()):
            return False
    accepted = [a for a in risk.get("affected") or [] if a]
    if not accepted:
        return True  # no 'affected' list means the whole finding is accepted
    affected = finding["AffectedObjects"]
    if not affected:
        return False
    # Every affected object must be covered, otherwise a new object would be hidden by an old acceptance.
    # Prefix match tolerates detail suffixes that change between runs.
    return all(any(str(obj).lower().startswith(a.lower()) for a in accepted) for obj in affected)


def apply(findings: "list[dict]", risks: "list[dict]") -> None:
    """Mark Gap findings covered by an entry as Accepted and record who and why."""
    for f in findings:
        if f["Status"] != "Gap":
            continue
        hit = next((r for r in risks if covers(f, r)), None)
        if hit:
            f["Status"] = "Accepted"
            f["AcceptedRisk"] = {"Reason": hit["reason"], "ApprovedBy": hit.get("approvedBy"), "Expires": hit.get("expires")}
