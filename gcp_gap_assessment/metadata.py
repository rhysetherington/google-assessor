"""Audit artefacts for a run: client, assessment name, assessor, date, reference. Anything not supplied is asked for
interactively with a sensible default; --no-prompt (or a non-interactive session) accepts the defaults silently."""

from __future__ import annotations

import re
import sys
from datetime import date, datetime

from .validation import safe_name

DEFAULT_ASSESSMENT_NAME = "Google Cloud Security Gap Assessment"


def default_client_name(primary_domain: "str | None", project_name: "str | None") -> str:
    """The first label of the organisation's domain (contoso.com -> contoso), else the first project's name."""
    if primary_domain:
        return primary_domain.split(".")[0]
    return project_name or "Client"


def _ask(prompt: str, default: str) -> str:
    answer = input(f"{prompt}{f' [{default}]' if default else ''}: ")
    return answer.strip() or default


def _clip(text: "str | None", limit: int) -> str:
    return re.sub(r"[\x00-\x1f]", " ", text or "").strip()[:limit]


def resolve_metadata(client_name=None, assessment_name=None, assessor_name=None, prepared_by=None, assessment_date=None,
                     reference=None, project_name=None, primary_domain=None, signed_in_account=None, no_prompt=False) -> dict:
    interactive = sys.stdin.isatty() and not no_prompt
    ask = _ask if interactive else (lambda _prompt, default: default)
    if interactive:
        print("\nAssessment details (press Enter to accept the value in brackets)")
    client_name = client_name or ask("Client name", default_client_name(primary_domain, project_name))
    assessment_name = assessment_name or ask("Assessment name", DEFAULT_ASSESSMENT_NAME)
    assessor_name = assessor_name or ask("Assessor (who is performing this assessment)", signed_in_account or "")
    assessment_date = assessment_date or ask("Assessment date (yyyy-MM-dd)", date.today().isoformat())
    if not reference and interactive:
        reference = ask("Engagement / reference number (optional)", "")
    try:
        parsed = datetime.strptime(assessment_date, "%Y-%m-%d").date()
    except ValueError:
        raise ValueError(f"Assessment date '{assessment_date}' is not a valid date (use yyyy-MM-dd).") from None
    return {"ClientName": _clip(client_name, 120), "AssessmentName": _clip(assessment_name, 120), "AssessorName": _clip(assessor_name, 120),
            "PreparedBy": _clip(prepared_by, 120), "AssessmentDate": parsed.isoformat(), "Reference": _clip(reference, 60),
            "ProjectName": _clip(project_name, 120), "PrimaryDomain": _clip(primary_domain, 253)}


def base_name(assessment: dict) -> "str | None":
    """ClientName-Date, e.g. contoso-2026-10-03."""
    m = assessment.get("Metadata") or {}
    if m.get("ClientName") and m.get("AssessmentDate"):
        return f"{safe_name(m['ClientName'])}-{m['AssessmentDate']}"
    return None
