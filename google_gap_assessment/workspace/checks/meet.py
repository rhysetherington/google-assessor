"""Workspace Google Meet (GMT-xxx): who can join, external participant warnings, host controls, automatic recording and transcripts."""

from __future__ import annotations

from ..context import WsContext
from .common import PolicyRule, describe_fields, flag, is_in, registrar, run_checks

CHECKS: list = []
check = registrar(CHECKS)
DOMAIN_NAME = "Workspace: Meet"

SVC = "meet.service_status"


def _rule(id_, setting, ok, fields, detail, question):
    return PolicyRule(id_, setting, ok, describe_fields(*fields), detail, question, service=SVC)


RULES = [
    _rule("GMT-001", "meet.meet_joining", lambda s: None if s.get("allowedAudience") is None else s["allowedAudience"] in ("TRUSTED", "RESTRICTED"), ["allowedAudience"],
          "Anyone with a meeting link who was not invited should have to knock and be admitted.", "Outsiders who were not invited must ask to join"),
    _rule("GMT-002", "meet.safety_access", lambda s: None if s.get("meetingsAllowedToJoin") is None else s["meetingsAllowedToJoin"] in ("SAME_ORGANIZATION_ONLY", "ANY_WORKSPACE_ORGANIZATION"),
          ["meetingsAllowedToJoin"], "Your people should not join meetings made by anonymous or consumer accounts, a common phishing and lure route.",
          "Users cannot join meetings created outside any Workspace organisation"),
    _rule("GMT-003", "meet.safety_host_management", flag("enableHostManagement", True), ["enableHostManagement"],
          "Host controls let a meeting host remove disruptors and lock the meeting.", "Host management features are on"),
    _rule("GMT-004", "meet.safety_external_participants", flag("enableExternalLabel", True), ["enableExternalLabel"],
          "Labelling outside participants helps people notice who is, and is not, from the organisation.", "External participants are labelled"),
    _rule("GMT-005", "meet.automatic_recording", flag("enabled", False), ["enabled"],
          "Recording every meeting by default captures sensitive discussions that nobody decided to keep.", "Meetings are not recorded automatically"),
    _rule("GMT-006", "meet.automatic_transcription", flag("enabled", False), ["enabled"],
          "Transcribing every meeting by default creates searchable records of conversations nobody decided to keep.", "Meetings are not transcribed automatically"),
]
CHECKS.extend(r.as_check() for r in RULES)


def collect(ctx: WsContext, tenants: "list[str]", only=None) -> "list[dict]":
    return run_checks(ctx, tenants, CHECKS, only)
