"""Workspace Calendar (GCL-xxx): external sharing of calendars, invitation warnings, Exchange interoperability and paid appointments."""

from __future__ import annotations

from ..context import WsContext
from .common import PolicyRule, describe_fields, flag, is_in, registrar, run_checks

CHECKS: list = []
check = registrar(CHECKS)
DOMAIN_NAME = "Workspace: Calendar"

SVC = "calendar.service_status"
FREE_BUSY = "EXTERNAL_FREE_BUSY_ONLY"


def _rule(id_, setting, ok, fields, detail, question):
    return PolicyRule(id_, setting, ok, describe_fields(*fields), detail, question, service=SVC)


RULES = [
    _rule("GCL-001", "calendar.primary_calendar_max_allowed_external_sharing", is_in("maxAllowedExternalSharing", FREE_BUSY), ["maxAllowedExternalSharing"],
          "Event details reveal who is meeting whom and where; outsiders should see only free/busy.", "Primary calendars show outsiders free/busy only"),
    _rule("GCL-002", "calendar.secondary_calendar_max_allowed_external_sharing", is_in("maxAllowedExternalSharing", FREE_BUSY), ["maxAllowedExternalSharing"],
          "Secondary calendars (rooms, teams, projects) often hold more sensitive detail than personal ones.", "Secondary calendars show outsiders free/busy only"),
    _rule("GCL-003", "calendar.external_invitations", flag("warnOnInvite", True), ["warnOnInvite"],
          "A prompt before inviting someone outside helps stop invitations to the wrong person.", "Users are warned when inviting people outside the organisation"),
    _rule("GCL-004", "calendar.interoperability", flag("enableInteroperability", False), ["enableInteroperability"],
          "Calendar interoperability with Exchange is another trust relationship to secure; it is only needed during a migration or coexistence.", "Calendar interoperability is off"),
    _rule("GCL-005", "calendar.appointment_schedules", flag("enablePayments", False), ["enablePayments"],
          "Accepting payments through appointment schedules brings financial fraud and data-handling risk into Calendar.", "Appointment schedules cannot take payments"),
]
CHECKS.extend(r.as_check() for r in RULES)


def collect(ctx: WsContext, tenants: "list[str]", only=None) -> "list[dict]":
    return run_checks(ctx, tenants, CHECKS, only)
