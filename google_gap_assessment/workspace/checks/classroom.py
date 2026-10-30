"""Workspace Classroom (GCR-xxx): who can join classes, app access to class data, roster import, who can unenrol students and create classes."""

from __future__ import annotations

from ..context import WsContext
from .common import PolicyRule, describe_fields, flag, is_in, registrar, run_checks

CHECKS: list = []
check = registrar(CHECKS)
DOMAIN_NAME = "Workspace: Classroom"

SVC = "classroom.service_status"


def _rule(id_, setting, ok, fields, detail, question):
    return PolicyRule(id_, setting, ok, describe_fields(*fields), detail, question, service=SVC)


RULES = [
    _rule("GCR-001", "classroom.class_membership", lambda s: None if s.get("whoCanJoinClasses") is None else s["whoCanJoinClasses"] in ("ANYONE_IN_DOMAIN", "ANYONE_IN_ALLOWLISTED_DOMAINS"),
          ["whoCanJoinClasses"], "Classes that outsiders can join expose students and course material to people the school has not vetted.", "Only users in the domain (or allowlisted domains) can join classes"),
    _rule("GCR-002", "classroom.class_membership", lambda s: None if s.get("whichClassesCanUsersJoin") is None else s["whichClassesCanUsersJoin"] in ("CLASSES_IN_DOMAIN", "CLASSES_IN_ALLOWLISTED_DOMAINS"),
          ["whichClassesCanUsersJoin"], "Users joining classes run by other organisations take their data, and their devices' exposure, outside your control.", "Users can join only classes in the domain (or allowlisted domains)"),
    _rule("GCR-003", "classroom.api_data_access", flag("enableApiAccess", False), ["enableApiAccess"],
          "Letting apps use the Classroom API exposes rosters, work and grades to whatever app a teacher approves.", "Users cannot authorise apps to access Classroom data"),
    _rule("GCR-004", "classroom.roster_import", is_in("rosterImportOption", "OFF"), ["rosterImportOption"],
          "Roster import from Clever is another path for student data to enter and leave Classroom.", "Roster import is off"),
    _rule("GCR-005", "classroom.student_unenrollment", is_in("whoCanUnenrollStudents", "TEACHERS_ONLY"), ["whoCanUnenrollStudents"],
          "Students who can remove each other (or themselves) from classes can disrupt teaching and hide activity.", "Only teachers can unenrol students"),
    _rule("GCR-006", "classroom.teacher_permissions", is_in("whoCanCreateClasses", "VERIFIED_TEACHERS_ONLY"), ["whoCanCreateClasses"],
          "Anyone who can create a class can invite students and outsiders; verification keeps that to real teachers.", "Only verified teachers can create classes"),
]
CHECKS.extend(r.as_check() for r in RULES)


def collect(ctx: WsContext, tenants: "list[str]", only=None) -> "list[dict]":
    return run_checks(ctx, tenants, CHECKS, only)
