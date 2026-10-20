"""Workspace Groups for Business (GGR-xxx): who outside the organisation can reach groups, who can create them, who can read them."""

from __future__ import annotations

from ..context import WsContext
from .common import PolicyRule, describe_fields, flag, is_in, registrar, run_checks

CHECKS: list = []
check = registrar(CHECKS)
DOMAIN_NAME = "Workspace: Groups"

SVC, S = "groups_for_business.service_status", "groups_for_business.groups_sharing"


def _rule(id_, ok, fields, detail, question):
    return PolicyRule(id_, S, ok, describe_fields(*fields), detail, question, service=SVC)


RULES = [
    _rule("GGR-001", is_in("collaborationCapability", "DOMAIN_USERS_ONLY"), ["collaborationCapability"],
          "Groups reachable from outside expose their conversations and membership to anyone the owner lets in.", "Access to groups from outside the organisation is off by default"),
    _rule("GGR-002", flag("ownersCanAllowExternalMembers", False), ["ownersCanAllowExternalMembers"],
          "Group owners adding outside members creates access nobody reviews.", "Group owners cannot add external members"),
    _rule("GGR-003", flag("ownersCanAllowIncomingMailFromPublic", False), ["ownersCanAllowIncomingMailFromPublic"],
          "A group that accepts mail from the public is a spam, phishing and enumeration target.", "Group owners cannot let the public post to a group"),
    _rule("GGR-004", is_in("createGroupsAccessLevel", "ADMIN_ONLY"), ["createGroupsAccessLevel"],
          "Unrestricted group creation produces groups nobody governs, some of which end up granting access to shared resources.", "Only administrators can create groups"),
    _rule("GGR-005", is_in("viewTopicsDefaultAccessLevel", "GROUP_MEMBERS"), ["viewTopicsDefaultAccessLevel"],
          "By default only members should be able to read a group's conversations.", "Conversations are visible to group members only by default"),
    _rule("GGR-006", lambda s: None if s.get("ownersCanHideGroups") is None and s.get("newGroupsAreHidden") is None
          else not (s.get("ownersCanHideGroups") or s.get("newGroupsAreHidden")),
          ["ownersCanHideGroups", "newGroupsAreHidden"], "Hidden groups cannot be seen in the directory, so administrators and users cannot review them.", "Groups cannot be hidden from the directory"),
]
CHECKS.extend(r.as_check() for r in RULES)


def collect(ctx: WsContext, tenants: "list[str]", only=None) -> "list[dict]":
    return run_checks(ctx, tenants, CHECKS, only)
