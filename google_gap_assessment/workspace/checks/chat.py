"""Workspace Google Chat (GCH-xxx): history, external file sharing, external messaging."""

from __future__ import annotations

from ..context import WsContext
from .common import PolicyRule, describe_fields, flag, is_in, registrar, run_checks

CHECKS: list = []
check = registrar(CHECKS)
DOMAIN_NAME = "Workspace: Chat"

SVC = "chat.service_status"


def _rule(id_, setting, ok, fields, detail, question):
    return PolicyRule(id_, setting, ok, describe_fields(*fields), detail, question, service=SVC)


RULES = [
    _rule("GCH-001", "chat.chat_history", flag("historyOnByDefault", True), ["historyOnByDefault"],
          "Chat history keeps conversations available for investigations and records obligations.", "Chat history is on by default"),
    _rule("GCH-002", "chat.chat_history", flag("allowUserModification", False), ["allowUserModification"],
          "If users can turn history off, anything said in Chat can be made to vanish.", "Users cannot change their chat history setting"),
    _rule("GCH-003", "chat.chat_file_sharing", is_in("externalFileSharing", "NO_FILES"), ["externalFileSharing"],
          "File sharing with outsiders in Chat bypasses the controls on Drive sharing.", "Files cannot be shared with people outside the organisation in Chat"),
    _rule("GCH-004", "chat.space_history", is_in("historyState", "HISTORY_ALWAYS_ON"), ["historyState"],
          "Spaces hold group decisions; their history should always be kept.", "Space history is always on"),
    _rule("GCH-005", "chat.external_chat_restriction",
          lambda s: None if s.get("allowExternalChat") is None else (not s["allowExternalChat"] or s.get("externalChatRestriction") == "TRUSTED_DOMAINS"),
          ["allowExternalChat", "externalChatRestriction"],
          "Open messaging with anyone outside is a direct line for phishing; restrict it to allowlisted domains.", "External chat is limited to allowlisted domains"),
]
CHECKS.extend(r.as_check() for r in RULES)


def collect(ctx: WsContext, tenants: "list[str]", only=None) -> "list[dict]":
    return run_checks(ctx, tenants, CHECKS, only)
