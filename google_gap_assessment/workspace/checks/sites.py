"""Workspace Google Sites (GST-xxx). The service status of a product that a tenant may not need."""

from __future__ import annotations

from ..context import WsContext
from .common import PolicyRule, describe_fields, registrar, run_checks

CHECKS: list = []
check = registrar(CHECKS)
DOMAIN_NAME = "Workspace: Sites"

RULES = [
    PolicyRule("GST-001", "sites.service_status", lambda s: None if s.get("serviceState") is None else str(s["serviceState"]).upper() == "DISABLED",
               describe_fields("serviceState"),
               "Sites lets any user publish web pages, including publicly. If the organisation has no use for it, switching it off removes the exposure.",
               "Google Sites is switched off for users"),
]
CHECKS.extend(r.as_check() for r in RULES)


def collect(ctx: WsContext, tenants: "list[str]", only=None) -> "list[dict]":
    return run_checks(ctx, tenants, CHECKS, only)
