"""Helpers for the Workspace check domains: table-driven rules over admin-console settings, and small predicates.

Most Workspace checks ask one question of one setting ("is automatic forwarding off?"), so they are written as a ``PolicyRule``: a
finding id, the setting, a predicate and a docstring. ``as_check`` turns a rule into a registered ``Check``. Checks that need more than
one setting, the directory or DNS are ordinary functions registered with ``@check``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Optional

from ...model import ProjectResult, gap_or_pass
from ...registry import Check, registrar, run_checks  # noqa: F401 - re-exported for the domain modules
from ..context import WsContext
from ..policy import judge

Predicate = Callable[[Any], Optional[bool]]


# --- predicates: each returns True (compliant), False (gap) or None (the field was not returned, so it cannot be judged) ---------

def flag(key: str, expected: bool) -> Predicate:
    """The boolean field equals ``expected``."""
    return lambda s: None if s.get(key) is None else bool(s[key]) is expected


def is_in(key: str, *allowed: Any) -> Predicate:
    """The field is one of the allowed values."""
    return lambda s: None if s.get(key) is None else s[key] in allowed


def not_in(key: str, *bad: Any) -> Predicate:
    """The field is none of the given values."""
    return lambda s: None if s.get(key) is None else s[key] not in bad


def all_of(*preds: Predicate) -> Predicate:
    """False if any is False; None if none is False but some cannot be judged; True otherwise."""
    def run(s: Any) -> Optional[bool]:
        answers = [p(s) for p in preds]
        return False if False in answers else (None if None in answers else True)
    return run


def service_enabled(setting_name: str = "") -> Predicate:
    return lambda s: None if s.get("serviceState") is None else str(s["serviceState"]).upper() == "ENABLED"


def describe_fields(*keys: str) -> Callable[[Any], str]:
    """'key=value, key=value' for the fields that matter, to say what was found."""
    return lambda s: ", ".join(f"{k}={s.get(k)!r}" for k in keys)


def policy_result(ctx: WsContext, tenant: str, finding_id: str, setting: str, ok: Predicate,
                  describe: Callable[[Any], str], detail: str) -> "list[ProjectResult]":
    """Judge one setting at the top-level OU and in every OU or group that overrides it."""
    verdict = judge(ctx.policies(), setting, ok)
    if verdict.unknown:
        return [ProjectResult(tenant, finding_id, "NotAssessed", [], f"Google returned no value for settings/{setting}. "
                              "The tenant's edition may not include it, or the signed-in admin cannot read it.")]
    if verdict.unreadable_field:
        return [ProjectResult(tenant, finding_id, "NotAssessed", [], f"settings/{setting} was returned without the field this check needs.")]
    return [gap_or_pass(tenant, finding_id, [f"{tenant}: {scope} - {describe(value)}" for scope, value in verdict.bad], detail)]


@dataclass(frozen=True)
class PolicyRule:
    """One finding = one question about one admin-console setting."""
    id: str
    setting: str            # Policy API setting type without the "settings/" prefix, e.g. "gmail.auto_forwarding"
    ok: Predicate
    describe: Callable[[Any], str]
    detail: str             # why it matters; also used as the check's docstring
    question: str = ""

    def as_check(self) -> Check:
        def run(ctx: WsContext, tenant: str):
            return policy_result(ctx, tenant, self.id, self.setting, self.ok, self.describe, self.detail)
        run.__doc__ = f"{self.question or self.setting}. {self.detail}"
        return Check(self.id, run)
