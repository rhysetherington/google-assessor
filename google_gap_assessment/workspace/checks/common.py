"""Helpers for the Workspace check domains: table-driven rules over admin-console settings, and small predicates.

Most Workspace checks ask one question of one setting ("is automatic forwarding off?"), so they are written as a ``PolicyRule``: a
finding id, the setting, a predicate and a docstring. ``as_check`` turns a rule into a registered ``Check``. Checks that need more than
one setting, the directory or DNS are ordinary functions registered with ``@check``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Optional

from ...model import ProjectResult, gap_or_pass
from ...registry import Check, registrar  # noqa: F401 - re-exported for the domain modules
from ...registry import run_checks as _run_checks
from ..context import WsContext
from ...errors import ApiError
from ..policy import judge, judge_many

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


def _service_gate(ctx: WsContext, tenant: str, finding_id: str, service: str) -> "tuple[list[ProjectResult] | None, set[str]]":
    """If the product (e.g. Gmail) is switched off for the whole tenant there is nothing to assess; OUs that switch it off are skipped."""
    if not service:
        return None, set()
    ps = ctx.policies()
    if (ps.top(service) or {}).get("serviceState") == "DISABLED":
        return [ProjectResult(tenant, finding_id, "NotApplicable", [], f"{service.split('.')[0].replace('_', ' ').title()} is switched off for the tenant.")], set()
    return None, {label for label, value in ps.overrides(service) if (value or {}).get("serviceState") == "DISABLED"}


def policy_result(ctx: WsContext, tenant: str, finding_id: str, setting: str, ok: Predicate,
                  describe: Callable[[Any], str], detail: str, service: str = "") -> "list[ProjectResult]":
    """Judge one setting at the top-level OU and in every OU or group that overrides it."""
    gated, skip = _service_gate(ctx, tenant, finding_id, service)
    if gated:
        return gated
    verdict = judge(ctx.policies(), setting, ok)
    verdict.bad = [(scope, value) for scope, value in verdict.bad if scope not in skip]
    if verdict.unknown:
        return [ProjectResult(tenant, finding_id, "NotAssessed", [], f"Google returned no value for settings/{setting}. "
                              "The tenant's edition may not include it, or the signed-in admin cannot read it.")]
    if verdict.unreadable_field:
        return [ProjectResult(tenant, finding_id, "NotAssessed", [], f"settings/{setting} was returned without a value this check can interpret (the field is missing, or is a value whose meaning is not documented). Check it in the Admin console.")]
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
    service: str = ""       # service-status setting (e.g. "gmail.service_status"); when it is DISABLED the rule does not apply

    def as_check(self) -> Check:
        def run(ctx: WsContext, tenant: str):
            return policy_result(ctx, tenant, self.id, self.setting, self.ok, self.describe, self.detail, self.service)
        run.__doc__ = f"{self.question or self.setting}. {self.detail}"
        return Check(self.id, run)


def policy_result_many(ctx: WsContext, tenant: str, finding_id: str, settings: "list[str]", ok: Callable[[dict], Optional[bool]],
                       describe: Callable[[dict], str], detail: str, service: str = "") -> "list[ProjectResult]":
    """Judge a question that needs several settings together, at the top-level OU and wherever any of them is overridden."""
    gated, skip = _service_gate(ctx, tenant, finding_id, service)
    if gated:
        return gated
    verdict = judge_many(ctx.policies(), settings, ok)
    verdict.bad = [(scope, value) for scope, value in verdict.bad if scope not in skip]
    if verdict.unknown:
        missing = [s for s in settings if ctx.policies().top(s) is None]
        return [ProjectResult(tenant, finding_id, "NotAssessed", [], f"Google returned no value for {', '.join('settings/' + m for m in missing)}. "
                              "The tenant's edition may not include it, or the signed-in admin cannot read it.")]
    if verdict.unreadable_field:
        return [ProjectResult(tenant, finding_id, "NotAssessed", [], "A setting was returned without the field this check needs.")]
    return [gap_or_pass(tenant, finding_id, [f"{tenant}: {scope} - {describe(value)}" for scope, value in verdict.bad], detail)]


def dns_check(ctx: WsContext, tenant: str, finding_id: str, per_domain: "Callable[[str, Any], Optional[str]]", detail: str) -> "list[ProjectResult]":
    """Run a DNS question for every domain of the tenant. ``per_domain(domain, resolver)`` returns a problem description or None.

    Skipped with --no-dns (NotAssessed, never a pass). A lookup that fails is NotAssessed for that domain; it does not hide the others.
    """
    if not ctx.options.check_dns or ctx.resolver is None:
        return [ProjectResult(tenant, finding_id, "NotAssessed", [], "DNS lookups were switched off (--no-dns), so this record was not checked.")]
    problems, failed = [], []
    for domain in ctx.domains or [tenant]:
        try:
            message = per_domain(domain, ctx.resolver)
        except ApiError as exc:
            failed.append(f"{domain} ({exc})")
            continue
        if message:
            problems.append(f"{tenant}: {domain} - {message}")
    out = [gap_or_pass(tenant, finding_id, problems, detail)]
    if failed:
        out.append(ProjectResult(tenant, finding_id, "NotAssessed", [], f"DNS lookup failed for: {'; '.join(failed[:3])}"))
    return out


def run_checks(ctx, tenants, checks, only=None):
    """Registry runner for Workspace. A disabled API here is the assessor's own project missing an API, never a tenant that
    does not use the service, so it is NotAssessed (and counts against the score), not NotApplicable."""
    return _run_checks(ctx, tenants, checks, only, disabled_api_means_unused=False)
