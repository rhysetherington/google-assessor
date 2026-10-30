"""The check registry shared by every target (Google Cloud projects and Google Workspace tenants).

A check is one function that evaluates one finding id for ONE unit (a project, or the Workspace tenant). ``run_checks`` runs the
selected checks for every unit, isolates failures, and merges the per-unit results into one finding per check.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Iterable

from .model import ProjectResult, merge_results, run_project_check


@dataclass(frozen=True)
class Check:
    """One check: a finding id and the function that evaluates it for ONE project.

    ``run(ctx, project)`` returns ProjectResults for that id (usually one; a second NotAssessed result is added when part of
    the data could not be read). Everything else (merging projects, failure containment) is done by ``run_checks``.
    """
    id: str
    run: Callable[[Any, str], Iterable[ProjectResult]]


def registrar(registry: "list[Check]"):
    """Decorator factory: ``check = registrar(CHECKS)`` then ``@check("IAM-001")`` above a function registers it."""
    def check(check_id: str):
        def decorate(fn):
            registry.append(Check(check_id, fn))
            return fn
        return decorate
    return check


def run_checks(ctx: Any, projects: "list[str]", checks: "list[Check]", only: "Iterable[str] | None" = None,
               disabled_api_means_unused: bool = True) -> "list[dict]":
    """Run each check for every project and merge the results into one finding per check.

    Each check is isolated: if one cannot read its data it becomes NotAssessed on its own and its neighbours still run.
    ``only`` limits the run to those finding ids, which is how a single check is redone.
    """
    wanted = None if only is None else set(only)
    findings = []
    for chk in checks:
        if wanted is not None and chk.id not in wanted:
            continue
        results: "list[ProjectResult]" = []
        for project in projects:
            results += run_project_check(project, [chk.id], lambda p, chk=chk: chk.run(ctx, p), disabled_api_means_unused)
        findings.append(merge_results(chk.id, results))
    return findings


