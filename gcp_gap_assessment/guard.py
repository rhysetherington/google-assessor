"""Warn when the signed-in account can change resources.

An assessment only reads, so a Viewer + Security Reviewer account is enough. Owner and Editor can change
resources, which a read-only assessment should not need.
"""

from __future__ import annotations

import sys

from .checks.common import binding_pairs
from .gcloud import Gcloud


def elevated_assignments(gcloud: Gcloud, account: str, projects: "list[str]") -> "list[tuple[str, str]]":
    """(project, role) where the account holds Owner or Editor directly. Group membership is not expanded."""
    me = {f"user:{account}".lower(), f"serviceAccount:{account}".lower()}
    found = []
    for project in projects:
        try:
            policy = gcloud.get_one("projects get-iam-policy", [project])
        except Exception:  # noqa: BLE001 - best effort: the checks themselves report an unreadable policy
            continue
        for pair in binding_pairs(policy):
            if pair.role in ("roles/owner", "roles/editor") and pair.member.lower() in me:
                found.append((project, pair.role))
    return found


def confirm_elevated_use(gcloud: Gcloud, account: str, projects: "list[str]", allow: bool = False,
                         ask=input, interactive: "bool | None" = None) -> None:
    """Warn, then ask before continuing. A non-interactive run is refused unless ``allow`` is set."""
    elevated = elevated_assignments(gcloud, account, projects)
    if not elevated:
        return
    listing = ", ".join(f"{p} ({r})" for p, r in elevated)
    message = (f"'{account}' holds a role that can change resources: {listing}. The assessment itself only reads, "
               "but a read-only account (Viewer, Security Reviewer) is recommended.")
    interactive = sys.stdin.isatty() if interactive is None else interactive
    if allow:
        print(f"WARNING: {message}", file=sys.stderr)
        return
    if not interactive:
        raise RuntimeError(f"{message} Re-run with a read-only account, with --impersonate-service-account, or pass --allow-elevated-account to proceed.")
    print(f"WARNING: {message}", file=sys.stderr)
    if ask("Continue with this account anyway? (y/N) ").strip().lower() not in ("y", "yes"):
        raise RuntimeError("Cancelled: sign in with a read-only account (gcloud auth login) or use --impersonate-service-account.")
