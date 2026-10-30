"""Cloud KMS (KMS-001, KMS-002): publicly usable keys and keys not rotated within 90 days. One function per check.

Key rings exist per location and gcloud cannot list across locations, so only ``options.kms_locations``
(default: global) are scanned; the detail says which. This is an opt-in domain because of the extra calls.
"""

from __future__ import annotations

import re
from typing import NamedTuple

from ...model import gap_or_pass, g
from .common import Context, binding_pairs, is_public, leaf, registrar, run_checks

CHECKS: list = []
check = registrar(CHECKS)
DOMAIN_NAME = "Cloud KMS"   # the name the control mapping and reports use for this domain

MAX_ROTATION_SECONDS = 90 * 86400


class Key(NamedTuple):
    location: str
    ring: str
    name: str
    data: dict

    def label(self, project: str) -> str:
        return f"{project}/{self.location}/{self.ring}/{self.name}"


def _keys(ctx: Context, project: str) -> "list[Key]":
    """Every key in the scanned locations. Fetched once per run and shared by both checks."""
    keys = []
    for loc in ctx.options.kms_locations:
        for ring in ctx.gcloud.get_list("kms keyrings list", [f"--location={loc}"], project):
            ring_name = leaf(ring.get("name"))
            for k in ctx.gcloud.get_list("kms keys list", [f"--keyring={ring_name}", f"--location={loc}"], project):
                keys.append(Key(loc, ring_name, leaf(k.get("name")), k))
    return keys


def _scanned(ctx: Context, keys: list) -> str:
    return f"Scanned location(s): {', '.join(ctx.options.kms_locations)}; {len(keys)} key(s)."


@check("KMS-001")
def keys_publicly_usable(ctx: Context, project: str):
    """allUsers / allAuthenticatedUsers in a key's IAM policy."""
    keys = _keys(ctx, project)
    public = []
    for k in keys:
        policy = ctx.gcloud.get_one("kms keys get-iam-policy", [k.name, f"--keyring={k.ring}", f"--location={k.location}"], project)
        public += [f"{k.label(project)} - {p.member} has {p.role}" for p in binding_pairs(policy) if is_public(p.member)]
    return [gap_or_pass(project, "KMS-001", public, f"A key usable by allUsers or allAuthenticatedUsers lets anyone decrypt or sign. {_scanned(ctx, keys)}")]


@check("KMS-002")
def keys_rotated(ctx: Context, project: str):
    """Symmetric keys rotate at least every 90 days. Asymmetric keys do not rotate automatically, so they are skipped."""
    keys = _keys(ctx, project)
    def rotates_in_time(k: Key) -> bool:
        m = re.fullmatch(r"(\d+)s", str(g(k.data, "rotationPeriod") or ""))
        return bool(m) and float(m[1]) <= MAX_ROTATION_SECONDS
    stale = [k.label(project) for k in keys if g(k.data, "purpose") == "ENCRYPT_DECRYPT" and not rotates_in_time(k)]
    return [gap_or_pass(project, "KMS-002", stale, f"Symmetric keys with no rotation schedule or a period longer than 90 days. {_scanned(ctx, keys)}")]


def collect(ctx: Context, projects: "list[str]", only=None) -> "list[dict]":
    return run_checks(ctx, projects, CHECKS, only)
