"""Cloud SQL (SQL-001..SQL-004): public IP, networks open to the world, unencrypted connections, automated backups. One function per check."""

from __future__ import annotations

from ...model import ProjectResult, gap_or_pass, g
from .common import Context, registrar, run_checks

CHECKS: list = []
check = registrar(CHECKS)


def _instances(ctx: Context, project: str) -> "list[dict]":
    """Cloud SQL instances (on-premises replicas excluded). Fetched once per run and shared by all the checks below."""
    return [i for i in ctx.gcloud.get_list("sql instances list", project=project) if g(i, "instanceType") != "ON_PREMISES_INSTANCE"]


def _ip_config(i: dict):
    return (i.get("settings") or {}).get("ipConfiguration")


def _name(project: str, i: dict) -> str:
    return f"{project}/{i.get('name')}"


def _network_check(ctx: Context, project: str, finding_id: str, predicate, detail: str) -> list:
    """Shared shape of the three network checks: instances with network settings are judged, the rest are NotAssessed, never passed."""
    inst = _instances(ctx, project)
    judged = [i for i in inst if _ip_config(i)]
    missing = [i for i in inst if not _ip_config(i)]
    out = [gap_or_pass(project, finding_id, [_name(project, i) for i in judged if predicate(_ip_config(i))], f"{detail} Checked {len(inst)} instance(s).")]
    if missing:
        out.append(ProjectResult(project, finding_id, "NotAssessed", [], f"gcloud returned no network settings for: {', '.join(x.get('name', '?') for x in missing[:3])}"))
    return out


@check("SQL-001")
def public_ip(ctx: Context, project: str):
    """Instances with a public IPv4 address."""
    return _network_check(ctx, project, "SQL-001", lambda ip: ip.get("ipv4Enabled"), "Instances with a public IPv4 address.")


@check("SQL-002")
def authorized_network_open_to_world(ctx: Context, project: str):
    """An authorized network of 0.0.0.0/0."""
    return _network_check(ctx, project, "SQL-002",
                          lambda ip: any(n.get("value") in ("0.0.0.0/0", "::/0") for n in ip.get("authorizedNetworks") or []),
                          "Authorized networks that include 0.0.0.0/0, the whole internet.")


@check("SQL-003")
def encrypted_connections_required(ctx: Context, project: str):
    """Instances that accept unencrypted connections. sslMode replaced requireSsl; either setting that forces encryption satisfies the check."""
    def accepts_plaintext(ip: dict) -> bool:
        mode = g(ip, "sslMode")
        return mode == "ALLOW_UNENCRYPTED_AND_ENCRYPTED" if mode else not ip.get("requireSsl")
    return _network_check(ctx, project, "SQL-003", accepts_plaintext, "Instances that accept unencrypted connections.")


@check("SQL-004")
def automated_backups(ctx: Context, project: str):
    """Automated backups on. Read replicas take no backups of their own, so they are skipped."""
    inst = _instances(ctx, project)
    primaries = [i for i in inst if g(i, "instanceType") != "READ_REPLICA_INSTANCE"]
    off = [_name(project, i) for i in primaries if not ((i.get("settings") or {}).get("backupConfiguration") or {}).get("enabled")]
    return [gap_or_pass(project, "SQL-004", off, f"Instances without automated backups. Checked {len(inst)} instance(s).")]


def collect(ctx: Context, projects: "list[str]", only=None) -> "list[dict]":
    return run_checks(ctx, projects, CHECKS, only)
