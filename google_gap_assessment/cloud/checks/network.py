"""Networking (NET-001..NET-008): default and legacy networks, SSH / RDP / anything open to the internet, flow logs, DNSSEC.

One function per check. Firewall evaluation is deliberately simple (see ``rule_opens_port``).
"""

from __future__ import annotations

import re

from ...model import gap_or_pass, g
from .common import Context, has_items, leaf, registrar, run_checks

CHECKS: list = []
check = registrar(CHECKS)
DOMAIN_NAME = "Networking"   # the name the control mapping and reports use for this domain

FIREWALL_NOTE = "Rule priority, deny rules and hierarchical firewall policies are not evaluated."


def _internet_ingress_allow(rule: dict) -> bool:
    """An enabled ingress allow rule open to the whole internet."""
    if rule.get("disabled"):
        return False
    if rule.get("direction") and rule["direction"] != "INGRESS":
        return False
    if not has_items(rule.get("allowed")):
        return False
    ranges = rule.get("sourceRanges") or []
    return "0.0.0.0/0" in ranges or "::/0" in ranges


def rule_opens_port(rule: dict, port: int) -> bool:
    """True when an ingress allow rule admits the TCP port from the whole internet.

    Rule priority, deny rules and hierarchical firewall policies are not evaluated, so a match means "an allow rule
    exists", which is what the CIS recommendation tests.
    """
    if not _internet_ingress_allow(rule):
        return False
    for a in rule["allowed"]:
        proto = str(g(a, "IPProtocol", "ipProtocol") or "").lower()
        if proto in ("all", ""):
            return True
        if proto not in ("tcp", "6"):
            continue
        ports = a.get("ports") or []
        if not ports:  # no port list means every port
            return True
        for p in map(str, ports):
            m = re.fullmatch(r"(\d+)-(\d+)", p)
            if (m and int(m[1]) <= port <= int(m[2])) or p == str(port):
                return True
    return False


def rule_allows_everything(rule: dict) -> bool:
    """Every protocol, or all TCP/UDP ports, from the internet."""
    if not _internet_ingress_allow(rule):
        return False
    for a in rule["allowed"]:
        proto = str(g(a, "IPProtocol", "ipProtocol") or "").lower()
        if proto == "all" or (proto in ("tcp", "udp") and not a.get("ports")):
            return True
    return False


def _rule_label(project: str, r: dict) -> str:
    return f"{project}/{r.get('name')} (network {leaf(r.get('network'))})"


def _public_zones(ctx: Context, project: str) -> "list[dict]":
    return [z for z in ctx.gcloud.get_list("dns managed-zones list", project=project) if z.get("visibility") in (None, "public")]


@check("NET-001")
def default_network_exists(ctx: Context, project: str):
    """A network named 'default' exists."""
    nets = ctx.gcloud.get_list("compute networks list", project=project)
    return [gap_or_pass(project, "NET-001", [f"{project}/default" for n in nets if n.get("name") == "default"],
                        "The default network comes with permissive pre-populated firewall rules (SSH, RDP, ICMP and all internal traffic).")]


@check("NET-002")
def legacy_network_exists(ctx: Context, project: str):
    """A legacy (single address range) network exists."""
    nets = ctx.gcloud.get_list("compute networks list", project=project)
    return [gap_or_pass(project, "NET-002", [f"{project}/{n.get('name')}" for n in nets if g(n, "IPv4Range", "ipv4Range") is not None],
                        "Legacy networks have a single global address range and cannot use subnet-level controls.")]


@check("NET-003")
def ssh_open_to_internet(ctx: Context, project: str):
    """An ingress allow rule admitting TCP 22 from 0.0.0.0/0."""
    rules = ctx.gcloud.get_list("compute firewall-rules list", project=project)
    return [gap_or_pass(project, "NET-003", [_rule_label(project, r) for r in rules if rule_opens_port(r, 22)], f"SSH (22) reachable from 0.0.0.0/0. {FIREWALL_NOTE}")]


@check("NET-004")
def rdp_open_to_internet(ctx: Context, project: str):
    """An ingress allow rule admitting TCP 3389 from 0.0.0.0/0."""
    rules = ctx.gcloud.get_list("compute firewall-rules list", project=project)
    return [gap_or_pass(project, "NET-004", [_rule_label(project, r) for r in rules if rule_opens_port(r, 3389)], f"RDP (3389) reachable from 0.0.0.0/0. {FIREWALL_NOTE}")]


@check("NET-005")
def everything_open_to_internet(ctx: Context, project: str):
    """An ingress allow rule admitting every protocol, or all TCP/UDP ports, from 0.0.0.0/0."""
    rules = ctx.gcloud.get_list("compute firewall-rules list", project=project)
    return [gap_or_pass(project, "NET-005", [_rule_label(project, r) for r in rules if rule_allows_everything(r)],
                        f"All protocols or all ports reachable from 0.0.0.0/0. {FIREWALL_NOTE}")]


@check("NET-006")
def flow_logs_enabled(ctx: Context, project: str):
    """VPC Flow Logs on every ordinary subnet (proxy-only and similar subnets cannot have them)."""
    subnets = ctx.gcloud.get_list("compute networks subnets list", project=project)
    missing = [f"{project}/{leaf(s.get('region'))}/{s.get('name')}" for s in subnets
               if g(s, "purpose") in (None, "PRIVATE") and not (s.get("logConfig") or {}).get("enable")]
    return [gap_or_pass(project, "NET-006", missing, "VPC Flow Logs record network flows for investigation and anomaly detection.")]


@check("NET-007")
def dnssec_on_public_zones(ctx: Context, project: str):
    """DNSSEC on for every public managed zone (a missing dnssecConfig means off)."""
    off = [f"{project}/{z.get('name')}" for z in _public_zones(ctx, project) if g(z.get("dnssecConfig"), "state") not in ("on", "transfer")]
    return [gap_or_pass(project, "NET-007", off, "DNSSEC protects public zones against spoofed answers.")]


@check("NET-008")
def dnssec_weak_algorithm(ctx: Context, project: str):
    """A DNSSEC-enabled public zone still signing with RSASHA1."""
    weak = [f"{project}/{z.get('name')} - RSASHA1 signing key" for z in _public_zones(ctx, project)
            if g(z.get("dnssecConfig"), "state") == "on"
            and any(str(k.get("algorithm", "")).lower() == "rsasha1" for k in (z["dnssecConfig"].get("defaultKeySpecs") or []))]
    return [gap_or_pass(project, "NET-008", weak, "RSASHA1 is a weak signing algorithm; use RSASHA256 or ECDSA.")]


def collect(ctx: Context, projects: "list[str]", only=None) -> "list[dict]":
    return run_checks(ctx, projects, CHECKS, only)
