"""Compute Engine (CMP-001..CMP-008): default service account, full API scope, SSH key and OS Login settings, serial port,
IP forwarding, Shielded VM and external IPs. One function per check. Instances created by GKE are skipped, as the CIS benchmark does."""

from __future__ import annotations

import re

from ..model import gap_or_pass
from .common import Context, leaf, registrar, run_checks, service_account_kind

CHECKS: list = []
check = registrar(CHECKS)

FULL_ACCESS_SCOPE = "https://www.googleapis.com/auth/cloud-platform"
GKE_NOTE = "instances created by GKE are excluded"


def metadata_flag(metadata: "dict | None", key: str) -> "str | None":
    """'true' / 'false' for a metadata key, or None when it is not set.

    Only the boolean is returned, never the value of any other key: metadata also holds SSH keys and startup
    scripts that may contain secrets.
    """
    for item in (metadata or {}).get("items") or []:
        if item.get("key") == key:
            return "true" if re.fullmatch(r"(?i)true|1", str(item.get("value", ""))) else "false"
    return None


def is_gke_node(instance: dict) -> bool:
    """CIS excludes instances GKE creates and manages; their settings follow the node pool, not the VM."""
    if "goog-gke-node" in (instance.get("labels") or {}):
        return True
    return any(i.get("key") == "cluster-name" for i in (instance.get("metadata") or {}).get("items") or [])


def _instances(ctx: Context, project: str) -> "list[dict]":
    """The project's instances without GKE nodes. Fetched once per run and shared by all the checks below."""
    return [i for i in ctx.gcloud.get_list("compute instances list", project=project) if not is_gke_node(i)]


def _project_metadata(ctx: Context, project: str) -> "dict | None":
    return ctx.gcloud.get_one("compute project-info describe", project=project).get("commonInstanceMetadata")


def _name(project: str, i: dict) -> str:
    return f"{project}/{i.get('name')} ({leaf(i.get('zone'))})"


def _note(instances: list) -> str:
    return f"Checked {len(instances)} instance(s); {GKE_NOTE}."


def _uses_default_sa(i: dict) -> bool:
    return any(service_account_kind(sa.get("email")) == "DefaultCompute" for sa in i.get("serviceAccounts") or [])


def _effective_oslogin(i: dict, project_meta: "dict | None") -> "str | None":
    """OS Login set on an instance overrides the project value."""
    own = metadata_flag(i.get("metadata"), "enable-oslogin")
    return own if own is not None else metadata_flag(project_meta, "enable-oslogin")


@check("CMP-001")
def default_service_account(ctx: Context, project: str):
    """Instances running as the default Compute Engine service account."""
    inst = _instances(ctx, project)
    return [gap_or_pass(project, "CMP-001", [_name(project, i) for i in inst if _uses_default_sa(i)],
                        f"Instances running as the default Compute Engine service account, which is granted Editor by default. {_note(inst)}")]


@check("CMP-002")
def default_service_account_full_scope(ctx: Context, project: str):
    """Default service account combined with the cloud-platform scope (full access to every API)."""
    inst = _instances(ctx, project)
    hits = [i for i in inst if _uses_default_sa(i) and any(FULL_ACCESS_SCOPE in (sa.get("scopes") or []) for sa in i.get("serviceAccounts") or [])]
    return [gap_or_pass(project, "CMP-002", [_name(project, i) for i in hits],
                        f"Default service account with the cloud-platform scope (full access to every API). {_note(inst)}")]


@check("CMP-003")
def project_wide_ssh_keys_accepted(ctx: Context, project: str):
    """Instances that accept project-wide SSH keys. When OS Login is on, project keys are ignored, so those instances pass."""
    inst, meta = _instances(ctx, project), _project_metadata(ctx, project)
    hits = [i for i in inst if _effective_oslogin(i, meta) != "true" and metadata_flag(i.get("metadata"), "block-project-ssh-keys") != "true"]
    return [gap_or_pass(project, "CMP-003", [_name(project, i) for i in hits],
                        f"Instances that accept project-wide SSH keys (block-project-ssh-keys is not true and OS Login is off). {_note(inst)}")]


@check("CMP-004")
def os_login_enabled(ctx: Context, project: str):
    """OS Login on in project metadata, and not switched off on any instance."""
    inst, meta = _instances(ctx, project), _project_metadata(ctx, project)
    hits = [f"{project} (project metadata enable-oslogin is not TRUE)"] if metadata_flag(meta, "enable-oslogin") != "true" else []
    hits += [f"{_name(project, i)} - enable-oslogin is FALSE" for i in inst if metadata_flag(i.get("metadata"), "enable-oslogin") == "false"]
    return [gap_or_pass(project, "CMP-004", hits, "OS Login ties SSH access to IAM identities and supports 2-step verification.")]


@check("CMP-005")
def serial_port_disabled(ctx: Context, project: str):
    """Serial console access not enabled in project metadata or on any instance."""
    inst, meta = _instances(ctx, project), _project_metadata(ctx, project)
    hits = [f"{project} (project metadata serial-port-enable is TRUE)"] if metadata_flag(meta, "serial-port-enable") == "true" else []
    hits += [_name(project, i) for i in inst if metadata_flag(i.get("metadata"), "serial-port-enable") == "true"]
    return [gap_or_pass(project, "CMP-005", hits, "The interactive serial console accepts connections without the usual network controls.")]


@check("CMP-006")
def ip_forwarding_off(ctx: Context, project: str):
    """Instances allowed to forward packets with a foreign source or destination address."""
    inst = _instances(ctx, project)
    return [gap_or_pass(project, "CMP-006", [_name(project, i) for i in inst if i.get("canIpForward")],
                        f"Instances allowed to forward packets with a foreign source or destination address. {_note(inst)}")]


@check("CMP-007")
def shielded_vm_enabled(ctx: Context, project: str):
    """vTPM and integrity monitoring both on (the CIS requirement; Secure Boot is not required)."""
    inst = _instances(ctx, project)
    def shielded(i: dict) -> bool:
        s = i.get("shieldedInstanceConfig") or {}
        return bool(s.get("enableVtpm") and s.get("enableIntegrityMonitoring"))
    return [gap_or_pass(project, "CMP-007", [_name(project, i) for i in inst if not shielded(i)],
                        f"Instances without both vTPM and integrity monitoring (Shielded VM). {_note(inst)}")]


@check("CMP-008")
def no_external_ip(ctx: Context, project: str):
    """Instances with an external IP address."""
    inst = _instances(ctx, project)
    def external(i: dict) -> bool:
        return any(ac and (ac.get("natIP") or ac.get("type") == "ONE_TO_ONE_NAT")
                   for ni in i.get("networkInterfaces") or [] for ac in ni.get("accessConfigs") or [])
    return [gap_or_pass(project, "CMP-008", [_name(project, i) for i in inst if external(i)],
                        f"Instances with an external IP address, reachable directly from the internet. {_note(inst)}")]


def collect(ctx: Context, projects: "list[str]", only=None) -> "list[dict]":
    return run_checks(ctx, projects, CHECKS, only)
