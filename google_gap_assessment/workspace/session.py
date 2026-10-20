"""Connecting to a Google Workspace tenant: get a token, check it holds the read-only scopes, and learn which tenant it is."""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from typing import Callable, Optional

from ..errors import ApiError
from . import auth
from .client import WorkspaceClient
from .context import WsContext, WsOptions
from .directory import Directory
from .mail_dns import DEFAULT_ENDPOINT, DohResolver


@dataclass
class WsSession:
    """A connected tenant: the context the checks run in, and who/what it is."""
    ctx: WsContext
    customer_id: str
    primary_domain: str
    domains: "list[str]" = field(default_factory=list)
    account: str = "unknown"


def _explain(exc: ApiError, quota_project: Optional[str]) -> str:
    hints = {
        "Auth": "Sign in first, then retry.\n" + auth.setup_instructions(quota_project=quota_project or "YOUR_PROJECT_ID"),
        "PermissionDenied": "The signed-in account must be a Super Admin of the Workspace tenant, and the token must carry the read-only scopes.",
        "ApiDisabled": "Enable the Admin SDK and Cloud Identity APIs in the quota project (gcloud services enable admin.googleapis.com cloudidentity.googleapis.com --project <project>).",
    }
    return f"{exc}\n{hints.get(exc.category, '')}".strip()


def connect_workspace(quota_project: Optional[str] = None, doh_endpoint: str = DEFAULT_ENDPOINT, check_dns: bool = True,
                      options: Optional[WsOptions] = None, token_provider: Optional[Callable[[], str]] = None,
                      info_post: Optional[Callable[..., dict]] = None, client: Optional[WorkspaceClient] = None,
                      resolver: Optional[DohResolver] = None, warn: Callable[[str], None] = lambda m: print(f"WARNING: {m}", file=sys.stderr)) -> WsSession:
    """Verify the token and discover the tenant. Raises RuntimeError with the fix when sign-in, role or API access is missing."""
    provider = token_provider or auth.AdcTokenProvider()
    try:
        token = provider()
        info = auth.token_info(token, info_post)
    except ApiError as exc:
        raise RuntimeError(_explain(exc, quota_project)) from exc
    granted = set(str(info.get("scope", "")).split())
    missing = auth.missing_scopes(granted)
    if len(missing) == len(auth.SCOPES):
        raise RuntimeError("The access token has none of the read-only Workspace scopes.\n" + auth.setup_instructions(quota_project=quota_project or "YOUR_PROJECT_ID"))
    for scope in missing:  # partial scopes still work: the checks that need the missing one report NotAssessed
        warn(f"The access token lacks {scope} ({auth.SCOPES[scope]}); checks that need it will be reported as not assessed.")

    http = client or WorkspaceClient(provider, quota_project=quota_project)
    directory = Directory(http)
    try:
        customer = directory.customer()
    except ApiError as exc:
        raise RuntimeError(_explain(exc, quota_project)) from exc
    try:
        domains = directory.domains()
    except ApiError:
        domains = []
    names = [str(d["domainName"]) for d in domains if d.get("domainName")]
    primary = next((str(d["domainName"]) for d in domains if d.get("isPrimary")), customer.get("customerDomain") or (names[0] if names else "unknown-domain"))
    # Domain aliases and verified secondary domains also send mail, so email authentication is checked for all of them.
    verified = [str(d["domainName"]) for d in domains if d.get("verified", True) and d.get("domainName")]
    for d in domains:
        verified += [str(a["domainAliasName"]) for a in d.get("domainAliases") or [] if a.get("domainAliasName")]
    unique = list(dict.fromkeys(verified or [primary]))

    ws_options = options or WsOptions(check_dns=check_dns)
    ws_options.check_dns = check_dns and ws_options.check_dns
    ctx = WsContext(client=http, directory=directory, domains=unique, resolver=(resolver or (DohResolver(doh_endpoint) if ws_options.check_dns else None)), options=ws_options)
    return WsSession(ctx=ctx, customer_id=str(customer.get("id", "")), primary_domain=primary, domains=unique, account=str(info.get("email") or "unknown"))
