"""Access tokens for Google Workspace APIs, taken from gcloud's Application Default Credentials.

Nothing is stored by this tool. A Super Admin signs in once with `gcloud auth application-default login`, passing an OAuth client
and the read-only scopes below; this module asks gcloud for a short-lived access token each run and checks which scopes it holds,
so a missing scope is explained up front instead of surfacing as a confusing 403 halfway through.

gcloud's own login cannot be used for this: Google blocks the Admin SDK scopes for its built-in client, which is why an OAuth client
from your own Google Cloud project is needed (see ``setup_instructions``).
"""

from __future__ import annotations

import json
import shutil
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Callable, Sequence

from ..errors import ApiError

# Read-only scopes only. (Group settings and licensing have no read-only scope, so they are deliberately not used.)
SCOPES = {
    "https://www.googleapis.com/auth/admin.directory.user.readonly": "users, 2-step verification status, admin flags",
    "https://www.googleapis.com/auth/admin.directory.group.readonly": "groups",
    "https://www.googleapis.com/auth/admin.directory.orgunit.readonly": "organisational units",
    "https://www.googleapis.com/auth/admin.directory.domain.readonly": "domains (SPF, DKIM and DMARC are checked for each)",
    "https://www.googleapis.com/auth/admin.directory.rolemanagement.readonly": "admin roles and who holds them",
    "https://www.googleapis.com/auth/admin.directory.customer.readonly": "customer (tenant) ID",
    "https://www.googleapis.com/auth/admin.reports.audit.readonly": "audit log availability",
    "https://www.googleapis.com/auth/cloud-identity.policies.readonly": "admin-console settings (the Policy API)",
    "https://www.googleapis.com/auth/cloud-identity.inboundsso.readonly": "SSO profiles and assignments",
}
APIS = ["admin.googleapis.com", "cloudidentity.googleapis.com"]

Runner = Callable[[Sequence[str]], "tuple[int, str, str]"]


def _run(args: Sequence[str]) -> "tuple[int, str, str]":
    done = subprocess.run(list(args), capture_output=True, text=True, timeout=120, check=False)
    return done.returncode, done.stdout, done.stderr


def setup_instructions(client_id_file: str = "client_secret.json", quota_project: str = "YOUR_PROJECT_ID") -> str:
    """The one-time commands a Super Admin runs. The tool prints these; it never runs them itself (they open a browser sign-in)."""
    scopes = ",".join(SCOPES)
    return (
        "One-time setup (about five minutes, done by a Google Workspace Super Admin):\n"
        f"  1. In a Google Cloud project you control, enable the APIs:\n"
        f"       gcloud services enable {' '.join(APIS)} --project {quota_project}\n"
        "  2. In that project, create an OAuth client ID of type 'Desktop app' (Console > APIs & Services > Credentials) and download its JSON\n"
        f"     as {client_id_file}. (If asked, set the OAuth consent screen to Internal.)\n"
        "  3. Sign in with the read-only scopes:\n"
        f"       gcloud auth application-default login --client-id-file={client_id_file} --scopes={scopes}\n"
        f"  4. Run the assessment with --quota-project {quota_project}.\n"
        "Sign out afterwards with: gcloud auth application-default revoke")


class AdcTokenProvider:
    """Callable returning a cached access token from `gcloud auth application-default print-access-token`."""

    def __init__(self, gcloud_path: "str | None" = None, runner: "Runner | None" = None,
                 clock: Callable[[], float] = time.monotonic, ttl: float = 1800):
        self._path = gcloud_path or shutil.which("gcloud")
        self._runner = runner or _run
        self._clock = clock
        self._ttl = ttl
        self._token: "str | None" = None
        self._fetched = 0.0

    def __call__(self) -> str:
        if self._token and self._clock() - self._fetched < self._ttl:
            return self._token
        if not self._path:
            raise ApiError("The Google Cloud CLI (gcloud) was not found on PATH, and it is needed to get a Workspace access token.", "Auth")
        code, out, err = self._runner([self._path, "auth", "application-default", "print-access-token"])
        if code != 0 or not out.strip():
            raise ApiError("No Application Default Credentials. " + (" ".join(err.split())[:200] if err else ""), "Auth")
        self._token, self._fetched = out.strip(), self._clock()
        return self._token


def token_info(token: str, post: "Callable[..., dict] | None" = None) -> dict:
    """What Google says about an access token (its scopes and the account it belongs to). The token goes in the POST body, not the URL."""
    def default_post(url: str, data: dict) -> dict:
        request = urllib.request.Request(url, data=urllib.parse.urlencode(data).encode(), method="POST",
                                         headers={"Content-Type": "application/x-www-form-urlencoded"})
        try:
            with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310 - fixed https URL below
                return json.loads(response.read().decode())
        except urllib.error.HTTPError as exc:
            raise ApiError(f"tokeninfo returned HTTP {exc.code}", "Auth") from exc
        except urllib.error.URLError as exc:
            raise ApiError(f"network error: {exc.reason}", "Transient") from exc
    return (post or default_post)("https://oauth2.googleapis.com/tokeninfo", {"access_token": token})


def token_scopes(token: str, post: "Callable[..., dict] | None" = None) -> "set[str]":
    """The scopes an access token actually holds."""
    return set(str(token_info(token, post).get("scope", "")).split())


def write_capable_scopes(granted: "set[str]") -> "list[str]":
    """Scopes in a token that could change things: the broad cloud-platform scope, and any Workspace admin scope that is not read-only.

    The assessor only ever makes GET requests, but a token that *could* write is a credential worth not having lying around, and it
    usually means the sign-in was done without the read-only scopes (a plain `gcloud auth application-default login`).
    """
    workspace_admin = ("admin.directory", "admin.reports", "cloud-identity", "apps.")
    return sorted(s for s in granted if s.endswith("/cloud-platform") or (any(w in s for w in workspace_admin) and not s.endswith(".readonly")))


def missing_scopes(granted: "set[str]") -> "list[str]":
    return [s for s in SCOPES if s not in granted]
