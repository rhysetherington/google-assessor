"""Access tokens for Google Workspace APIs.

Two ways to get one:

* **Browser sign-in (recommended, ``BrowserTokenProvider``).** The tool signs the Super Admin in itself with the standard OAuth
  "installed app" flow (PKCE, loopback redirect) using an OAuth client file from your own Google Cloud project. It asks for the
  read-only scopes below and nothing else, keeps the token in memory only, and revokes it at the end of the run. Nothing is stored.
* **gcloud Application Default Credentials (``AdcTokenProvider``).** Works, but gcloud refuses to create ADC without the broad
  ``cloud-platform`` scope, so that token can write to Google Cloud. The tool warns when it sees one.

Either way the token's scopes are checked up front, so a missing scope is explained before the run instead of surfacing as a 403.
"""

from __future__ import annotations

import base64
import hashlib
import http.server
import json
import secrets
import shutil
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from pathlib import Path
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


def setup_instructions(client_id_file: str = "~/.config/client_secret.json", quota_project: str = "YOUR_PROJECT_ID") -> str:
    """The one-time setup a Super Admin does. The sign-in itself is done by this tool (it opens your browser)."""
    return (
        "One-time setup (about five minutes, done by a Google Workspace Super Admin):\n"
        "  1. In the Google Cloud Console, create a project you control (any name) and enable these APIs under APIs & Services > Library:\n"
        f"       {' and '.join(APIS)}   (or: gcloud services enable {' '.join(APIS)} --project {quota_project})\n"
        "  2. APIs & Services > OAuth consent screen: choose user type 'Internal', give it a name and your e-mail, and save.\n"
        "  3. APIs & Services > Credentials > Create credentials > OAuth client ID > 'Desktop app'. Download the JSON and save it as\n"
        f"     {client_id_file} (outside any git folder; it is git-ignored here if you keep it in this one).\n"
        "  4. Run the assessment; a browser window opens for you to sign in as the Super Admin:\n"
        f"       python3 -m google_gap_assessment --scope workspace --oauth-client-file {client_id_file}\n"
        "The tool asks only for these read-only permissions, keeps the sign-in in memory, and revokes it when the run ends:\n"
        + "\n".join(f"       {name.rsplit('/', 1)[-1]:<28} {why}" for name, why in SCOPES.items()))


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


# --- browser sign-in -----------------------------------------------------------------------------------------------------------
AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URL = "https://oauth2.googleapis.com/token"
REVOKE_URL = "https://oauth2.googleapis.com/revoke"
IDENTITY_SCOPES = ("openid", "https://www.googleapis.com/auth/userinfo.email")  # who signed in, for the report; read nothing else


def load_client_file(path: "str | Path") -> "tuple[str, str]":
    """(client_id, client_secret) from the JSON that the Console gives for a Desktop-app OAuth client. The secret is never printed."""
    try:
        data = json.loads(Path(path).expanduser().read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise ApiError(f"OAuth client file not found: {path}. Create a Desktop-app OAuth client in the Cloud Console and download its JSON "
                       "(see --setup-help).", "Auth") from None
    except ValueError as exc:
        raise ApiError(f"{path} is not valid JSON: {exc}", "Auth") from exc
    client = data.get("installed")
    if not isinstance(client, dict) or not client.get("client_id") or not client.get("client_secret"):
        raise ApiError(f"{path} is not a Desktop-app OAuth client file (it should start with {{\"installed\": ...}}). "
                       "Create the client with application type 'Desktop app'.", "Auth")
    return str(client["client_id"]), str(client["client_secret"])


def pkce_challenge(verifier: str) -> str:
    """The S256 code challenge for a PKCE verifier (RFC 7636)."""
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")


def wait_for_redirect(server: http.server.HTTPServer, state: str, timeout: float = 300) -> str:
    """Serve the loopback redirect until Google's callback arrives and return its authorisation code.

    Requests that are not the callback (a favicon, a stray probe) are ignored; a callback with the wrong ``state`` is refused, which
    stops another page on this machine from feeding the tool a code of its own.
    """
    result: "dict[str, str]" = {}

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802 - http.server naming
            query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
            if "state" not in query and "error" not in query:
                self.send_response(404); self.end_headers(); return
            if query.get("state", [""])[0] != state:
                self.send_response(400); self.end_headers(); self.wfile.write(b"State mismatch. Close this tab and run the tool again."); return
            result.update({k: v[0] for k, v in query.items()})
            self.send_response(200); self.send_header("Content-Type", "text/html; charset=utf-8"); self.end_headers()
            self.wfile.write(b"<html><body><h3>Signed in.</h3><p>You can close this tab and return to the terminal.</p></body></html>")

        def log_message(self, *args):  # keep the authorisation code out of any log
            pass

    server.RequestHandlerClass = Handler
    server.timeout = 1
    deadline = time.monotonic() + timeout
    while not result and time.monotonic() < deadline:
        server.handle_request()
    if not result:
        raise ApiError(f"No sign-in arrived within {int(timeout)} seconds.", "Auth")
    if "error" in result:
        raise ApiError(f"Google refused the sign-in: {result['error']}" + (f" ({result.get('error_description')})" if result.get("error_description") else ""), "Auth")
    if "code" not in result:
        raise ApiError("The sign-in redirect carried no authorisation code.", "Auth")
    return result["code"]


def _post_form(url: str, data: dict) -> dict:
    request = urllib.request.Request(url, data=urllib.parse.urlencode(data).encode(), method="POST",
                                     headers={"Content-Type": "application/x-www-form-urlencoded"})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310 - fixed https URLs above
            body = response.read().decode()
            return json.loads(body) if body.strip() else {}
    except urllib.error.HTTPError as exc:
        try:
            detail = json.loads(exc.read().decode()).get("error_description") or "rejected"
        except ValueError:
            detail = "rejected"
        finally:
            exc.close()
        raise ApiError(f"Google's token endpoint returned HTTP {exc.code}: {detail}", "Auth") from exc
    except urllib.error.URLError as exc:
        raise ApiError(f"network error: {exc.reason}", "Transient") from exc


class BrowserTokenProvider:
    """Signs the admin in through the browser on first use and hands out the access token. In memory only; ``revoke`` ends the grant."""

    def __init__(self, client_id: str, client_secret: str, scopes: "Sequence[str] | None" = None,
                 open_browser: Callable[[str], object] = webbrowser.open, post: "Callable[[str, dict], dict] | None" = None,
                 show: Callable[[str], None] = print, clock: Callable[[], float] = time.monotonic, timeout: float = 300):
        self._id, self._secret = client_id, client_secret
        self._scopes = list(IDENTITY_SCOPES) + list(scopes if scopes is not None else SCOPES)
        self._open, self._post, self._show, self._clock, self._timeout = open_browser, post or _post_form, show, clock, timeout
        self._token: "str | None" = None
        self._expires = 0.0

    def __call__(self) -> str:
        if self._token is None:
            self._sign_in()
        elif self._clock() >= self._expires:
            raise ApiError("The sign-in expired (tokens last an hour). Run the tool again.", "Auth")
        return self._token  # type: ignore[return-value]

    def _sign_in(self) -> None:
        verifier = secrets.token_urlsafe(64)
        state = secrets.token_urlsafe(24)
        server = http.server.HTTPServer(("127.0.0.1", 0), http.server.BaseHTTPRequestHandler)  # loopback only, a free port
        try:
            redirect = f"http://127.0.0.1:{server.server_address[1]}"
            url = AUTH_URL + "?" + urllib.parse.urlencode({
                "client_id": self._id, "redirect_uri": redirect, "response_type": "code", "scope": " ".join(self._scopes),
                "state": state, "code_challenge": pkce_challenge(verifier), "code_challenge_method": "S256", "prompt": "select_account"})
            self._show("Opening your browser to sign in as the Google Workspace Super Admin. If it does not open, visit:\n  " + url)
            self._open(url)
            code = wait_for_redirect(server, state, self._timeout)
        finally:
            server.server_close()
        reply = self._post(TOKEN_URL, {"code": code, "client_id": self._id, "client_secret": self._secret, "redirect_uri": redirect,
                                       "grant_type": "authorization_code", "code_verifier": verifier})
        if not reply.get("access_token"):
            raise ApiError("Google did not return an access token.", "Auth")
        self._token = str(reply["access_token"])
        self._expires = self._clock() + max(60.0, float(reply.get("expires_in", 3600)) - 120)  # refresh margin; no refresh token is requested

    def revoke(self) -> bool:
        """End the grant at Google and forget the token. Returns True when Google accepted the revocation."""
        token, self._token = self._token, None
        if not token:
            return False
        try:
            self._post(REVOKE_URL, {"token": token})
            return True
        except ApiError:
            return False
