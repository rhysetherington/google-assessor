"""The only way this package reads Google Workspace: a GET-only HTTPS client for a short list of Google API hosts.

Read-only by construction, the same promise the gcloud gateway makes for Google Cloud: there is no way to ask this client for any
HTTP method other than GET, it refuses any host that is not on the allowlist, and it never follows a redirect off that list. Every
API it talks to is queried with read-only OAuth scopes (see ``auth.SCOPES``), so even a bug could not change a tenant.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Iterator

from ..errors import ApiError

# Admin SDK (Directory, Reports), Cloud Identity (Policy API, SSO profiles), and the older www.googleapis.com APIs.
ALLOWED_HOSTS = frozenset({"admin.googleapis.com", "cloudidentity.googleapis.com", "www.googleapis.com"})

_DISABLED_REASONS = {"accessNotConfigured", "SERVICE_DISABLED"}
_PERMISSION_REASONS = {"forbidden", "insufficientPermissions", "notAuthorized", "PERMISSION_DENIED", "ACCESS_TOKEN_SCOPE_INSUFFICIENT",
                       "insufficient_scope", "domainPolicy"}
_TRANSIENT_REASONS = {"rateLimitExceeded", "userRateLimitExceeded", "quotaExceeded", "backendError", "RESOURCE_EXHAUSTED"}


def classify_http_error(status: int, body: str) -> ApiError:
    """Turn an HTTP error response from a Google API into a categorised ApiError."""
    message, reasons = "", set()
    try:
        err = json.loads(body).get("error", {})
        message = str(err.get("message", ""))
        reasons = {str(e.get("reason", "")) for e in err.get("errors", []) if isinstance(e, dict)}
        reasons |= {str(d.get("reason", "")) for d in err.get("details", []) if isinstance(d, dict)}
        reasons.add(str(err.get("status", "")))
    except (ValueError, AttributeError):
        message = (body or "")[:200]
    text = " ".join(message.split())[:300]
    lower = text.lower()
    if reasons & _DISABLED_REASONS or "has not been used in project" in lower or "api has not been enabled" in lower:
        category = "ApiDisabled"
    elif status == 401:
        category = "Auth"
    elif reasons & _TRANSIENT_REASONS or status in (429, 500, 502, 503, 504):
        category = "Transient"
    elif reasons & _PERMISSION_REASONS or status == 403 or "not authorized" in lower or "insufficient" in lower:
        category = "PermissionDenied"
    elif status == 404:
        category = "NotFound"
    else:
        category = "Other"
    return ApiError(f"HTTP {status}: {text}".strip(), category)


class WorkspaceClient:
    """GET-only client with retry/back-off, pagination and a per-run cache of successes and failures."""

    def __init__(self, token_provider: Callable[[], str], quota_project: "str | None" = None,
                 opener: "Callable[..., Any] | None" = None, sleep: Callable[[float], None] = time.sleep, max_retries: int = 5):
        self._token = token_provider
        self.quota_project = quota_project
        self._open = opener or urllib.request.urlopen
        self._sleep = sleep
        self._max_retries = max_retries
        self._cache: "dict[str, tuple[bool, Any]]" = {}

    # -- raw call ----------------------------------------------------------------------------------------------------
    def get(self, url: str, params: "dict | None" = None) -> dict:
        """GET one URL and return the parsed JSON object. Raises ApiError (with a category) on failure."""
        full = self._build(url, params)
        headers = {"Authorization": f"Bearer {self._token()}", "Accept": "application/json"}
        if self.quota_project:
            headers["x-goog-user-project"] = self.quota_project
        request = urllib.request.Request(full, headers=headers, method="GET")  # the only method this client ever uses
        attempt = 0
        while True:
            try:
                with self._open(request, timeout=60) as response:
                    body = response.read().decode("utf-8")
                return json.loads(body) if body.strip() else {}
            except urllib.error.HTTPError as exc:
                error = classify_http_error(exc.code, exc.read().decode("utf-8", "replace"))
                retry_after = exc.headers.get("Retry-After") if exc.headers else None
            except urllib.error.URLError as exc:
                error, retry_after = ApiError(f"network error: {exc.reason}", "Transient"), None
            if error.category == "Transient" and attempt < self._max_retries:
                attempt += 1
                delay = float(retry_after) if retry_after and retry_after.replace(".", "", 1).isdigit() else 2 ** attempt
                self._sleep(min(delay, 60))
                continue
            raise error

    @staticmethod
    def _build(url: str, params: "dict | None") -> str:
        parts = urllib.parse.urlsplit(url)
        if parts.scheme != "https" or parts.hostname not in ALLOWED_HOSTS:
            raise ValueError(f"Refusing to call {parts.hostname or url!r}: only HTTPS requests to {sorted(ALLOWED_HOSTS)} are allowed.")
        query = urllib.parse.urlencode(params, doseq=True) if params else ""
        return urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path, "&".join(q for q in (parts.query, query) if q), ""))

    # -- helpers used by the checks -----------------------------------------------------------------------------------
    def pages(self, url: str, params: "dict | None" = None, key: "str | None" = None, page_delay: float = 0.0) -> Iterator[dict]:
        """Yield each page of a list response, following nextPageToken. ``key`` names the list field (items by default)."""
        params = dict(params or {})
        while True:
            page = self.get(url, params)
            yield page
            token = page.get("nextPageToken")
            if not token:
                return
            params["pageToken"] = token
            if page_delay:
                self._sleep(page_delay)  # the Policy API rejects requests that arrive back-to-back

    def items(self, url: str, params: "dict | None" = None, key: str = "items", page_delay: float = 0.0) -> "list[dict]":
        out: "list[dict]" = []
        for page in self.pages(url, params, page_delay=page_delay):
            out += page.get(key) or []
        return out

    def cached(self, url: str, params: "dict | None" = None) -> dict:
        """``get`` with a per-run cache of successes AND failures, so each tenant's data is read once however many checks use it."""
        cache_key = self._build(url, params)
        if cache_key not in self._cache:
            try:
                self._cache[cache_key] = (True, self.get(url, params))
            except Exception as exc:  # noqa: BLE001 - cached and re-raised for every caller
                self._cache[cache_key] = (False, exc)
        ok, value = self._cache[cache_key]
        if not ok:
            raise value
        return value
