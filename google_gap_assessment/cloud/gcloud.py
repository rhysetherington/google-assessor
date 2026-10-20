"""The only way this package talks to Google Cloud: the gcloud CLI, through ``Gcloud.run``.

``Gcloud.run`` refuses any command whose last word is not a read-only verb, so a typo or a future
edit cannot change a resource. Output is requested as JSON and never written to disk here.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time
from typing import Any, Callable, Sequence

from ..errors import ApiError

# gcloud commands end in a verb ("compute instances LIST"). Only these three verbs read without side effects.
READ_ONLY_VERBS = ("list", "describe", "get-iam-policy")

# A runner takes the full argument list and returns (exit_code, stdout, stderr). Tests inject a fake one.
Runner = Callable[[Sequence[str]], "tuple[int, str, str]"]


class GcloudError(ApiError):
    """A failed gcloud call. ``category`` lets callers tell "nothing to assess" from "could not assess"."""


def is_read_only(command: "str | Sequence[str]") -> bool:
    """True when the command words (no flags, no resource names) end in a read-only verb."""
    words = command.split() if isinstance(command, str) else [w for part in command for w in part.split()]
    if not words:
        return False
    # Flags belong in ``arguments``; a flag among the command words could hide a different verb.
    if any(w.startswith("-") for w in words):
        return False
    return words[-1] in READ_ONLY_VERBS


def classify_error(stderr: str) -> GcloudError:
    """Turn gcloud's stderr into a categorised error."""
    text = stderr or ""
    category = "Other"
    # SERVICE_DISABLED usually arrives together with PERMISSION_DENIED, so it is tested first.
    if re.search(r"SERVICE_DISABLED|has not been used in project|API \[[^\]]+\] not enabled|it is disabled", text):
        category = "ApiDisabled"
    elif re.search(r"RESOURCE_EXHAUSTED|rateLimitExceeded|Quota exceeded|HTTPError 429|HTTPError 503|Backend Error|temporarily unavailable", text):
        category = "Transient"
    elif re.search(r"PERMISSION_DENIED|does not have .*permission|HTTPError 403|Forbidden|Permission .* denied", text):
        category = "PermissionDenied"
    elif re.search(r"NOT_FOUND|was not found|HTTPError 404|Not found", text):
        category = "NotFound"
    elif re.search(r"Reauthentication|gcloud auth login|invalid_grant|do not currently have an active account", text):
        category = "Auth"
    summary = re.sub(r"\s+", " ", re.sub(r"(?m)^ERROR:\s*\(gcloud[^)]*\)\s*", "", text)).strip()
    if len(summary) > 300:
        summary = summary[:300] + "..."
    return GcloudError(summary, category)


def _subprocess_runner(args: Sequence[str]) -> "tuple[int, str, str]":
    # A list of arguments with no shell: nothing a project name contains can be interpreted as a command.
    env = dict(os.environ, CLOUDSDK_CORE_DISABLE_PROMPTS="1", CLOUDSDK_CORE_DISABLE_USAGE_REPORTING="true")
    done = subprocess.run(list(args), capture_output=True, text=True, env=env, timeout=300, check=False)
    return done.returncode, done.stdout, done.stderr


class Gcloud:
    """Runs read-only gcloud commands and caches the answers for one assessment run."""

    def __init__(self, path: "str | None" = None, impersonate: "str | None" = None,
                 runner: "Runner | None" = None, sleep: Callable[[float], None] = time.sleep):
        self.path = path or shutil.which("gcloud")
        self.impersonate = impersonate
        self._runner = runner or _subprocess_runner
        self._sleep = sleep
        self._cache: "dict[str, tuple[bool, Any]]" = {}

    # -- raw call ---------------------------------------------------------------------------------------------------
    def run(self, command: str, arguments: Sequence[str] = (), project: "str | None" = None,
            max_retries: int = 4, impersonate: bool = True) -> Any:
        """Run one read-only command and return the parsed JSON (``None`` for empty output)."""
        words = command.split()
        if not is_read_only(words):
            raise ValueError(f"Refusing to run 'gcloud {command}': only read-only commands (list, describe, get-iam-policy) are allowed.")
        if not self.path:
            raise GcloudError("The Google Cloud CLI (gcloud) was not found on PATH.", "Other")
        args = [self.path, *words, *map(str, arguments)]
        if project:
            args.append(f"--project={project}")
        if self.impersonate and impersonate:
            args.append(f"--impersonate-service-account={self.impersonate}")
        args += ["--format=json", "--quiet"]

        attempt = 0
        while True:
            code, out, err = self._runner(args)
            if code == 0:
                break
            error = classify_error(err)
            if error.category == "Transient" and attempt < max_retries:
                attempt += 1
                self._sleep(2 ** attempt)  # exponential back-off: 2, 4, 8, 16 seconds
                continue
            raise error
        if not out.strip():
            return None
        return json.loads(out)

    # -- cached calls used by the checks ---------------------------------------------------------------------------
    def get(self, command: str, arguments: Sequence[str] = (), project: "str | None" = None) -> Any:
        """``run`` with a per-run cache of successes AND failures, so each project's data is read once however many checks use it."""
        key = f"{project}|{command}|{' '.join(map(str, arguments))}"
        if key not in self._cache:
            try:
                self._cache[key] = (True, self.run(command, arguments, project))
            except Exception as exc:  # noqa: BLE001 - cached and re-raised for every caller
                self._cache[key] = (False, exc)
        ok, value = self._cache[key]
        if not ok:
            raise value
        return value

    def get_list(self, command: str, arguments: Sequence[str] = (), project: "str | None" = None) -> list:
        """Like ``get`` but always a list: gcloud prints nothing for an empty result and one object for a single one."""
        value = self.get(command, arguments, project)
        if value is None:
            return []
        return value if isinstance(value, list) else [value]

    def get_one(self, command: str, arguments: Sequence[str] = (), project: "str | None" = None) -> dict:
        """Like ``get`` but always a dict (empty when gcloud printed nothing)."""
        value = self.get(command, arguments, project)
        if isinstance(value, list):
            return value[0] if value else {}
        return value or {}
