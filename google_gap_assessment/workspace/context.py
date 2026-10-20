"""Everything a Workspace check needs, with lazy, memoised reads: the HTTP client, the directory, the settings and the DNS resolver."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Optional

from .client import WorkspaceClient
from .directory import Directory
from .mail_dns import DohResolver
from .policy import PolicySet, load_policies


@dataclass
class WsOptions:
    """Settings that change how Workspace checks decide."""
    check_dns: bool = True            # False (--no-dns): SPF/DKIM/DMARC are not looked up and those checks are NotAssessed
    max_super_admins: int = 8         # CISA SCuBA: between two and eight super admin accounts
    min_super_admins: int = 2
    stale_days: int = 90              # accounts with no sign-in for this long count as stale


@dataclass
class WsContext:
    client: WorkspaceClient
    directory: Directory
    resolver: Optional[DohResolver] = None
    options: WsOptions = field(default_factory=WsOptions)
    clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc)   # injectable so tests can fix "now"
    _policies: "Optional[PolicySet]" = None
    _policy_error: "Optional[Exception]" = None

    def policies(self) -> PolicySet:
        """Admin-console settings, fetched once per run. A failure is remembered and re-raised for every check that needs them."""
        if self._policy_error is not None:
            raise self._policy_error
        if self._policies is None:
            try:
                self._policies = load_policies(self.client)
            except Exception as exc:  # noqa: BLE001
                self._policy_error = exc
                raise
        return self._policies
