"""Errors shared by every data source (gcloud for Google Cloud, HTTPS for Google Workspace).

``category`` lets callers tell "nothing to assess" from "could not assess":
ApiDisabled | PermissionDenied | NotFound | Auth | Transient | Other.
"""

from __future__ import annotations


class ApiError(Exception):
    """A failed read from a Google API or the gcloud CLI."""

    def __init__(self, message: str, category: str = "Other"):
        super().__init__(message)
        self.category = category
