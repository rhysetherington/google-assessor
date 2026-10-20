"""Turn --project-id / --folder-id / --organization-id into the list of projects to assess."""

from __future__ import annotations

import sys

from .gcloud import Gcloud
from ..validation import is_project_id


def project_detail(gcloud: Gcloud, project_id: str) -> "dict | None":
    """Confirm a project exists and return its number, display name, state and parent; None when it cannot be read."""
    try:
        p = gcloud.get_one("projects describe", [project_id])
    except Exception as exc:  # noqa: BLE001 - skipped with a warning, not fatal for the others
        print(f"WARNING: project '{project_id}' cannot be read and is skipped: {exc}", file=sys.stderr)
        return None
    parent = p.get("parent") or {}
    return {"ProjectId": str(p.get("projectId", project_id)), "ProjectNumber": str(p.get("projectNumber", "")),
            "Name": str(p.get("name", "")), "State": str(p.get("lifecycleState", "")),
            "ParentType": str(parent.get("type", "")), "ParentId": str(parent.get("id", ""))}


def resolve_scope(gcloud: Gcloud, project_ids: "list[str]", folder_id: "str | None" = None,
                  organization_id: "str | None" = None) -> "list[dict]":
    """Projects to assess. A folder or organisation expands to the projects directly under it (nested folders are not followed)."""
    ids = list(project_ids or [])
    for parent_type, parent_id in (("folder", folder_id), ("organization", organization_id)):
        if not parent_id:
            continue
        found = gcloud.get_list("projects list", [f"--filter=parent.type={parent_type} AND parent.id={parent_id} AND lifecycleState=ACTIVE"])
        if not found:
            print(f"WARNING: no active projects found directly under {parent_type} {parent_id} (or no permission to list them).", file=sys.stderr)
        ids += [str(p["projectId"]) for p in found if p.get("projectId")]

    details = []
    for project_id in dict.fromkeys(ids):
        d = project_detail(gcloud, project_id)
        if d is None:
            continue
        if d["State"] and d["State"] != "ACTIVE":
            print(f"WARNING: project '{project_id}' is {d['State']} and is skipped.", file=sys.stderr)
            continue
        details.append(d)
    if not details:
        raise RuntimeError("None of the requested projects could be read. Check the project IDs and that the signed-in account can view them.")
    return details


def prompt_for_projects() -> "list[str]":
    """Ask for project IDs instead of relying on a value stored in a script or file."""
    if not sys.stdin.isatty():
        raise RuntimeError("No --project-id, --folder-id or --organization-id supplied and the session is not interactive; pass one explicitly.")
    answer = input("Project ID(s) to assess (comma separate for several): ")
    projects = [p for p in answer.replace(";", ",").replace(" ", ",").split(",") if p]
    if not projects:
        raise RuntimeError("No project supplied.")
    for p in projects:
        if not is_project_id(p):
            raise RuntimeError(f"'{p}' is not a project ID.")
    return projects
