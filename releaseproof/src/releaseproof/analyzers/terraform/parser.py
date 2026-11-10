"""Classify planned resource actions from Terraform plan JSON.

Terraform encodes the planned change for each resource as a list of actions in
``resource_changes[].change.actions``:

    ["no-op"]            -> no change
    ["create"]           -> create
    ["update"]           -> in-place update
    ["delete"]           -> destroy
    ["delete","create"]  -> replace (destroy then create)
    ["create","delete"]  -> replace (create then destroy, create_before_destroy)
    ["read"]             -> data read

We normalise these into a small, explicit ChangeKind so the rules layer never
has to re-interpret raw action arrays.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ChangeKind(str, Enum):
    NOOP = "no-op"
    CREATE = "create"
    UPDATE = "update"
    DELETE = "delete"
    REPLACE = "replace"
    READ = "read"
    UNKNOWN = "unknown"


@dataclass
class ResourceChange:
    address: str
    resource_type: str
    name: str
    provider: str
    kind: ChangeKind
    actions: list[str]
    # Tag values pulled from the planned/before state, lower-cased, for
    # environment classification. Values only — never full attribute maps.
    tag_values: list[str] = field(default_factory=list)
    # Attribute keys that triggered the replacement, if Terraform reported them.
    replace_paths: list[str] = field(default_factory=list)


def _classify(actions: list[str]) -> ChangeKind:
    a = [str(x) for x in actions]
    if a in (["no-op"], []):
        return ChangeKind.NOOP
    if a == ["read"]:
        return ChangeKind.READ
    if a == ["create"]:
        return ChangeKind.CREATE
    if a == ["update"]:
        return ChangeKind.UPDATE
    if a == ["delete"]:
        return ChangeKind.DELETE
    if set(a) == {"delete", "create"}:
        return ChangeKind.REPLACE
    return ChangeKind.UNKNOWN


def _extract_tag_values(change: dict[str, Any]) -> list[str]:
    """Pull tag/label *values* from before+after state for env classification.

    We deliberately take only values from known tag containers, lower-cased,
    and never the whole attribute map (which may hold sensitive values).
    """
    values: list[str] = []
    for state_key in ("after", "before"):
        state = change.get(state_key)
        if not isinstance(state, dict):
            continue
        for tag_key in ("tags", "tags_all", "labels"):
            container = state.get(tag_key)
            if isinstance(container, dict):
                for v in container.values():
                    if isinstance(v, (str, int, float)):
                        values.append(str(v).lower())
    return values


def _extract_replace_paths(rc: dict[str, Any]) -> list[str]:
    paths: list[str] = []
    change = rc.get("change", {})
    for entry in change.get("replace_paths", []) or []:
        if isinstance(entry, list):
            paths.append(".".join(str(x) for x in entry))
        else:
            paths.append(str(entry))
    return paths


def parse_resource_changes(resource_changes: list[dict[str, Any]]) -> list[ResourceChange]:
    """Turn raw plan ``resource_changes`` into normalised ResourceChange objects.

    ``no-op`` and ``read`` changes are dropped — they carry no release risk.
    """
    out: list[ResourceChange] = []
    for rc in resource_changes:
        if not isinstance(rc, dict):
            continue
        change = rc.get("change", {})
        if not isinstance(change, dict):
            continue
        actions = change.get("actions", []) or []
        kind = _classify(list(actions))
        if kind in (ChangeKind.NOOP, ChangeKind.READ):
            continue

        out.append(
            ResourceChange(
                address=str(rc.get("address", "<unknown>")),
                resource_type=str(rc.get("type", "")),
                name=str(rc.get("name", "")),
                provider=str(rc.get("provider_name", "")),
                kind=kind,
                actions=[str(x) for x in actions],
                tag_values=_extract_tag_values(change),
                replace_paths=_extract_replace_paths(rc),
            )
        )
    return out
