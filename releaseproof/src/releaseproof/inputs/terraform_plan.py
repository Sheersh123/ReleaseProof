"""Load and validate a Terraform plan in machine-readable JSON form.

The plan JSON is produced by the customer's existing workflow, e.g.::

    terraform show -json tfplan.binary > plan.json

We never run ``terraform apply`` or touch state. We only read the JSON.
Sensitive values can appear in a plan, so the raw document is kept in memory,
never echoed, and never written to the report (see findings.normalize.redact).
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# Terraform plan format versions we know how to read. The structure of
# `resource_changes[].change.actions` has been stable across these.
SUPPORTED_FORMAT_VERSIONS = {"0.1", "0.2", "1.0", "1.1", "1.2"}


class PlanInputError(Exception):
    """Raised when the plan is missing, unreadable, or malformed.

    Callers map this to an "Analysis Incomplete" result — never a Pass.
    """

    def __init__(self, message: str, reason_code: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code


@dataclass
class TerraformPlan:
    """A validated wrapper around parsed plan JSON."""

    format_version: str
    terraform_version: str | None
    resource_changes: list[dict[str, Any]]
    raw: dict[str, Any]
    format_supported: bool


def load_plan(path: str | Path) -> TerraformPlan:
    """Read, parse, and structurally validate a Terraform plan JSON file.

    Raises PlanInputError (reason ``missing_terraform_plan`` /
    ``analyzer_error``) on fatal problems. An unknown-but-parseable format
    version is *not* fatal here: it is surfaced via ``format_supported=False``
    so the analyzer can emit an incomplete finding rather than crash.
    """
    p = Path(path)
    if not p.exists():
        raise PlanInputError(
            f"Terraform plan not found: {p}", reason_code="missing_terraform_plan"
        )
    if not p.is_file():
        raise PlanInputError(
            f"Terraform plan path is not a file: {p}",
            reason_code="missing_terraform_plan",
        )

    try:
        text = p.read_text(encoding="utf-8")
    except OSError as exc:
        raise PlanInputError(
            f"Could not read Terraform plan: {exc}", reason_code="analyzer_error"
        ) from exc

    if not text.strip():
        raise PlanInputError(
            "Terraform plan file is empty", reason_code="missing_terraform_plan"
        )

    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        # Do not include the raw text in the message — it may hold secrets.
        raise PlanInputError(
            f"Terraform plan is not valid JSON (line {exc.lineno}, col {exc.colno})",
            reason_code="analyzer_error",
        ) from exc

    if not isinstance(data, dict):
        raise PlanInputError(
            "Terraform plan JSON root is not an object", reason_code="analyzer_error"
        )

    format_version = str(data.get("format_version", "")).strip()
    if not format_version:
        raise PlanInputError(
            "Terraform plan JSON missing 'format_version' — is this `terraform "
            "show -json` output?",
            reason_code="analyzer_error",
        )

    resource_changes = data.get("resource_changes", [])
    if not isinstance(resource_changes, list):
        raise PlanInputError(
            "Terraform plan 'resource_changes' is not a list",
            reason_code="analyzer_error",
        )

    return TerraformPlan(
        format_version=format_version,
        terraform_version=data.get("terraform_version"),
        resource_changes=resource_changes,
        raw=data,
        format_supported=format_version in SUPPORTED_FORMAT_VERSIONS,
    )
