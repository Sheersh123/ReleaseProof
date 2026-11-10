"""Load and validate the versioned YAML policy (doc section 7).

The policy is version-controlled and reviewable. The analyzer config
(stateful/production classification) is carried on the same object so the whole
decision surface lives in one reviewable file.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any

import yaml

from ..findings.models import Action

SUPPORTED_POLICY_VERSIONS = {1}


class PolicyError(Exception):
    """Raised when a policy file is missing or structurally invalid."""


@dataclass
class Policy:
    version: int
    terraform_rules: dict[str, Action]
    postgres_rules: dict[str, Action]
    severity_defaults: dict[str, Action]
    analysis: dict[str, str]
    stateful_resource_types: list[str] = field(default_factory=list)
    production_markers: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)

    def action_for_rule(self, rule_id: str, source: str) -> Action | None:
        table = self.terraform_rules if source == "terraform" else self.postgres_rules
        return table.get(rule_id)

    def action_for_severity(self, severity: str) -> Action:
        return self.severity_defaults.get(severity, Action.WARN)

    def analysis_action(self, reason_code: str) -> str:
        # Returns one of: block | warn | pass | incomplete
        return self.analysis.get(reason_code, "incomplete")


def _coerce_action_map(raw: Any, where: str) -> dict[str, Action]:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise PolicyError(f"'{where}' must be a mapping of rule-id to action.")
    out: dict[str, Action] = {}
    for rule_id, val in raw.items():
        # Support both `rule: block` and `rule: {severity: block}` shorthand.
        if isinstance(val, dict):
            val = val.get("severity") or val.get("action")
        try:
            out[str(rule_id)] = Action(str(val).strip().lower())
        except ValueError as exc:
            raise PolicyError(
                f"Invalid action '{val}' for '{rule_id}' in '{where}'. "
                f"Expected one of: {', '.join(a.value for a in Action)}."
            ) from exc
    return out


def load_policy(path: str | Path | None = None) -> Policy:
    """Load a policy from ``path``, or the packaged defaults when path is None."""
    if path is None:
        text = resources.files("releaseproof.config").joinpath("defaults.yml").read_text(
            encoding="utf-8"
        )
    else:
        p = Path(path)
        if not p.exists():
            raise PolicyError(f"Policy file not found: {p}")
        text = p.read_text(encoding="utf-8")

    try:
        data = yaml.safe_load(text) or {}
    except yaml.YAMLError as exc:
        raise PolicyError(f"Policy file is not valid YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise PolicyError("Policy root must be a mapping.")

    version = data.get("version")
    if version not in SUPPORTED_POLICY_VERSIONS:
        raise PolicyError(
            f"Unsupported policy version {version!r}; supported: "
            f"{sorted(SUPPORTED_POLICY_VERSIONS)}."
        )

    policies = data.get("policies", {})
    if not isinstance(policies, dict):
        raise PolicyError("'policies' must be a mapping.")

    analysis = policies.get("analysis", {}) or {}
    valid_analysis = {"block", "warn", "pass", "incomplete"}
    for key, val in analysis.items():
        if str(val).lower() not in valid_analysis:
            raise PolicyError(
                f"Invalid analysis action '{val}' for '{key}'. "
                f"Expected one of: {', '.join(sorted(valid_analysis))}."
            )

    return Policy(
        version=int(version),
        terraform_rules=_coerce_action_map(
            policies.get("terraform"), "policies.terraform"
        ),
        postgres_rules=_coerce_action_map(
            policies.get("postgres"), "policies.postgres"
        ),
        severity_defaults=_coerce_action_map(
            policies.get("severity_defaults"), "policies.severity_defaults"
        ),
        analysis={k: str(v).lower() for k, v in analysis.items()},
        stateful_resource_types=list(data.get("stateful_resource_types", []) or []),
        production_markers=list(data.get("production_markers", []) or []),
        raw=data,
    )
