"""Risk rules over classified Terraform resource changes.

Rules are context-aware: replacing a production database is not the same as
replacing a disposable test instance (doc section 4). Each rule emits a Finding
with a stable rule_id; the policy engine — not these rules — decides the
Pass/Warn/Block outcome.

Rules never read raw attribute values; they reason over resource type, address,
tags, and the planned action only.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from ...findings.models import AnalyzerResult, Severity, Source
from ...findings.normalize import make_finding
from .parser import ChangeKind, ResourceChange, parse_resource_changes


@dataclass
class TerraformRuleConfig:
    """Classification knobs, usually sourced from the policy file."""

    stateful_resource_types: list[str] = field(
        default_factory=lambda: [
            "db_instance",
            "rds",
            "database",
            "sql",
            "disk",
            "volume",
            "bucket",
            "s3_bucket",
            "efs",
            "elasticache",
            "dynamodb_table",
            "persistent",
        ]
    )
    production_markers: list[str] = field(
        default_factory=lambda: ["prod", "production", "prd"]
    )

    def is_stateful(self, rc: ResourceChange) -> bool:
        t = rc.resource_type.lower()
        return any(marker in t for marker in self.stateful_resource_types)

    def is_production(self, rc: ResourceChange) -> bool:
        haystack = " ".join(
            [rc.address.lower(), rc.name.lower(), *rc.tag_values]
        )
        # Word-ish boundary check to avoid matching "reproduce" as "prod".
        import re

        for marker in self.production_markers:
            if re.search(rf"(?<![a-z]){re.escape(marker)}(?![a-z])", haystack):
                return True
        return False


# A rule takes a ResourceChange + config and returns a Finding kwargs dict or None.
Rule = Callable[[ResourceChange, TerraformRuleConfig], dict[str, Any] | None]


def _rule_destroy_prod(rc: ResourceChange, cfg: TerraformRuleConfig):
    if rc.kind not in (ChangeKind.DELETE, ChangeKind.REPLACE):
        return None
    if not cfg.is_production(rc):
        return None
    verb = "destroy" if rc.kind is ChangeKind.DELETE else "replace (destroy + recreate)"
    return dict(
        rule_id="TF-DESTROY-PROD",
        severity=Severity.CRITICAL,
        observation=f"Plan will {verb} a production-tagged resource",
        reason=(
            "Destroying or replacing a production resource can cause downtime "
            "or irreversible data loss."
        ),
        recommendation=(
            "Confirm this is intended, ensure a tested backup/restore path "
            "exists, and consider a create-before-destroy or migration strategy."
        ),
    )


def _rule_delete_stateful(rc: ResourceChange, cfg: TerraformRuleConfig):
    if rc.kind is not ChangeKind.DELETE or not cfg.is_stateful(rc):
        return None
    if cfg.is_production(rc):
        return None  # covered by TF-DESTROY-PROD at higher severity
    return dict(
        rule_id="TF-DELETE-STATEFUL",
        severity=Severity.HIGH,
        observation="Plan will delete a stateful resource",
        reason="Deleting a stateful resource destroys the data it holds.",
        recommendation="Verify the data is disposable or has a retained backup.",
    )


def _rule_replace_stateful(rc: ResourceChange, cfg: TerraformRuleConfig):
    if rc.kind is not ChangeKind.REPLACE or not cfg.is_stateful(rc):
        return None
    if cfg.is_production(rc):
        return None  # covered by TF-DESTROY-PROD
    detail = (
        f" Triggered by: {', '.join(rc.replace_paths)}." if rc.replace_paths else ""
    )
    return dict(
        rule_id="TF-REPLACE-STATEFUL",
        severity=Severity.HIGH,
        observation="Plan will replace a stateful resource" + detail,
        reason=(
            "Replacement destroys and recreates the resource, discarding its "
            "current data/state unless migrated."
        ),
        recommendation=(
            "Check whether an in-place update is possible, or migrate data "
            "before replacement."
        ),
    )


def _rule_delete_generic(rc: ResourceChange, cfg: TerraformRuleConfig):
    if rc.kind is not ChangeKind.DELETE:
        return None
    if cfg.is_stateful(rc) or cfg.is_production(rc):
        return None  # higher-severity rules own these
    return dict(
        rule_id="TF-DELETE-GENERIC",
        severity=Severity.MEDIUM,
        observation="Plan will delete a resource",
        reason="Deleting a resource may remove capability other systems rely on.",
        recommendation="Confirm no dependent systems still require this resource.",
    )


_IAM_HINTS = ("iam", "security_group", "policy", "role", "firewall")


def _rule_iam_broaden(rc: ResourceChange, cfg: TerraformRuleConfig):
    if rc.kind not in (ChangeKind.CREATE, ChangeKind.UPDATE, ChangeKind.REPLACE):
        return None
    t = rc.resource_type.lower()
    if not any(h in t for h in _IAM_HINTS):
        return None
    return dict(
        rule_id="TF-IAM-BROADEN",
        severity=Severity.MEDIUM,
        observation="Plan creates or modifies an access-control resource",
        reason=(
            "Changes to IAM, roles, policies, or security groups can broaden "
            "access and widen the blast radius."
        ),
        recommendation=(
            "Review the effective permissions/ingress for least-privilege."
        ),
    )


_RULES: list[Rule] = [
    _rule_destroy_prod,
    _rule_delete_stateful,
    _rule_replace_stateful,
    _rule_delete_generic,
    _rule_iam_broaden,
]


def analyze(
    resource_changes: list[dict[str, Any]],
    *,
    config: TerraformRuleConfig | None = None,
    format_supported: bool = True,
    format_version: str | None = None,
) -> AnalyzerResult:
    """Run every rule over every classified change and collect findings."""
    cfg = config or TerraformRuleConfig()
    result = AnalyzerResult()

    if not format_supported:
        result.completed = False
        result.incomplete_reasons.append("unsupported_plan_format")
        result.findings.append(
            make_finding(
                rule_id="TF-UNSUPPORTED-FORMAT",
                source=Source.TERRAFORM,
                severity=Severity.HIGH,
                location=f"plan(format_version={format_version})",
                observation="Terraform plan format version is not supported",
                reason="ReleaseProof cannot reliably classify actions in this format.",
                recommendation="Regenerate the plan JSON with a supported Terraform version.",
                evidence={"format_version": format_version},
            )
        )
        return result

    changes = parse_resource_changes(resource_changes)
    for rc in changes:
        for rule in _RULES:
            kwargs = rule(rc, cfg)
            if kwargs is None:
                continue
            result.findings.append(
                make_finding(
                    source=Source.TERRAFORM,
                    location=rc.address,
                    evidence={
                        "resource_type": rc.resource_type,
                        "action": rc.kind.value,
                    },
                    **kwargs,
                )
            )
    return result
