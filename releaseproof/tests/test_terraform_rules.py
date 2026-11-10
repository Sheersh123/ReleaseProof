"""Tests for the Terraform analyzer: classification + risk rules."""
import json

from releaseproof.analyzers.terraform import rules as tf_rules
from releaseproof.analyzers.terraform.parser import ChangeKind, parse_resource_changes
from releaseproof.inputs.terraform_plan import load_plan


def _rule_ids(result):
    return {f.rule_id for f in result.findings}


def _by_location(result):
    out = {}
    for f in result.findings:
        out.setdefault(f.location, set()).add(f.rule_id)
    return out


def test_classify_actions():
    changes = parse_resource_changes(
        [
            {"address": "a", "type": "t", "name": "a", "change": {"actions": ["create"]}},
            {"address": "b", "type": "t", "name": "b", "change": {"actions": ["update"]}},
            {"address": "c", "type": "t", "name": "c", "change": {"actions": ["delete"]}},
            {"address": "d", "type": "t", "name": "d", "change": {"actions": ["delete", "create"]}},
            {"address": "e", "type": "t", "name": "e", "change": {"actions": ["no-op"]}},
            {"address": "f", "type": "t", "name": "f", "change": {"actions": ["read"]}},
        ]
    )
    kinds = {c.address: c.kind for c in changes}
    # no-op and read are dropped.
    assert "e" not in kinds and "f" not in kinds
    assert kinds["a"] is ChangeKind.CREATE
    assert kinds["b"] is ChangeKind.UPDATE
    assert kinds["c"] is ChangeKind.DELETE
    assert kinds["d"] is ChangeKind.REPLACE


def test_safe_plan_has_no_findings(tf_fixtures):
    plan = load_plan(tf_fixtures / "safe_plan.json")
    result = tf_rules.analyze(plan.resource_changes)
    assert result.findings == []
    assert result.completed is True


def test_unsafe_plan_flags_expected_rules(tf_fixtures):
    plan = load_plan(tf_fixtures / "unsafe_plan.json")
    result = tf_rules.analyze(plan.resource_changes)
    by_loc = _by_location(result)

    # Production DB replacement is the top-severity destroy-prod rule.
    assert "TF-DESTROY-PROD" in by_loc["aws_db_instance.prod_primary"]
    # Non-prod stateful replacement is a warn-level replace.
    assert "TF-REPLACE-STATEFUL" in by_loc["aws_db_instance.staging_cache"]
    # Dev stateful delete.
    assert "TF-DELETE-STATEFUL" in by_loc["aws_ebs_volume.scratch"]
    # IAM change.
    assert "TF-IAM-BROADEN" in by_loc["aws_iam_policy.app"]
    # Generic (non-stateful, non-prod) delete.
    assert "TF-DELETE-GENERIC" in by_loc["aws_cloudwatch_log_group.old"]


def test_prod_rule_takes_precedence_over_generic_stateful(tf_fixtures):
    """A prod stateful replace should only emit TF-DESTROY-PROD, not also the
    generic stateful-replace rule (avoids double-counting)."""
    plan = load_plan(tf_fixtures / "unsafe_plan.json")
    result = tf_rules.analyze(plan.resource_changes)
    prod_rules = _by_location(result)["aws_db_instance.prod_primary"]
    assert prod_rules == {"TF-DESTROY-PROD"}


def test_production_detection_is_word_bounded():
    cfg = tf_rules.TerraformRuleConfig()
    from releaseproof.analyzers.terraform.parser import ResourceChange

    reproduce = ResourceChange(
        address="aws_instance.reproduce_env",
        resource_type="aws_instance",
        name="reproduce_env",
        provider="aws",
        kind=ChangeKind.DELETE,
        actions=["delete"],
    )
    # "reproduce" must not match "prod".
    assert cfg.is_production(reproduce) is False

    prod = ResourceChange(
        address="aws_db_instance.prod_db",
        resource_type="aws_db_instance",
        name="prod_db",
        provider="aws",
        kind=ChangeKind.DELETE,
        actions=["delete"],
    )
    assert cfg.is_production(prod) is True


def test_unsupported_format_is_incomplete(tf_fixtures):
    plan = load_plan(tf_fixtures / "unsupported_plan.json")
    assert plan.format_supported is False
    result = tf_rules.analyze(
        plan.resource_changes,
        format_supported=plan.format_supported,
        format_version=plan.format_version,
    )
    assert result.completed is False
    assert "unsupported_plan_format" in result.incomplete_reasons
    assert "TF-UNSUPPORTED-FORMAT" in _rule_ids(result)


def test_evidence_contains_no_raw_tag_maps(tf_fixtures):
    plan = load_plan(tf_fixtures / "unsafe_plan.json")
    result = tf_rules.analyze(plan.resource_changes)
    for f in result.findings:
        # Evidence should be small and string-valued, never nested dicts.
        for v in f.evidence.values():
            assert isinstance(v, str)
