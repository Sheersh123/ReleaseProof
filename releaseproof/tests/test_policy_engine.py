"""Tests for the policy loader and deterministic evaluator."""
import pytest

from releaseproof.findings.models import Action, Decision, Severity, Source
from releaseproof.findings.normalize import make_finding
from releaseproof.policy.evaluator import evaluate
from releaseproof.policy.loader import PolicyError, load_policy


def _finding(rule_id, source=Source.POSTGRES, severity=Severity.HIGH):
    return make_finding(
        rule_id=rule_id,
        source=source,
        severity=severity,
        location="x",
        observation="o",
        reason="r",
        recommendation="rec",
    )


def test_default_policy_loads():
    p = load_policy()
    assert p.version == 1
    assert p.action_for_rule("PG-DROP-TABLE", "postgres") is Action.BLOCK


def test_pass_when_no_findings():
    ev = evaluate([], load_policy())
    assert ev.decision is Decision.PASS
    assert ev.exit_code == 0


def test_block_beats_warn():
    policy = load_policy()
    findings = [
        _finding("PG-ADD-INDEX-NON-CONCURRENT"),  # warn
        _finding("PG-DROP-TABLE"),  # block
    ]
    ev = evaluate(findings, policy)
    assert ev.decision is Decision.BLOCK
    assert ev.exit_code == 1


def test_warn_only_is_warning():
    ev = evaluate([_finding("PG-ADD-INDEX-NON-CONCURRENT")], load_policy())
    assert ev.decision is Decision.WARNING
    assert ev.exit_code == 0  # non-blocking by default


def test_incomplete_never_downgrades_to_pass():
    # No findings, but an analyzer reported a missing plan.
    ev = evaluate([], load_policy(), incomplete_reasons=["missing_terraform_plan"])
    assert ev.decision is Decision.INCOMPLETE
    assert ev.exit_code == 2


def test_incomplete_outranks_block():
    policy = load_policy()
    ev = evaluate(
        [_finding("PG-DROP-TABLE")],
        policy,
        incomplete_reasons=["analyzer_error"],
    )
    assert ev.decision is Decision.INCOMPLETE


def test_severity_default_for_unmapped_rule():
    """An unmapped rule (e.g. a native Squawk rule) falls back to severity."""
    policy = load_policy()
    assert policy.action_for_rule("PG-SQUAWK-SOMETHING", "postgres") is None
    ev = evaluate(
        [_finding("PG-SQUAWK-SOMETHING", severity=Severity.CRITICAL)], policy
    )
    # critical -> block per severity_defaults.
    assert ev.decision is Decision.BLOCK


def test_determinism_same_inputs_same_decision():
    policy = load_policy()
    findings = [_finding("PG-DROP-TABLE"), _finding("TF-DELETE-GENERIC", Source.TERRAFORM, Severity.MEDIUM)]
    a = evaluate(findings, policy)
    b = evaluate(list(reversed(findings)), policy)
    assert a.decision is b.decision
    # Evaluated order is normalised, so the sequences match too.
    assert [e.finding.rule_id for e in a.evaluated] == [e.finding.rule_id for e in b.evaluated]


def test_counts():
    policy = load_policy()
    ev = evaluate(
        [
            _finding("PG-DROP-TABLE"),  # block
            _finding("PG-ADD-INDEX-NON-CONCURRENT"),  # warn
        ],
        policy,
    )
    c = ev.counts()
    assert c["block"] == 1 and c["warn"] == 1


def test_invalid_policy_version_rejected(tmp_path):
    bad = tmp_path / "p.yml"
    bad.write_text("version: 99\npolicies: {}\n")
    with pytest.raises(PolicyError):
        load_policy(bad)


def test_invalid_action_rejected(tmp_path):
    bad = tmp_path / "p.yml"
    bad.write_text("version: 1\npolicies:\n  postgres:\n    PG-X: explode\n")
    with pytest.raises(PolicyError):
        load_policy(bad)


def test_custom_policy_can_block_missing_plan(tmp_path):
    custom = tmp_path / "p.yml"
    custom.write_text(
        "version: 1\n"
        "policies:\n"
        "  analysis:\n"
        "    missing_terraform_plan: block\n"
    )
    policy = load_policy(custom)
    ev = evaluate([], policy, incomplete_reasons=["missing_terraform_plan"])
    assert ev.decision is Decision.BLOCK
