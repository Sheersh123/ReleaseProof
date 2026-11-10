"""Deterministic policy evaluation (doc section 7).

Takes the normalised findings plus the incomplete reasons gathered by the
analyzers, applies the versioned policy, and returns a single release decision
with a per-finding breakdown.

Guarantees:
* Identical inputs + identical policy version => identical decision
  (MVP acceptance criterion 4).
* "Analysis Incomplete" can never be downgraded to "Pass"
  (doc section 2 principle 7, section 7).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..findings.models import Action, Decision, Finding
from ..findings.normalize import sort_findings
from .loader import Policy

# How a per-finding/analysis action contributes to the overall decision.
_ACTION_TO_DECISION = {
    Action.BLOCK: Decision.BLOCK,
    Action.WARN: Decision.WARNING,
    Action.PASS: Decision.PASS,
    Action.INCOMPLETE: Decision.INCOMPLETE,
}


@dataclass
class EvaluatedFinding:
    finding: Finding
    action: Action
    # Where the action came from: "rule", "severity-default", or "ignored".
    action_source: str


@dataclass
class Evaluation:
    decision: Decision
    evaluated: list[EvaluatedFinding] = field(default_factory=list)
    # Analysis-level reasons that forced/contributed to the decision.
    incomplete_reasons: list[str] = field(default_factory=list)
    analysis_notes: list[str] = field(default_factory=list)

    @property
    def exit_code(self) -> int:
        return self.decision.exit_code

    def counts(self) -> dict[str, int]:
        out = {"block": 0, "warn": 0, "pass": 0, "ignore": 0}
        for ev in self.evaluated:
            if ev.action is Action.BLOCK:
                out["block"] += 1
            elif ev.action is Action.WARN:
                out["warn"] += 1
            elif ev.action is Action.IGNORE:
                out["ignore"] += 1
            else:
                out["pass"] += 1
        return out


def _resolve_action(finding: Finding, policy: Policy) -> tuple[Action, str]:
    """Decide the action for a single finding."""
    explicit = policy.action_for_rule(finding.rule_id, finding.source.value)
    if explicit is not None:
        return explicit, "rule"
    # Fall back to severity-based default (covers unmapped Squawk rules).
    return policy.action_for_severity(finding.severity.value), "severity-default"


def evaluate(
    findings: list[Finding],
    policy: Policy,
    *,
    incomplete_reasons: list[str] | None = None,
) -> Evaluation:
    """Apply the policy to findings + analysis signals and return a decision."""
    incomplete_reasons = list(incomplete_reasons or [])
    evaluated: list[EvaluatedFinding] = []
    decision = Decision.PASS
    analysis_notes: list[str] = []

    # 1. Per-finding contributions.
    for finding in sort_findings(findings):
        action, src = _resolve_action(finding, policy)
        evaluated.append(EvaluatedFinding(finding=finding, action=action, action_source=src))
        if action is Action.IGNORE:
            continue
        contribution = _ACTION_TO_DECISION[action]
        if contribution.rank > decision.rank:
            decision = contribution

    # 2. Analysis-level signals (missing/invalid input, analyzer errors).
    #    These are mapped through policies.analysis, so a team can, for example,
    #    decide a missing plan is "incomplete" (default) vs "block".
    for reason in incomplete_reasons:
        mapped = policy.analysis_action(reason)
        analysis_notes.append(f"{reason} -> {mapped}")
        try:
            contribution = _ACTION_TO_DECISION[Action(mapped)]
        except (ValueError, KeyError):
            contribution = Decision.INCOMPLETE
        if contribution.rank > decision.rank:
            decision = contribution

    return Evaluation(
        decision=decision,
        evaluated=evaluated,
        incomplete_reasons=incomplete_reasons,
        analysis_notes=analysis_notes,
    )
