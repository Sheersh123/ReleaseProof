"""GitHub job summary reporter (doc section 3/5).

Renders Markdown that GitHub Actions displays as the run summary (via the file
pointed to by ``$GITHUB_STEP_SUMMARY``). Results land where developers already
work; the process exit status drives the check itself.
"""
from __future__ import annotations

import os
from typing import Iterable

from ..findings.models import Action, Decision
from ..policy.evaluator import Evaluation, EvaluatedFinding

_DECISION_BADGE = {
    Decision.PASS: "✅ Pass",
    Decision.WARNING: "⚠️ Warning",
    Decision.BLOCK: "⛔ Block",
    Decision.INCOMPLETE: "🚧 Analysis Incomplete",
}

_ACTION_BADGE = {
    Action.BLOCK: "⛔ block",
    Action.WARN: "⚠️ warn",
    Action.PASS: "✅ pass",
    Action.INCOMPLETE: "🚧 incomplete",
    Action.IGNORE: "➖ ignore",
}


def _headline(evaluation: Evaluation) -> str:
    badge = _DECISION_BADGE[evaluation.decision]
    c = evaluation.counts()
    return (
        f"## ReleaseProof — {badge}\n\n"
        f"**{c['block']}** blocking · **{c['warn']}** warnings · "
        f"**{c['pass']}** informational"
    )


def _decision_explainer(evaluation: Evaluation) -> str:
    d = evaluation.decision
    if d is Decision.BLOCK:
        return (
            "> One or more blocking rules were triggered. Address the blocking "
            "findings below, or adjust policy via review on the base branch."
        )
    if d is Decision.INCOMPLETE:
        reasons = ", ".join(evaluation.incomplete_reasons) or "an analyzer could not complete"
        return (
            f"> Analysis could not be completed ({reasons}). This is **not** a "
            "pass — fix the inputs and re-run."
        )
    if d is Decision.WARNING:
        return "> Risks were found but none block under the current policy. Review before merging."
    return "> No policy violations found under the active policy."


def _findings_table(evaluated: Iterable[EvaluatedFinding]) -> str:
    rows = list(evaluated)
    actionable = [e for e in rows if e.action in (Action.BLOCK, Action.WARN)]
    if not actionable:
        return "_No blocking or warning findings._"

    lines = [
        "| Decision | Rule | Severity | Source | Location | Observation |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for ev in actionable:
        f = ev.finding
        lines.append(
            f"| {_ACTION_BADGE[ev.action]} | `{f.rule_id}` | {f.severity.value} "
            f"| {f.source.value} | `{_md_escape(f.location)}` | {_md_escape(f.observation)} |"
        )
    return "\n".join(lines)


def _details(evaluated: Iterable[EvaluatedFinding]) -> str:
    rows = [e for e in evaluated if e.action in (Action.BLOCK, Action.WARN)]
    if not rows:
        return ""
    blocks = ["\n<details><summary>Finding details & remediation</summary>\n"]
    for ev in rows:
        f = ev.finding
        blocks.append(
            f"\n**`{f.rule_id}`** — {_md_escape(f.observation)}\n\n"
            f"- **Why:** {_md_escape(f.reason)}\n"
            f"- **Fix:** {_md_escape(f.recommendation)}\n"
            f"- **Where:** `{_md_escape(f.location)}`\n"
        )
    blocks.append("\n</details>\n")
    return "".join(blocks)


def _notes_section(notes: list[str]) -> str:
    if not notes:
        return ""
    body = "\n".join(f"- {_md_escape(n)}" for n in notes)
    return f"\n### Notes\n{body}\n"


def _md_escape(text: str) -> str:
    return str(text).replace("|", "\\|")


def render(evaluation: Evaluation, *, notes: list[str] | None = None) -> str:
    """Build the full Markdown summary."""
    parts = [
        _headline(evaluation),
        "",
        _decision_explainer(evaluation),
        "",
        "### Findings",
        _findings_table(evaluation.evaluated),
        _details(evaluation.evaluated),
        _notes_section(notes or []),
        "\n---\n_ReleaseProof detects selected risks; it does not guarantee "
        "production behaviour or replace tested recovery._",
    ]
    return "\n".join(p for p in parts if p is not None)


def write_step_summary(markdown: str) -> bool:
    """Append the summary to GitHub's step-summary file if present.

    Returns True if written to the GitHub summary, False otherwise.
    """
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not path:
        return False
    try:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(markdown + "\n")
        return True
    except OSError:
        return False
