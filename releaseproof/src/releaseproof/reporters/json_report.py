"""Machine-readable JSON report.

This is the shareable, sanitised result. It contains only redacted findings and
the decision — never raw plan contents, credentials, or DB data. A future
hosted control plane would receive this exact shape (doc section 3/8).
"""
from __future__ import annotations

import json
from typing import Any

from .. import __version__
from ..policy.evaluator import Evaluation


def build_report(evaluation: Evaluation, *, notes: list[str] | None = None) -> dict[str, Any]:
    counts = evaluation.counts()
    return {
        "tool": "releaseproof",
        "version": __version__,
        "decision": evaluation.decision.value,
        "decision_label": evaluation.decision.label,
        "exit_code": evaluation.exit_code,
        "summary": {
            "total_findings": len(evaluation.evaluated),
            "blocking": counts["block"],
            "warnings": counts["warn"],
            "passed": counts["pass"],
            "ignored": counts["ignore"],
        },
        "incomplete_reasons": evaluation.incomplete_reasons,
        "analysis_notes": evaluation.analysis_notes,
        "notes": notes or [],
        "findings": [
            {
                **ev.finding.to_dict(),
                "action": ev.action.value,
                "action_source": ev.action_source,
            }
            for ev in evaluation.evaluated
        ],
    }


def render(evaluation: Evaluation, *, notes: list[str] | None = None, indent: int = 2) -> str:
    return json.dumps(build_report(evaluation, notes=notes), indent=indent, sort_keys=False)
