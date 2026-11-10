"""Normalisation helpers that turn raw analyzer output into Findings.

Keeping this in one place means every analyzer emits the same shape, and the
policy engine and reporters never have to special-case a source.
"""
from __future__ import annotations

import re
from typing import Any, Iterable

from .models import Finding, Severity, Source

# Characters/patterns we never want to leak into evidence or reports.
_SECRET_HINTS = re.compile(
    r"(password|secret|token|api[_-]?key|private[_-]?key|credential|passwd|bearer)",
    re.IGNORECASE,
)


def redact(value: Any, *, max_len: int = 120) -> str:
    """Return a log-safe string for a value.

    Values whose context looks secret-bearing are masked entirely; everything
    else is stringified and truncated so large/raw plan blobs never land in a
    report.
    """
    text = "" if value is None else str(value)
    if _SECRET_HINTS.search(text):
        return "<redacted>"
    text = text.replace("\n", " ").strip()
    if len(text) > max_len:
        return text[: max_len - 1] + "…"
    return text


def safe_evidence(raw: dict[str, Any] | None) -> dict[str, Any]:
    """Redact an evidence dict: mask secret-looking keys, truncate the rest."""
    if not raw:
        return {}
    clean: dict[str, Any] = {}
    for key, val in raw.items():
        if _SECRET_HINTS.search(str(key)):
            clean[key] = "<redacted>"
        else:
            clean[key] = redact(val)
    return clean


def make_finding(
    *,
    rule_id: str,
    source: Source | str,
    severity: Severity | str,
    location: str,
    observation: str,
    reason: str,
    recommendation: str,
    evidence: dict[str, Any] | None = None,
) -> Finding:
    """Build a Finding with evidence redacted and fields normalised."""
    return Finding(
        rule_id=rule_id,
        source=source if isinstance(source, Source) else Source(str(source)),
        severity=Severity.coerce(severity),
        location=redact(location, max_len=200),
        observation=redact(observation, max_len=240),
        reason=redact(reason, max_len=240),
        recommendation=redact(recommendation, max_len=240),
        evidence=safe_evidence(evidence),
    )


def sort_findings(findings: Iterable[Finding]) -> list[Finding]:
    """Deterministic ordering: severity desc, then source, then rule, location.

    Determinism matters — identical inputs must produce identical reports
    (MVP acceptance criterion 4).
    """
    return sorted(
        findings,
        key=lambda f: (
            -f.severity.rank,
            f.source.value,
            f.rule_id,
            f.location,
        ),
    )
