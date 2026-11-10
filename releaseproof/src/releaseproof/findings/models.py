"""Core data models shared across ReleaseProof.

These implement the finding model (doc section 6) and the policy outcomes
(doc section 7). Detection is kept separate from policy: an analyzer reports
what it *observed*; the policy engine decides what to do about it.
"""
from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Source(str, Enum):
    """Which analyzer produced a finding."""

    TERRAFORM = "terraform"
    POSTGRES = "postgres"
    SYSTEM = "system"  # ReleaseProof itself (e.g. input/analyzer errors)


class Severity(str, Enum):
    """Normalised severity. Order matters for comparison/sorting."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        order = {
            Severity.CRITICAL: 4,
            Severity.HIGH: 3,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
            Severity.INFO: 0,
        }
        return order[self]

    @classmethod
    def coerce(cls, value: Any) -> "Severity":
        """Best-effort map an arbitrary severity string onto the enum."""
        if isinstance(value, Severity):
            return value
        if value is None:
            return cls.MEDIUM
        text = str(value).strip().lower()
        aliases = {
            "crit": cls.CRITICAL,
            "critical": cls.CRITICAL,
            "error": cls.HIGH,
            "high": cls.HIGH,
            "warning": cls.MEDIUM,
            "warn": cls.MEDIUM,
            "medium": cls.MEDIUM,
            "moderate": cls.MEDIUM,
            "low": cls.LOW,
            "minor": cls.LOW,
            "notice": cls.INFO,
            "info": cls.INFO,
            "informational": cls.INFO,
        }
        return aliases.get(text, cls.MEDIUM)


class Action(str, Enum):
    """Policy action attached to a rule (doc section 7 YAML)."""

    BLOCK = "block"
    WARN = "warn"
    PASS = "pass"
    INCOMPLETE = "incomplete"
    IGNORE = "ignore"


class Decision(str, Enum):
    """Overall release decision (doc section 7)."""

    PASS = "pass"
    WARNING = "warning"
    BLOCK = "block"
    INCOMPLETE = "incomplete"

    @property
    def rank(self) -> int:
        # Higher rank wins when combining. Incomplete must never be downgraded
        # to pass, so it outranks everything.
        order = {
            Decision.PASS: 0,
            Decision.WARNING: 1,
            Decision.BLOCK: 2,
            Decision.INCOMPLETE: 3,
        }
        return order[self]

    @property
    def exit_code(self) -> int:
        """Process exit status used to drive the GitHub check."""
        return {
            Decision.PASS: 0,
            Decision.WARNING: 0,  # visible but non-blocking by default
            Decision.BLOCK: 1,
            Decision.INCOMPLETE: 2,  # fail visibly — never a silent pass
        }[self]

    @property
    def label(self) -> str:
        return {
            Decision.PASS: "Pass",
            Decision.WARNING: "Warning",
            Decision.BLOCK: "Block",
            Decision.INCOMPLETE: "Analysis Incomplete",
        }[self]


@dataclass
class Finding:
    """A single observation from an analyzer (doc section 6).

    Fields mirror the documented finding model. ``evidence`` must contain only
    minimal, redacted facts — never raw plan values or credentials.
    """

    rule_id: str
    source: Source
    severity: Severity
    location: str
    observation: str
    reason: str
    recommendation: str
    evidence: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # Coerce loosely-typed inputs so analyzers can pass plain strings.
        if not isinstance(self.source, Source):
            self.source = Source(str(self.source))
        if not isinstance(self.severity, Severity):
            self.severity = Severity.coerce(self.severity)

    def to_dict(self) -> dict[str, Any]:
        d = dataclasses.asdict(self)
        d["source"] = self.source.value
        d["severity"] = self.severity.value
        return d


@dataclass
class AnalyzerResult:
    """What one analyzer returns: findings plus whether it completed cleanly."""

    findings: list[Finding] = field(default_factory=list)
    completed: bool = True
    # Reason codes (keys under policies.analysis) that should force Incomplete.
    incomplete_reasons: list[str] = field(default_factory=list)
    # Non-fatal notes surfaced to the report (e.g. "squawk not installed").
    notes: list[str] = field(default_factory=list)

    def extend(self, other: "AnalyzerResult") -> None:
        self.findings.extend(other.findings)
        self.completed = self.completed and other.completed
        self.incomplete_reasons.extend(other.incomplete_reasons)
        self.notes.extend(other.notes)
