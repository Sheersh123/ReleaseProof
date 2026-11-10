"""Built-in PostgreSQL migration-safety rules.

These are ReleaseProof's own product-specific checks (doc section 4: "add only
product-specific rules not covered by [Squawk]"). They also let the analyzer
function when the Squawk binary is not installed, so the MVP is runnable and
testable in any CI environment.

Detection is intentionally conservative and regex-based over normalised SQL —
enough to catch the common destructive/locking patterns, explainable, and with
no false *silence* on the headline risks. Policy decides severity-to-action.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable

from ...findings.models import AnalyzerResult, Severity, Source
from ...findings.normalize import make_finding


def _normalise_sql(sql: str) -> str:
    """Strip comments and collapse whitespace for easier matching."""
    # Remove -- line comments and /* */ block comments.
    sql = re.sub(r"--[^\n]*", " ", sql)
    sql = re.sub(r"/\*.*?\*/", " ", sql, flags=re.DOTALL)
    return re.sub(r"\s+", " ", sql).strip()


@dataclass
class _Match:
    rule_id: str
    severity: Severity
    observation: str
    reason: str
    recommendation: str
    snippet: str


# Each detector scans normalised SQL and yields _Match objects.
Detector = Callable[[str], list[_Match]]


def _d_drop_column(sql: str) -> list[_Match]:
    out = []
    for m in re.finditer(
        r"\balter\s+table\s+(?:if\s+exists\s+)?([^\s;]+)[^;]*?\bdrop\s+column\b\s+(?:if\s+exists\s+)?([^\s;,]+)",
        sql,
        re.IGNORECASE,
    ):
        out.append(
            _Match(
                "PG-DROP-COLUMN",
                Severity.HIGH,
                f"Drops column {m.group(2)} from {m.group(1)}",
                "Dropping a column breaks any running code that still reads it, "
                "and the data is lost.",
                "Deploy code that stops using the column first, then drop it in a "
                "later release (expand/contract).",
                m.group(0),
            )
        )
    return out


def _d_drop_table(sql: str) -> list[_Match]:
    out = []
    for m in re.finditer(
        r"\bdrop\s+table\b\s+(?:if\s+exists\s+)?([^\s;]+)", sql, re.IGNORECASE
    ):
        out.append(
            _Match(
                "PG-DROP-TABLE",
                Severity.CRITICAL,
                f"Drops table {m.group(1)}",
                "Dropping a table destroys its data and breaks dependents.",
                "Confirm nothing reads the table and a backup exists; prefer a "
                "staged deprecation.",
                m.group(0),
            )
        )
    return out


def _d_truncate(sql: str) -> list[_Match]:
    out = []
    for m in re.finditer(r"\btruncate\s+(?:table\s+)?([^\s;]+)", sql, re.IGNORECASE):
        out.append(
            _Match(
                "PG-TRUNCATE",
                Severity.CRITICAL,
                f"Truncates {m.group(1)}",
                "TRUNCATE deletes all rows and cannot be rolled back on some setups.",
                "Avoid TRUNCATE in migrations against tables with real data.",
                m.group(0),
            )
        )
    return out


def _d_rename_column(sql: str) -> list[_Match]:
    out = []
    for m in re.finditer(
        r"\balter\s+table\s+(?:if\s+exists\s+)?([^\s;]+)[^;]*?\brename\s+column\b\s+([^\s;]+)\s+to\s+([^\s;,]+)",
        sql,
        re.IGNORECASE,
    ):
        out.append(
            _Match(
                "PG-RENAME-COLUMN",
                Severity.HIGH,
                f"Renames column {m.group(2)} to {m.group(3)} on {m.group(1)}",
                "A rename is not backward compatible — old and new app versions "
                "cannot both work during a rollout.",
                "Add the new column, backfill, switch reads/writes, then drop the "
                "old column across separate releases.",
                m.group(0),
            )
        )
    return out


def _d_rename_table(sql: str) -> list[_Match]:
    out = []
    for m in re.finditer(
        r"\balter\s+table\s+(?:if\s+exists\s+)?([^\s;]+)\s+rename\s+to\s+([^\s;,]+)",
        sql,
        re.IGNORECASE,
    ):
        out.append(
            _Match(
                "PG-RENAME-TABLE",
                Severity.HIGH,
                f"Renames table {m.group(1)} to {m.group(2)}",
                "Renaming a table breaks code referencing the old name during a "
                "rollout.",
                "Use a view or staged migration so both names resolve during "
                "deploy.",
                m.group(0),
            )
        )
    return out


def _d_not_null_no_default(sql: str) -> list[_Match]:
    out = []
    for m in re.finditer(
        r"\balter\s+table\s+(?:if\s+exists\s+)?([^\s;]+)[^;]*?\badd\s+column\b\s+([^\s;]+)\s+([^;]*?)(?=,\s*add\s+column|;|$)",
        sql,
        re.IGNORECASE,
    ):
        clause = m.group(3)
        if re.search(r"\bnot\s+null\b", clause, re.IGNORECASE) and not re.search(
            r"\bdefault\b", clause, re.IGNORECASE
        ):
            out.append(
                _Match(
                    "PG-NOT-NULL-NO-DEFAULT",
                    Severity.HIGH,
                    f"Adds NOT NULL column {m.group(2)} without a default on {m.group(1)}",
                    "Existing rows have no value for the new column, so the "
                    "statement fails or requires a full table rewrite.",
                    "Add the column nullable (or with a default), backfill, then "
                    "add the NOT NULL constraint.",
                    m.group(0),
                )
            )
    return out


_VOLATILE_DEFAULTS = re.compile(
    r"\bdefault\b\s+(now\(\)|current_timestamp|gen_random_uuid\(\)|uuid_generate|random\()",
    re.IGNORECASE,
)


def _d_add_column_volatile_default(sql: str) -> list[_Match]:
    out = []
    for m in re.finditer(
        r"\balter\s+table\s+(?:if\s+exists\s+)?([^\s;]+)[^;]*?\badd\s+column\b\s+([^\s;]+)\s+([^;]*?)(?=,\s*add\s+column|;|$)",
        sql,
        re.IGNORECASE,
    ):
        if _VOLATILE_DEFAULTS.search(m.group(3)):
            out.append(
                _Match(
                    "PG-ADD-COLUMN-DEFAULT-VOLATILE",
                    Severity.MEDIUM,
                    f"Adds column {m.group(2)} with a volatile default on {m.group(1)}",
                    "A volatile default forces a full table rewrite under an "
                    "ACCESS EXCLUSIVE lock on large tables.",
                    "Add the column without a default, backfill in batches, then "
                    "set the default.",
                    m.group(0),
                )
            )
    return out


def _d_change_column_type(sql: str) -> list[_Match]:
    out = []
    for m in re.finditer(
        r"\balter\s+table\s+(?:if\s+exists\s+)?([^\s;]+)[^;]*?\balter\s+column\b\s+([^\s;]+)\s+(?:set\s+data\s+)?type\b\s+([^\s;,]+)",
        sql,
        re.IGNORECASE,
    ):
        out.append(
            _Match(
                "PG-CHANGE-COLUMN-TYPE",
                Severity.MEDIUM,
                f"Changes type of column {m.group(2)} to {m.group(3)} on {m.group(1)}",
                "A type change can rewrite the whole table under a heavy lock and "
                "may be lossy.",
                "Verify the conversion is safe and consider a new-column migration "
                "for large tables.",
                m.group(0),
            )
        )
    return out


def _d_non_concurrent_index(sql: str) -> list[_Match]:
    out = []
    for m in re.finditer(
        r"\bcreate\s+(?:unique\s+)?index\b\s+(?:if\s+not\s+exists\s+)?([^\s;]+)?\s*on\s+([^\s;(]+)",
        sql,
        re.IGNORECASE,
    ):
        # Only flag when CONCURRENTLY is absent.
        if not re.search(r"\bcreate\s+(?:unique\s+)?index\s+concurrently", sql, re.IGNORECASE) or \
           "concurrently" not in m.group(0).lower():
            # Re-check the specific statement span, not the whole file.
            if "concurrently" not in m.group(0).lower():
                target = m.group(2)
                out.append(
                    _Match(
                        "PG-ADD-INDEX-NON-CONCURRENT",
                        Severity.MEDIUM,
                        f"Creates an index on {target} without CONCURRENTLY",
                        "A non-concurrent index build takes a lock that blocks "
                        "writes for the duration.",
                        "Use CREATE INDEX CONCURRENTLY (outside a transaction) on "
                        "busy tables.",
                        m.group(0),
                    )
                )
    return out


_DETECTORS: list[Detector] = [
    _d_drop_column,
    _d_drop_table,
    _d_truncate,
    _d_rename_column,
    _d_rename_table,
    _d_not_null_no_default,
    _d_add_column_volatile_default,
    _d_change_column_type,
    _d_non_concurrent_index,
]


def analyze_sql(file_path: str, sql: str) -> AnalyzerResult:
    """Run every built-in detector over one migration file's SQL."""
    result = AnalyzerResult()
    normalised = _normalise_sql(sql)
    seen: set[tuple[str, str]] = set()
    for detector in _DETECTORS:
        for match in detector(normalised):
            key = (match.rule_id, match.observation)
            if key in seen:
                continue
            seen.add(key)
            result.findings.append(
                make_finding(
                    rule_id=match.rule_id,
                    source=Source.POSTGRES,
                    severity=match.severity,
                    location=file_path,
                    observation=match.observation,
                    reason=match.reason,
                    recommendation=match.recommendation,
                    evidence={"statement": match.snippet, "engine": "builtin"},
                )
            )
    return result
