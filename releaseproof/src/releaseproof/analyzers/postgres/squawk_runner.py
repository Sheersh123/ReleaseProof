"""Layer A static analysis for PostgreSQL migrations.

Primary engine is Squawk (a mature migration linter) when its pinned binary is
available on PATH; ReleaseProof's built-in product rules always run alongside
it. Squawk findings are normalised into ReleaseProof's common finding format so
the policy engine sees one shape regardless of engine.

If Squawk is not installed, the analyzer degrades to built-in rules only and
records a note — it does not fail the run. (Headline destructive patterns are
covered by the built-in rules, so this is a coverage reduction, not a blind
spot on the critical cases.)
"""
from __future__ import annotations

import json
import shutil
import subprocess
from typing import Any, Iterable

from ...findings.models import AnalyzerResult, Severity, Source
from ...findings.normalize import make_finding
from ..postgres import builtin_rules
from ...inputs.migration_files import MigrationFile

# Recommended Squawk version. The JSON normaliser handles both the v1 and v2
# reporter shapes, so the integration is not hard-pinned to one release.
PINNED_SQUAWK_VERSION = "2.71.0"
SQUAWK_BINARY = "squawk"


def _squawk_available() -> str | None:
    return shutil.which(SQUAWK_BINARY)


def _run_squawk(paths: list[str]) -> list[dict[str, Any]]:
    """Invoke squawk with the JSON reporter and return parsed entries.

    Raises CalledProcessError only for unexpected invocation failures; a
    non-zero exit purely because lint issues were found is expected and handled.
    """
    cmd = [SQUAWK_BINARY, "--reporter", "json", *paths]
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    out = proc.stdout.strip()
    if not out:
        # squawk prints nothing when there is nothing to report.
        return []
    try:
        data = json.loads(out)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Could not parse Squawk JSON output: {exc}") from exc
    return data if isinstance(data, list) else []


def _normalise_squawk_entry(entry: dict[str, Any]) -> dict[str, Any]:
    """Map a squawk JSON entry onto make_finding kwargs."""
    rule_name = str(entry.get("rule_name", "unknown"))
    level = str(entry.get("level", "warning"))
    file_ = entry.get("file", "<unknown>")
    line = entry.get("line")
    location = f"{file_}:{line}" if line is not None else str(file_)

    # Squawk's JSON shape changed between major versions:
    #   v1: {"messages": [{"Note": "..."}, {"Help": "..."}]}
    #   v2: flat {"message": "...", "note": "...", "help": "..."}
    # Handle both so the integration is not pinned to one Squawk release.
    notes: list[str] = []
    helps: list[str] = []
    for msg in entry.get("messages", []) or []:
        if isinstance(msg, dict):
            if msg.get("Note"):
                notes.append(str(msg["Note"]))
            if msg.get("Help"):
                helps.append(str(msg["Help"]))
        elif msg:
            notes.append(str(msg))
    # v2 flat fields.
    for key in ("message", "note"):
        val = entry.get(key)
        if val:
            notes.append(str(val))
    if entry.get("help"):
        helps.append(str(entry["help"]))

    observation = notes[0] if notes else f"Squawk rule {rule_name} triggered"
    recommendation = helps[0] if helps else "See Squawk documentation for remediation."

    return dict(
        rule_id=f"PG-SQUAWK-{rule_name.upper().replace('_', '-')}",
        source=Source.POSTGRES,
        severity=Severity.coerce(level),
        location=location,
        observation=observation,
        reason="Flagged by Squawk migration linter.",
        recommendation=recommendation,
        evidence={"squawk_rule": rule_name, "level": level, "engine": "squawk"},
    )


def run(
    migrations: Iterable[MigrationFile],
    *,
    use_squawk: bool = True,
) -> AnalyzerResult:
    """Run Layer A static analysis over the given migration files."""
    migrations = list(migrations)
    result = AnalyzerResult()

    if not migrations:
        result.notes.append("No PostgreSQL migration files changed.")
        return result

    # Built-in product rules always run.
    for mig in migrations:
        result.extend(builtin_rules.analyze_sql(mig.path, mig.content))

    # Squawk runs when requested and available.
    if use_squawk:
        squawk_path = _squawk_available()
        if squawk_path is None:
            result.notes.append(
                "Squawk not found on PATH — ran built-in migration rules only. "
                f"Install squawk {PINNED_SQUAWK_VERSION} for full coverage."
            )
        else:
            try:
                entries = _run_squawk([m.path for m in migrations])
                for entry in entries:
                    result.findings.append(
                        make_finding(**_normalise_squawk_entry(entry))
                    )
            except (subprocess.SubprocessError, RuntimeError, OSError) as exc:
                # A squawk failure is an analyzer error → Incomplete, so we never
                # pass a migration that Squawk could not evaluate.
                result.completed = False
                result.incomplete_reasons.append("analyzer_error")
                result.notes.append(f"Squawk execution failed: {exc}")
    else:
        result.notes.append("Squawk disabled by configuration; built-in rules only.")

    return result
