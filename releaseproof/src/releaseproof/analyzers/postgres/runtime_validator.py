"""Layer B runtime validation for PostgreSQL migrations (doc section 5).

Applies the changed migrations against a disposable PostgreSQL service
container / test schema and captures whether they execute cleanly. This is the
*later* MVP stage and is gated off by default: it adds CI time and should be
conditional and measured.

Important honesty constraint (doc section 5): a successful apply against a test
schema does NOT prove safety under production data volume, locks, traffic, or
concurrency. The report states exactly what was tested.

This module is written to run against a database the caller provisions (e.g. a
GitHub Actions ``services:`` postgres). It never connects to production.
"""
from __future__ import annotations

import os
from typing import Iterable

from ...findings.models import AnalyzerResult, Severity, Source
from ...findings.normalize import make_finding
from ...inputs.migration_files import MigrationFile


def split_statements(sql: str) -> list[str]:
    """Split a SQL script into individual statements on top-level semicolons.

    Respects single/double-quoted strings, dollar-quoted blocks ($$ or $tag$),
    and ``--`` / ``/* */`` comments, so a semicolon inside a string or a
    function body is not treated as a terminator. Each statement is executed
    standalone so that statements which cannot run in a transaction (e.g.
    ``CREATE INDEX CONCURRENTLY``) work under autocommit.
    """
    statements: list[str] = []
    buf: list[str] = []
    i, n = 0, len(sql)
    in_squote = in_dquote = in_line_comment = in_block_comment = False
    dollar_tag: str | None = None

    while i < n:
        ch = sql[i]
        nxt = sql[i + 1] if i + 1 < n else ""

        if in_line_comment:
            buf.append(ch)
            if ch == "\n":
                in_line_comment = False
            i += 1
            continue
        if in_block_comment:
            buf.append(ch)
            if ch == "*" and nxt == "/":
                buf.append(nxt)
                i += 2
                in_block_comment = False
                continue
            i += 1
            continue
        if dollar_tag is not None:
            if sql.startswith(dollar_tag, i):
                buf.append(dollar_tag)
                i += len(dollar_tag)
                dollar_tag = None
                continue
            buf.append(ch)
            i += 1
            continue
        if in_squote:
            buf.append(ch)
            if ch == "'":
                in_squote = False
            i += 1
            continue
        if in_dquote:
            buf.append(ch)
            if ch == '"':
                in_dquote = False
            i += 1
            continue

        # Not inside any quoted/comment context.
        if ch == "-" and nxt == "-":
            in_line_comment = True
            buf.append(ch)
            i += 1
            continue
        if ch == "/" and nxt == "*":
            in_block_comment = True
            buf.append(ch)
            buf.append(nxt)
            i += 2
            continue
        if ch == "'":
            in_squote = True
            buf.append(ch)
            i += 1
            continue
        if ch == '"':
            in_dquote = True
            buf.append(ch)
            i += 1
            continue
        if ch == "$":
            # Match a dollar-quote opener: $...$ with an optional tag.
            end = sql.find("$", i + 1)
            if end != -1:
                tag = sql[i : end + 1]
                if tag[1:-1].replace("_", "").isalnum() or tag == "$$":
                    dollar_tag = tag
                    buf.append(tag)
                    i = end + 1
                    continue
        if ch == ";":
            stmt = "".join(buf).strip()
            if stmt:
                statements.append(stmt)
            buf = []
            i += 1
            continue

        buf.append(ch)
        i += 1

    tail = "".join(buf).strip()
    if tail:
        statements.append(tail)
    return statements


def _load_driver():
    try:
        import psycopg2  # type: ignore

        return "psycopg2", psycopg2
    except ImportError:
        pass
    try:
        import psycopg  # type: ignore

        return "psycopg", psycopg
    except ImportError:
        return None, None


def run(
    migrations: Iterable[MigrationFile],
    *,
    dsn: str | None = None,
    enabled: bool = False,
    baseline_sql: str | None = None,
) -> AnalyzerResult:
    """Apply migrations to a disposable test schema and capture evidence.

    Args:
        migrations: changed migration files, in order.
        dsn: libpq connection string for the disposable test database. Falls
            back to ``RELEASEPROOF_TEST_DSN`` env var.
        enabled: master switch. When False the validator is a no-op (default for
            Stage 1). Runtime validation is opt-in because it costs CI time.
        baseline_sql: optional SQL establishing a representative non-production
            schema (existing tables the migrations build on). Applied inside the
            disposable schema before the migrations, so an ``ALTER TABLE`` has
            something to alter (doc section 5). A baseline failure is itself an
            analyzer error, not a migration finding.

    The migrations are applied inside a dedicated schema that is dropped at the
    end, so the test database is left clean regardless of outcome.
    """
    result = AnalyzerResult()
    migrations = list(migrations)

    if not enabled:
        result.notes.append("Runtime validation disabled (Stage 1 default).")
        return result
    if not migrations:
        result.notes.append("Runtime validation skipped: no migrations changed.")
        return result

    dsn = dsn or os.environ.get("RELEASEPROOF_TEST_DSN")
    if not dsn:
        result.completed = False
        result.incomplete_reasons.append("analyzer_error")
        result.notes.append(
            "Runtime validation enabled but no test DSN provided "
            "(set RELEASEPROOF_TEST_DSN or pass --test-dsn)."
        )
        return result

    driver_name, driver = _load_driver()
    if driver is None:
        result.completed = False
        result.incomplete_reasons.append("analyzer_error")
        result.notes.append(
            "Runtime validation enabled but no psycopg driver installed."
        )
        return result

    schema = "releaseproof_check"
    conn = None
    try:
        conn = driver.connect(dsn)
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE;')
            cur.execute(f'CREATE SCHEMA "{schema}";')
            cur.execute(f'SET search_path TO "{schema}";')

            # Establish the representative baseline schema inside the isolated
            # schema, so migrations have existing objects to alter.
            if baseline_sql and baseline_sql.strip():
                try:
                    cur.execute(f'SET search_path TO "{schema}";')
                    cur.execute(baseline_sql)
                except Exception as exc:  # noqa: BLE001
                    result.completed = False
                    result.incomplete_reasons.append("analyzer_error")
                    result.notes.append(
                        f"Runtime baseline schema failed to apply: {exc}"
                    )
                    return result

            for mig in migrations:
                try:
                    cur.execute(f'SET search_path TO "{schema}";')
                    # Execute statement-by-statement so that statements which
                    # cannot run inside a transaction (CREATE INDEX
                    # CONCURRENTLY) succeed under autocommit.
                    for stmt in split_statements(mig.content):
                        cur.execute(stmt)
                except Exception as exc:  # noqa: BLE001 - capture as finding
                    result.findings.append(
                        make_finding(
                            rule_id="PG-RUNTIME-APPLY-FAILED",
                            source=Source.POSTGRES,
                            severity=Severity.HIGH,
                            location=mig.path,
                            observation="Migration failed to apply to the test schema",
                            reason=f"Execution error: {type(exc).__name__}",
                            recommendation=(
                                "Fix the migration so it applies cleanly against a "
                                "representative schema."
                            ),
                            evidence={"error": str(exc), "engine": driver_name},
                        )
                    )
                    result.completed = False
                    result.incomplete_reasons.append("analyzer_error")
                    break
            else:
                result.notes.append(
                    f"Runtime validation: {len(migrations)} migration(s) applied "
                    f"to a disposable test schema via {driver_name}. This does not "
                    "prove safety under production volume, locks, or concurrency."
                )
    except Exception as exc:  # noqa: BLE001
        result.completed = False
        result.incomplete_reasons.append("analyzer_error")
        result.notes.append(f"Runtime validation could not connect/run: {exc}")
    finally:
        if conn is not None:
            try:
                with conn.cursor() as cur:
                    cur.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE;')
            except Exception:  # noqa: BLE001 - best-effort cleanup
                pass
            conn.close()

    return result
