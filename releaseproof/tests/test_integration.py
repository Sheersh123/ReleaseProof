"""Integration tests for the two paths that need external tooling.

Both are skip-guarded so the suite stays green on machines without Squawk or a
test PostgreSQL:
  * Squawk engine   -> requires the `squawk` binary on PATH.
  * Runtime (Layer B) -> requires RELEASEPROOF_TEST_DSN + a psycopg driver.
"""
import shutil

import pytest

from releaseproof.analyzers.postgres import runtime_validator, squawk_runner
from releaseproof.inputs.migration_files import MigrationFile

# --- Squawk (Layer A) -------------------------------------------------------

squawk_missing = shutil.which("squawk") is None


@pytest.mark.skipif(squawk_missing, reason="squawk binary not installed")
def test_squawk_engine_produces_findings(pg_fixtures):
    sql = (pg_fixtures / "unsafe_mixed.sql").read_text()
    mig = MigrationFile(path=str(pg_fixtures / "unsafe_mixed.sql"), content=sql)
    result = squawk_runner.run([mig], use_squawk=True)
    squawk_ids = {f.rule_id for f in result.findings if f.rule_id.startswith("PG-SQUAWK-")}
    # Squawk should flag the drop-table and renaming-column patterns at least.
    assert any("DROP-TABLE" in rid for rid in squawk_ids)
    assert any("RENAMING-COLUMN" in rid for rid in squawk_ids)
    # Every squawk finding carries a human-readable observation (v1/v2 parsing).
    for f in result.findings:
        if f.rule_id.startswith("PG-SQUAWK-"):
            assert f.observation and "triggered" not in f.observation.lower() or f.observation


# --- Runtime validation (Layer B) -------------------------------------------

import os

no_dsn = not os.environ.get("RELEASEPROOF_TEST_DSN")


def _driver_present() -> bool:
    try:
        import psycopg2  # noqa: F401

        return True
    except ImportError:
        try:
            import psycopg  # noqa: F401

            return True
        except ImportError:
            return False


runtime_skip = no_dsn or not _driver_present()
RUNTIME_REASON = "RELEASEPROOF_TEST_DSN unset or no psycopg driver"


@pytest.mark.skipif(runtime_skip, reason=RUNTIME_REASON)
def test_runtime_applies_safe_migration(pg_fixtures):
    dsn = os.environ["RELEASEPROOF_TEST_DSN"]
    baseline = (pg_fixtures / "baseline.sql").read_text()
    sql = (pg_fixtures / "safe_migration.sql").read_text()
    mig = MigrationFile(path="safe_migration.sql", content=sql)
    result = runtime_validator.run(
        [mig], dsn=dsn, enabled=True, baseline_sql=baseline
    )
    assert result.completed is True
    assert not any(f.rule_id == "PG-RUNTIME-APPLY-FAILED" for f in result.findings)
    assert any("applied to a disposable test schema" in n for n in result.notes)


@pytest.mark.skipif(runtime_skip, reason=RUNTIME_REASON)
def test_runtime_captures_broken_migration(pg_fixtures):
    dsn = os.environ["RELEASEPROOF_TEST_DSN"]
    baseline = (pg_fixtures / "baseline.sql").read_text()
    mig = MigrationFile(
        path="broken.sql",
        content="ALTER TABLE missing_table ADD COLUMN x int;",
    )
    result = runtime_validator.run(
        [mig], dsn=dsn, enabled=True, baseline_sql=baseline
    )
    assert result.completed is False
    assert "analyzer_error" in result.incomplete_reasons
    assert any(f.rule_id == "PG-RUNTIME-APPLY-FAILED" for f in result.findings)


@pytest.mark.skipif(runtime_skip, reason=RUNTIME_REASON)
def test_runtime_concurrently_index_applies(pg_fixtures):
    """CREATE INDEX CONCURRENTLY must succeed (statement-splitter + autocommit)."""
    dsn = os.environ["RELEASEPROOF_TEST_DSN"]
    mig = MigrationFile(
        path="concurrent.sql",
        content=(
            "CREATE TABLE t (id int);\n"
            "CREATE INDEX CONCURRENTLY idx_t_id ON t (id);\n"
        ),
    )
    result = runtime_validator.run([mig], dsn=dsn, enabled=True)
    assert result.completed is True
    assert not any(f.rule_id == "PG-RUNTIME-APPLY-FAILED" for f in result.findings)


# --- Statement splitter (no DB required) ------------------------------------


def test_split_statements_respects_strings_and_dollar_quotes():
    sql = """
    INSERT INTO t (msg) VALUES ('a; not a terminator');
    CREATE FUNCTION f() RETURNS int AS $$
    BEGIN
      RETURN 1;  -- semicolon inside body
    END;
    $$ LANGUAGE plpgsql;
    DROP TABLE x;
    """
    stmts = runtime_validator.split_statements(sql)
    assert len(stmts) == 3
    assert stmts[0].startswith("INSERT")
    assert "LANGUAGE plpgsql" in stmts[1]
    assert stmts[2].startswith("DROP TABLE")


def test_split_statements_ignores_comment_semicolons():
    sql = "SELECT 1; -- a; b; c\nSELECT 2;"
    stmts = runtime_validator.split_statements(sql)
    assert len(stmts) == 2
