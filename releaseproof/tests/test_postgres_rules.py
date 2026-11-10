"""Tests for the PostgreSQL analyzer (built-in rules + squawk orchestration)."""
from releaseproof.analyzers.postgres import builtin_rules, squawk_runner
from releaseproof.inputs.migration_files import MigrationFile


def _ids(sql: str) -> set[str]:
    return {f.rule_id for f in builtin_rules.analyze_sql("m.sql", sql).findings}


def test_safe_migration_no_findings(pg_fixtures):
    sql = (pg_fixtures / "safe_migration.sql").read_text()
    assert builtin_rules.analyze_sql("safe.sql", sql).findings == []


def test_drop_column_blocked():
    assert "PG-DROP-COLUMN" in _ids("ALTER TABLE users DROP COLUMN token;")


def test_drop_table_detected():
    assert "PG-DROP-TABLE" in _ids("DROP TABLE legacy;")


def test_truncate_detected():
    assert "PG-TRUNCATE" in _ids("TRUNCATE sessions;")


def test_rename_column_detected():
    assert "PG-RENAME-COLUMN" in _ids(
        "ALTER TABLE accounts RENAME COLUMN email TO email_address;"
    )


def test_rename_table_detected():
    assert "PG-RENAME-TABLE" in _ids("ALTER TABLE old_name RENAME TO new_name;")


def test_not_null_without_default_detected():
    assert "PG-NOT-NULL-NO-DEFAULT" in _ids(
        "ALTER TABLE orders ADD COLUMN ref text NOT NULL;"
    )


def test_not_null_with_default_is_safe():
    # A default is provided, so the NOT-NULL rule must NOT fire.
    assert "PG-NOT-NULL-NO-DEFAULT" not in _ids(
        "ALTER TABLE orders ADD COLUMN ref text NOT NULL DEFAULT 'x';"
    )


def test_volatile_default_detected():
    assert "PG-ADD-COLUMN-DEFAULT-VOLATILE" in _ids(
        "ALTER TABLE events ADD COLUMN created_at timestamptz NOT NULL DEFAULT now();"
    )


def test_type_change_detected():
    assert "PG-CHANGE-COLUMN-TYPE" in _ids(
        "ALTER TABLE invoices ALTER COLUMN amount TYPE bigint;"
    )


def test_non_concurrent_index_detected():
    assert "PG-ADD-INDEX-NON-CONCURRENT" in _ids(
        "CREATE INDEX idx_x ON t (col);"
    )


def test_concurrent_index_is_safe():
    assert "PG-ADD-INDEX-NON-CONCURRENT" not in _ids(
        "CREATE INDEX CONCURRENTLY idx_x ON t (col);"
    )


def test_comments_are_ignored():
    sql = "-- ALTER TABLE users DROP COLUMN token;\nSELECT 1;"
    assert _ids(sql) == set()


def test_runner_without_squawk_uses_builtin(pg_fixtures):
    sql = (pg_fixtures / "unsafe_drop_column.sql").read_text()
    mig = MigrationFile(path="unsafe_drop_column.sql", content=sql)
    result = squawk_runner.run([mig], use_squawk=False)
    assert "PG-DROP-COLUMN" in {f.rule_id for f in result.findings}
    # Note recorded that squawk was skipped.
    assert any("built-in rules only" in n for n in result.notes)


def test_runner_empty_migrations_is_noop():
    result = squawk_runner.run([], use_squawk=True)
    assert result.findings == []
    assert result.completed is True


def test_mixed_migration_flags_multiple(pg_fixtures):
    sql = (pg_fixtures / "unsafe_mixed.sql").read_text()
    ids = _ids(sql)
    assert {
        "PG-DROP-TABLE",
        "PG-RENAME-COLUMN",
        "PG-TRUNCATE",
        "PG-ADD-COLUMN-DEFAULT-VOLATILE",
        "PG-ADD-INDEX-NON-CONCURRENT",
    } <= ids
