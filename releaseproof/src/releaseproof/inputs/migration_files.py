"""Collect the PostgreSQL migration files changed in a pull request.

The set of changed files is supplied by CI (e.g. from the PR diff). This module
resolves those paths, filters to SQL migrations, and reads their contents so the
Postgres analyzer has text to lint. It does not connect to any database.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

SQL_SUFFIXES = {".sql"}


class MigrationInputError(Exception):
    """Raised when a declared migration file cannot be read."""

    def __init__(self, message: str, reason_code: str = "analyzer_error") -> None:
        super().__init__(message)
        self.reason_code = reason_code


@dataclass
class MigrationFile:
    path: str
    content: str

    @property
    def name(self) -> str:
        return Path(self.path).name


def _is_migration(path: Path, migrations_dir: str | None) -> bool:
    if path.suffix.lower() not in SQL_SUFFIXES:
        return False
    if migrations_dir:
        try:
            path.resolve().relative_to(Path(migrations_dir).resolve())
        except ValueError:
            return False
    return True


def collect_migrations(
    changed_files: Iterable[str],
    *,
    migrations_dir: str | None = None,
    base_dir: str | Path | None = None,
) -> list[MigrationFile]:
    """Read the changed migration files.

    Args:
        changed_files: paths (relative or absolute) of files changed in the PR.
        migrations_dir: if set, only files under this directory count as
            migrations. Useful to avoid linting unrelated ``.sql`` fixtures.
        base_dir: root to resolve relative paths against (defaults to cwd).

    Missing files are skipped with a note rather than failing the whole run —
    a file may have been deleted in the PR. A file that exists but cannot be
    read raises MigrationInputError (→ analyzer_error → Incomplete).
    """
    root = Path(base_dir) if base_dir else Path.cwd()
    out: list[MigrationFile] = []
    seen: set[str] = set()

    for raw in changed_files:
        if not raw or not str(raw).strip():
            continue
        candidate = Path(raw)
        if not candidate.is_absolute():
            candidate = root / candidate

        if not _is_migration(candidate, migrations_dir):
            continue
        key = str(candidate.resolve())
        if key in seen:
            continue
        seen.add(key)

        if not candidate.exists():
            # Deleted-in-PR or stale path: nothing to lint.
            continue
        try:
            content = candidate.read_text(encoding="utf-8")
        except OSError as exc:
            raise MigrationInputError(
                f"Could not read migration file {candidate}: {exc}"
            ) from exc

        out.append(MigrationFile(path=str(raw), content=content))

    # Deterministic order for repeatable reports.
    out.sort(key=lambda m: m.path)
    return out
