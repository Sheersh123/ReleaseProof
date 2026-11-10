"""Shared pytest fixtures."""
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def fixtures_dir() -> Path:
    return FIXTURES


@pytest.fixture
def tf_fixtures() -> Path:
    return FIXTURES / "terraform"


@pytest.fixture
def pg_fixtures() -> Path:
    return FIXTURES / "postgres"
