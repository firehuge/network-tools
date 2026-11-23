import os
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
# Some test modules load profiles at import time, before any fixture runs.
os.environ["PANLAB_CUSTOMERS_DIR"] = str(ROOT / "tests" / "customers")


@pytest.fixture(autouse=True)
def _test_customers_dir(monkeypatch):
    """Tests use the synthetic profiles in tests/customers (the shipped install has no customers)."""
    monkeypatch.setenv("PANLAB_CUSTOMERS_DIR", str(ROOT / "tests" / "customers"))


@pytest.fixture
def repo_root() -> Path:
    return ROOT


@pytest.fixture
def schema_path(repo_root: Path) -> Path:
    return repo_root / "schema" / "rule_request.schema.json"


@pytest.fixture
def config_xml(repo_root: Path) -> Path:
    return repo_root / "tests" / "fixtures" / "synthetic-config.xml"


@pytest.fixture
def example_request(repo_root: Path) -> Path:
    return repo_root / "requests" / "example-rule-request.yaml"


@pytest.fixture
def fixtures(repo_root: Path) -> Path:
    return repo_root / "tests" / "fixtures"
