from dataclasses import replace

import pytest

from phi_gov.config import Settings
from phi_gov.discovery.agent import DiscoveryAgent
from phi_gov.synthetic import generate
from phi_gov.warehouse.duckdb_wh import DuckDBWarehouse


def build(tmp_path, n_patients=300, **overrides):
    s = replace(Settings(), duckdb_path=str(tmp_path / "t.duckdb"),
                reports_dir=str(tmp_path / "reports"), **overrides)
    wh = DuckDBWarehouse(s.duckdb_path)
    wh.ensure_dataset(s.gold_dataset)
    for name, df in generate(n_patients=n_patients).items():
        wh.write_dataframe(s.gold_dataset, name, df)
    return s, wh


@pytest.fixture(scope="session")
def scanned(tmp_path_factory):
    """A warehouse with one completed scan. Treat as read-only."""
    s, wh = build(tmp_path_factory.mktemp("wh"), n_patients=1500)
    result = DiscoveryAgent(wh, s).run()
    return s, wh, result


@pytest.fixture
def fresh(tmp_path):
    return build(tmp_path)
