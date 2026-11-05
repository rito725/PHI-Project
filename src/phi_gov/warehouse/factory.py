from __future__ import annotations

from phi_gov.config import Settings
from phi_gov.warehouse.base import Warehouse


def make_warehouse(settings: Settings) -> Warehouse:
    if settings.warehouse_backend == "bigquery":
        from phi_gov.warehouse.bigquery_wh import BigQueryWarehouse
        return BigQueryWarehouse(settings)
    from phi_gov.warehouse.duckdb_wh import DuckDBWarehouse
    return DuckDBWarehouse(settings.duckdb_path)
