"""Warehouse interface. All SQL in this project is written in BigQuery dialect;
the DuckDB backend transpiles it, so the local path exercises the same statements."""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

import pandas as pd


class SqlError(Exception):
    """The warehouse rejected a statement. Safe to feed back for self-correction."""


@dataclass(frozen=True)
class Column:
    name: str
    data_type: str


Schema = list[tuple[str, str]]  # (column, BigQuery type)


class Warehouse(ABC):
    name: str

    @abstractmethod
    def ensure_dataset(self, dataset: str) -> None: ...

    @abstractmethod
    def list_tables(self, dataset: str) -> list[str]: ...

    @abstractmethod
    def columns(self, dataset: str, table: str) -> list[Column]: ...

    @abstractmethod
    def query(self, sql: str, analyst: bool = False) -> pd.DataFrame:
        """Run a SELECT. analyst=True uses the least-privilege path."""

    @abstractmethod
    def execute(self, sql: str) -> None:
        """Run DDL as the governance identity."""

    @abstractmethod
    def dry_run(self, sql: str) -> int:
        """Validate without running and return bytes it would scan."""

    @abstractmethod
    def write_dataframe(self, dataset: str, table: str, df: pd.DataFrame) -> None:
        """Create or replace a table from a DataFrame."""

    @abstractmethod
    def write_rows(self, dataset: str, table: str, rows: list[dict], schema: Schema,
                   truncate: bool = False) -> None: ...

    @abstractmethod
    def apply_policy_tags(self, dataset: str, table: str, tags: dict[str, str]) -> None:
        """tags maps column to tier name."""

    @abstractmethod
    def authorize_views(self, source_dataset: str, view_dataset: str) -> None:
        """Let views in view_dataset read source_dataset without granting users access."""

    def table_exists(self, dataset: str, table: str) -> bool:
        return table in self.list_tables(dataset)

    def sample_column(self, dataset: str, table: str, column: str, n: int) -> list[str]:
        """Stable sample of non-null values. Ordering by a hash avoids taking only the
        first rows, which in a sorted table can all look alike."""
        sql = (
            f"SELECT CAST(`{column}` AS STRING) AS v FROM {dataset}.{table} "
            f"WHERE `{column}` IS NOT NULL "
            f"ORDER BY TO_HEX(SHA256(CAST(`{column}` AS STRING))) LIMIT {int(n)}"
        )
        return self.query(sql)["v"].astype(str).tolist()
