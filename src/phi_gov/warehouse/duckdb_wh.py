"""Local warehouse. BigQuery datasets map to DuckDB schemas."""
from __future__ import annotations

import threading
from pathlib import Path

import duckdb
import pandas as pd
import sqlglot
from sqlglot import exp

from phi_gov.warehouse.base import Column, Schema, SqlError, Warehouse

_TYPES = {"STRING": "VARCHAR", "INT64": "BIGINT", "FLOAT64": "DOUBLE",
          "BOOL": "BOOLEAN", "TIMESTAMP": "TIMESTAMP", "DATE": "DATE"}
_LOCK = threading.RLock()


def to_duckdb(sql: str) -> str:
    return sqlglot.transpile(sql, read="bigquery", write="duckdb")[0]


class DuckDBWarehouse(Warehouse):
    name = "duckdb"

    def __init__(self, path: str):
        self.path = path
        Path(path).parent.mkdir(parents=True, exist_ok=True)

    def _connect(self, read_only: bool = False) -> duckdb.DuckDBPyConnection:
        if read_only and not Path(self.path).exists():
            raise SqlError("warehouse not initialised; run `phi-gov load` first")
        return duckdb.connect(self.path, read_only=read_only)

    def ensure_dataset(self, dataset):
        with _LOCK, self._connect() as con:
            con.execute(f'CREATE SCHEMA IF NOT EXISTS "{dataset}"')

    def list_tables(self, dataset):
        with _LOCK, self._connect() as con:
            rows = con.execute(
                "SELECT table_name FROM information_schema.tables "
                "WHERE table_schema = ? ORDER BY 1", [dataset]).fetchall()
        return [r[0] for r in rows]

    def columns(self, dataset, table):
        with _LOCK, self._connect() as con:
            rows = con.execute(
                "SELECT column_name, data_type FROM information_schema.columns "
                "WHERE table_schema = ? AND table_name = ? ORDER BY ordinal_position",
                [dataset, table]).fetchall()
        return [Column(n, t) for n, t in rows]

    def query(self, sql, analyst=False):
        text = to_duckdb(sql)
        try:
            with _LOCK, self._connect(read_only=analyst) as con:
                if analyst:  # no reading local files or the network from analyst SQL
                    con.execute("SET enable_external_access = false")
                return con.execute(text).df()
        except duckdb.Error as err:
            raise SqlError(str(err).split("\n\nLINE")[0]) from err

    def execute(self, sql):
        try:
            with _LOCK, self._connect() as con:
                con.execute(to_duckdb(sql))
        except duckdb.Error as err:
            raise SqlError(str(err)) from err

    def dry_run(self, sql):
        """DuckDB has no billed bytes. EXPLAIN catches the same binder errors as a
        BigQuery dry run; the size is an estimate from the base tables behind the views."""
        text = to_duckdb(sql)
        try:
            with _LOCK, self._connect(read_only=True) as con:
                con.execute("SET enable_external_access = false")
                con.execute("EXPLAIN " + text)
                return self._estimate_bytes(con, sql)
        except duckdb.Error as err:
            raise SqlError(str(err).split("\n\nLINE")[0]) from err

    @staticmethod
    def _estimate_bytes(con, sql: str) -> int:
        total = 0
        for table in sqlglot.parse_one(sql, dialect="bigquery").find_all(exp.Table):
            if not table.db:
                continue
            ref = f'"{table.db}"."{table.name}"'
            rows = con.execute(f"SELECT COUNT(*) FROM {ref}").fetchone()[0]
            cols = len(con.execute(f"SELECT * FROM {ref} LIMIT 0").description)
            total += rows * cols * 16
        return total

    def write_dataframe(self, dataset, table, df):
        with _LOCK, self._connect() as con:
            con.register("incoming", df)
            con.execute(f'CREATE OR REPLACE TABLE "{dataset}"."{table}" AS SELECT * FROM incoming')
            con.unregister("incoming")

    def write_rows(self, dataset, table, rows, schema, truncate=False):
        cols = ", ".join(f'"{n}" {_TYPES[t]}' for n, t in schema)
        ref = f'"{dataset}"."{table}"'
        names = [n for n, _ in schema]
        with _LOCK, self._connect() as con:
            con.execute(f"CREATE TABLE IF NOT EXISTS {ref} ({cols})")
            if truncate:
                con.execute(f"DELETE FROM {ref}")
            if rows:
                marks = ", ".join("?" for _ in names)
                con.executemany(f"INSERT INTO {ref} VALUES ({marks})",
                                [[r.get(n) for n in names] for r in rows])

    def apply_policy_tags(self, dataset, table, tags):
        """DuckDB has no column-level security; the governance dataset records intent."""

    def authorize_views(self, source_dataset, view_dataset):
        """No per-dataset ACLs in DuckDB. Enforced by the guardrails alone locally."""
