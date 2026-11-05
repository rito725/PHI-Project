"""Governance tables: the column registry, human overrides and the query audit log."""
from __future__ import annotations

import pandas as pd

from phi_gov.warehouse.base import Schema, Warehouse

REGISTRY = "column_classifications"
OVERRIDES = "review_overrides"
AUDIT = "query_audit"
TAGS = "policy_tag_assignments"

REGISTRY_SCHEMA: Schema = [
    ("table_name", "STRING"), ("column_name", "STRING"), ("data_type", "STRING"),
    ("tier", "STRING"), ("category", "STRING"), ("confidence", "FLOAT64"),
    ("transform", "STRING"), ("output_column", "STRING"), ("needs_review", "BOOL"),
    ("human_reviewed", "BOOL"), ("rationale", "STRING"), ("findings", "STRING"),
    ("classifier", "STRING"), ("detector", "STRING"), ("schema_hash", "STRING"),
    ("scanned_at", "TIMESTAMP"),
]
OVERRIDE_SCHEMA: Schema = [
    ("table_name", "STRING"), ("column_name", "STRING"), ("category", "STRING"),
    ("reviewer", "STRING"), ("reviewed_at", "TIMESTAMP"),
]
AUDIT_SCHEMA: Schema = [
    ("audit_id", "STRING"), ("ts", "TIMESTAMP"), ("user_name", "STRING"),
    ("question", "STRING"), ("sql_text", "STRING"), ("status", "STRING"),
    ("block_stage", "STRING"), ("block_reason", "STRING"), ("rows_returned", "INT64"),
    ("bytes_estimated", "INT64"), ("attempts", "INT64"), ("writer", "STRING"),
]
TAG_SCHEMA: Schema = [
    ("table_name", "STRING"), ("column_name", "STRING"), ("policy_tag", "STRING"),
    ("applied_at", "TIMESTAMP"),
]


def read_table(wh: Warehouse, dataset: str, table: str) -> pd.DataFrame:
    if not wh.table_exists(dataset, table):
        return pd.DataFrame()
    return wh.query(f"SELECT * FROM {dataset}.{table}")
