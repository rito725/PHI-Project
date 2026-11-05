"""Generate de-identified view SQL from column decisions.

SQL is produced from fixed templates in code, never by a model. Columns are listed
explicitly, so a column added to a gold table stays hidden until it has been classified.
"""
from __future__ import annotations

import re

from phi_gov.config import Settings
from phi_gov.discovery.hipaa import RESTRICTED_ZIP3, Transform
from phi_gov.discovery.policy import Decision

_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def view_name(table: str) -> str:
    return re.sub(r"^gold_", "", table)


def _expr(d: Decision, salt_sql: str) -> str | None:
    col = f"`{d.column}`"
    text = f"CAST({col} AS STRING)"
    year = f"EXTRACT(YEAR FROM SAFE_CAST({col} AS DATE))"
    match d.transform:
        case Transform.HASH:
            # Salted, so MRNs cannot be recovered by hashing every possible MRN. The
            # salt lives in a restricted table, so it never appears in view text.
            return (f"IF({col} IS NULL, NULL, "
                    f"TO_HEX(SHA256(CONCAT({text}, ({salt_sql})))))")
        case Transform.BIRTH_YEAR:
            # Safe Harbor: ages over 89 must collapse into a single 90+ group.
            return (f"IF(EXTRACT(YEAR FROM CURRENT_DATE()) - {year} > 89, NULL, {year})")
        case Transform.YEAR:
            return year
        case Transform.ZIP3:
            prefix = f"SUBSTR({text}, 1, 3)"
            restricted = ", ".join(f"'{z}'" for z in RESTRICTED_ZIP3)
            return f"IF({prefix} IN ({restricted}), '000', {prefix})"
        case Transform.AGE_CAP:
            return f"IF({col} > 89, 90, {col})"
        case Transform.KEEP:
            return col
    return None


def build_view_sql(table: str, decisions: list[Decision], settings: Settings) -> str | None:
    """SELECT for one view, or None if no column may be exposed."""
    salt_sql = f"SELECT salt FROM {settings.restricted_dataset}.deid_secret"
    lines = []
    for d in decisions:
        if not _IDENT.match(d.column):
            continue  # an unsafe identifier is never templated into SQL
        expression = _expr(d, salt_sql)
        if expression is not None:
            lines.append(f"  {expression} AS `{d.output_column}`")
    if not lines:
        return None
    return "SELECT\n" + ",\n".join(lines) + f"\nFROM {settings.gold_dataset}.{table}"


def create_view_ddl(table: str, select_sql: str, settings: Settings) -> str:
    return f"CREATE OR REPLACE VIEW {settings.deid_dataset}.{view_name(table)} AS\n{select_sql}"
