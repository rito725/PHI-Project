"""AST-level SQL guardrails. The SQL writer is treated as untrusted, so nothing here
depends on it behaving: this code is the check, whatever wrote the query.

The output is regenerated from the validated AST, so comments and anything else the
parser discarded can never reach the warehouse. Regenerating rather than passing the
input string through also means a query cannot behave differently from what was checked.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field

import pandas as pd
import sqlglot
from sqlglot import exp
from sqlglot.errors import SqlglotError

from phi_gov.config import Settings
from phi_gov.discovery.hipaa import Transform
from phi_gov.governance import REGISTRY, read_table
from phi_gov.warehouse.base import Warehouse

logging.getLogger("sqlglot").setLevel(logging.ERROR)  # unsupported statements are expected

# sqlglot types common functions. Anything it does not recognise parses as Anonymous and
# must be on this list, which is an allowlist so unknown functions fail closed.
ALLOWED_UNTYPED_FUNCTIONS = {
    "APPROX_COUNT_DISTINCT", "COUNTIF", "DATE_TRUNC", "FORMAT_DATE", "IEEE_DIVIDE",
    "PARSE_DATE", "SAFE_DIVIDE", "SAFE_MULTIPLY", "STDDEV", "TIMESTAMP_TRUNC",
}
DENIED_FUNCTIONS = (
    exp.ReadCSV, exp.ReadParquet, exp.CurrentUser, exp.SessionUser, exp.CurrentDatabase,
    exp.JSONFormat,  # TO_JSON_STRING(t) serialises a whole row, keys included
)
# Checked anywhere in the tree, not just at the root: `WITH d AS (DELETE ...) SELECT 1`
# is a SELECT at the top. Parameters are out because no query here binds any, so @x and
# @@project_id can only be reads of session state.
FORBIDDEN_NODES = (
    exp.Insert, exp.Update, exp.Delete, exp.Merge, exp.Drop, exp.Create, exp.Alter,
    exp.TruncateTable, exp.Command, exp.Into, exp.Returning, exp.Parameter,
    exp.SessionParameter,
)


@dataclass(frozen=True)
class GuardPolicy:
    deid_dataset: str
    project: str
    allowed_tables: frozenset[str]        # view names in the de-identified dataset
    blocked_columns: frozenset[str]       # source names of PHI columns
    pseudonym_columns: frozenset[str]     # hashed keys: joinable, countable, never output
    max_rows: int


@dataclass
class GuardResult:
    allowed: bool
    sql: str | None = None
    violations: list[str] = field(default_factory=list)
    limit_applied: bool = False
    stage: str | None = None

    @property
    def reason(self) -> str:
        return "; ".join(self.violations)


def load_policy(wh: Warehouse, s: Settings) -> GuardPolicy:
    """Built from the governance registry, so with no registry nothing is queryable."""
    registry = read_table(wh, s.governance_dataset, REGISTRY)
    if registry.empty:
        return GuardPolicy(s.deid_dataset, s.gcp_project, frozenset(), frozenset(),
                           frozenset(), s.max_rows)
    outputs = {o.lower() for o in registry.output_column.dropna()}
    source = registry[registry["transform"] != Transform.KEEP.value]
    views = wh.list_tables(s.deid_dataset)
    hashed = registry[registry["transform"] == Transform.HASH.value]
    return GuardPolicy(
        deid_dataset=s.deid_dataset,
        project=s.gcp_project,
        allowed_tables=frozenset(v.lower() for v in views),
        blocked_columns=frozenset(c.lower() for c in source.column_name) - outputs,
        pseudonym_columns=frozenset(o.lower() for o in hashed.output_column.dropna()),
        max_rows=s.max_rows,
    )


def check_sql(sql: str, policy: GuardPolicy) -> GuardResult:
    try:
        statements = [st for st in sqlglot.parse(sql, dialect="bigquery") if st is not None]
    except (SqlglotError, ValueError, RecursionError) as err:
        return GuardResult(False, violations=[f"unparseable SQL: {str(err)[:120]}"], stage="parse")
    if len(statements) != 1:
        return GuardResult(False, violations=["exactly one statement is allowed"], stage="statement")
    root = statements[0].unnest() if isinstance(statements[0], exp.Subquery) else statements[0]
    if not isinstance(root, (exp.Select, exp.SetOperation)):
        return GuardResult(False, violations=[f"only SELECT is allowed, got {type(root).__name__}"],
                           stage="statement")
    forbidden = root.find(*FORBIDDEN_NODES)
    if forbidden is not None:
        return GuardResult(False, stage="statement",
                           violations=[f"not allowed inside a query: {type(forbidden).__name__}"])

    checks = [("tables", _check_tables), ("columns", _check_columns),
              ("functions", _check_functions)]
    violations, stage = [], None
    for name, check in checks:
        found = check(root, policy)
        if found and stage is None:
            stage = name
        violations += found
    if violations:
        return GuardResult(False, violations=violations, stage=stage)

    limited, changed = _enforce_limit(root, policy.max_rows)
    return GuardResult(True, sql=limited.sql(dialect="bigquery", comments=False),
                       limit_applied=changed)


def _check_tables(root: exp.Expression, policy: GuardPolicy) -> list[str]:
    cte_names = {cte.alias.lower() for cte in root.find_all(exp.CTE)}
    out = []
    for table in root.find_all(exp.Table):
        if not isinstance(table.this, exp.Identifier):
            out.append(f"table functions are not allowed: {table.sql(dialect='bigquery')[:60]}")
            continue
        name, db, catalog = table.name.lower(), table.db.lower(), table.catalog.lower()
        if not db and name in cte_names:
            continue
        ref = ".".join(p for p in (catalog, db, name) if p)
        if not db:
            out.append(f"table must be qualified with {policy.deid_dataset}: {ref}")
        elif db != policy.deid_dataset.lower():
            out.append(f"raw or non-allowlisted dataset: {ref}")
        elif catalog and catalog != policy.project.lower():
            out.append(f"cross-project access: {ref}")
        elif name not in policy.allowed_tables:
            out.append(f"table is not an approved de-identified view: {ref}")
    return out


def _check_columns(root: exp.Expression, policy: GuardPolicy) -> list[str]:
    aliases = {t.alias_or_name.lower() for t in root.find_all(exp.Table)}
    aliases |= {s.alias.lower() for s in root.find_all(exp.Subquery) if s.alias}
    aliases |= {c.alias.lower() for c in root.find_all(exp.CTE)}
    out = []
    for star in root.find_all(exp.Star):
        if not isinstance(star.parent, exp.Count):
            out.append("SELECT * is not allowed; list columns explicitly")
    for column in root.find_all(exp.Column):
        name = column.name.lower()
        if isinstance(column.this, exp.Star):
            continue  # t.* is reported by the Star walk above
        # Every path segment counts: in p.ssn.x the leaf is x but the data is ssn.
        parts = [part.name.lower() for part in column.parts]
        phi = [part for part in parts if part in policy.blocked_columns]
        pseudonym = next((part for part in parts if part in policy.pseudonym_columns), None)
        if phi:
            out.append(f"PHI column: {phi[0]}")
        elif pseudonym and not _pseudonym_use_ok(column):
            out.append(f"pseudonymous key {pseudonym} may only be used inside COUNT or a JOIN "
                       "condition, not returned")
        elif not column.table and name in aliases:
            out.append(f"selecting a whole row by alias is not allowed: {name}")
    return list(dict.fromkeys(out))


def _pseudonym_use_ok(column: exp.Column) -> bool:
    """MIN, MAX, ARRAY_AGG and friends would return the key itself, so only COUNT counts.
    The walk stops at the enclosing SELECT, so a subquery inside a JOIN gets no pass."""
    node, child = column.parent, column
    while node is not None:
        if isinstance(node, exp.Count):
            return True
        if isinstance(node, exp.Join):
            return node.args.get("on") is child
        if isinstance(node, exp.Select):
            return False
        node, child = node.parent, node
    return False


def _check_functions(root: exp.Expression, policy: GuardPolicy) -> list[str]:
    out = []
    for func in root.find_all(exp.Func):
        if isinstance(func, DENIED_FUNCTIONS):
            out.append(f"function not allowed: {func.sql_name()}")
        elif isinstance(func, exp.Anonymous) and func.name.upper() not in ALLOWED_UNTYPED_FUNCTIONS:
            out.append(f"function not allowed: {func.name}")
    for dot in root.find_all(exp.Dot):
        if isinstance(dot.expression, exp.Func):
            out.append(f"namespaced function not allowed: {dot.sql(dialect='bigquery')[:60]}")
    return list(dict.fromkeys(out))


def _enforce_limit(root: exp.Expression, max_rows: int) -> tuple[exp.Expression, bool]:
    clause = root.args.get("limit")
    if isinstance(clause, exp.Limit) and isinstance(clause.expression, exp.Literal) \
            and clause.expression.is_int and int(clause.expression.this) <= max_rows:
        return root, False
    return root.limit(max_rows, copy=True), True
