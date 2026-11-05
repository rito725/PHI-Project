"""Guarded NL-to-SQL agent, a LangGraph pipeline.

write_sql -> guard -> dry_run -> execute -> audit
    ^                    |          |
    +---- SQL error, up to 2 retries +

Corrected SQL goes back through the guard. A guardrail block is terminal and is never
retried: feeding block reasons back would let the writer probe its way around the policy.
"""
from __future__ import annotations

import datetime as dt
import uuid
from dataclasses import dataclass, field
from typing import TypedDict

import pandas as pd
from langgraph.graph import END, START, StateGraph

from phi_gov.analytics.guardrails import GuardResult, check_sql, load_policy
from phi_gov.analytics.writer import make_writer, schema_context
from phi_gov.config import Settings
from phi_gov.governance import AUDIT, AUDIT_SCHEMA
from phi_gov.warehouse.base import SqlError, Warehouse

ALLOWED, BLOCKED, ERROR = "ALLOWED", "BLOCKED", "ERROR"


class AuditError(RuntimeError):
    """The audit write failed. Results are withheld: no log, no data."""


class State(TypedDict, total=False):
    user: str
    question: str
    provided_sql: str | None
    attempts: int
    sql: str | None
    final_sql: str | None
    error: str | None
    status: str
    stage: str | None
    reason: str | None
    bytes_estimated: int | None
    result: pd.DataFrame | None
    limit_applied: bool
    trace: list[str]


@dataclass
class Answer:
    status: str
    question: str
    sql: str | None
    final_sql: str | None
    stage: str | None
    reason: str | None
    rows: pd.DataFrame | None
    rows_returned: int
    bytes_estimated: int | None
    attempts: int
    trace: list[str] = field(default_factory=list)
    limit_applied: bool = False


class AnalyticsAgent:
    def __init__(self, wh: Warehouse, settings: Settings, writer=None):
        self.wh, self.s = wh, settings
        self.writer = writer or make_writer(settings)
        self.graph = self._build()

    def _build(self):
        g = StateGraph(State)
        for name in ("write_sql", "guard", "dry_run", "execute", "audit"):
            g.add_node(name, getattr(self, name))
        g.add_conditional_edges(START, lambda st: "guard" if st.get("provided_sql") else "write_sql",
                                {"guard": "guard", "write_sql": "write_sql"})
        g.add_conditional_edges("write_sql", lambda st: "guard" if st.get("sql") else "audit",
                                {"guard": "guard", "audit": "audit"})
        g.add_conditional_edges("guard", lambda st: "audit" if st.get("status") else "dry_run",
                                {"audit": "audit", "dry_run": "dry_run"})
        g.add_conditional_edges("dry_run", self._after, {
            "retry": "write_sql", "next": "execute", "audit": "audit"})
        g.add_conditional_edges("execute", self._after, {
            "retry": "write_sql", "next": "audit", "audit": "audit"})
        g.add_edge("audit", END)
        return g.compile()

    def _after(self, st: State) -> str:
        if st.get("status"):
            return "audit"
        if st.get("error"):
            return "retry"
        return "next"

    def ask(self, user: str, question: str) -> Answer:
        return self._invoke({"user": user, "question": question})

    def run_sql(self, user: str, sql: str, label: str = "(direct SQL)") -> Answer:
        """Send SQL straight to the guard, bypassing the writer. This is the red-team path."""
        return self._invoke({"user": user, "question": label, "provided_sql": sql, "sql": sql})

    def _invoke(self, state: State) -> Answer:
        st = self.graph.invoke({"attempts": 0, "trace": [], **state})
        result = st.get("result")
        return Answer(
            status=st["status"], question=st["question"], sql=st.get("sql"),
            final_sql=st.get("final_sql"), stage=st.get("stage"), reason=st.get("reason"),
            rows=result, rows_returned=0 if result is None else len(result),
            bytes_estimated=st.get("bytes_estimated"), attempts=st.get("attempts", 0),
            trace=st.get("trace", []), limit_applied=st.get("limit_applied", False),
        )

    def write_sql(self, st: State) -> dict:
        attempt = st["attempts"] + 1
        trace = st["trace"] + [f"write_sql: attempt {attempt}"]
        try:
            draft = self.writer.write(st["question"], schema_context(self.wh, self.s),
                                      previous=st.get("sql"), error=st.get("error"))
        except Exception as err:
            return {"attempts": attempt, "trace": trace, "sql": None, "status": ERROR,
                    "stage": "writer", "reason": f"SQL writer failed: {type(err).__name__}"}
        if draft.cannot_answer or not draft.sql:
            return {"attempts": attempt, "trace": trace, "sql": None, "status": BLOCKED,
                    "stage": "model_declined", "reason": draft.reason}
        return {"attempts": attempt, "trace": trace, "sql": draft.sql, "error": None}

    def guard(self, st: State) -> dict:
        result: GuardResult = check_sql(st["sql"], load_policy(self.wh, self.s))
        if not result.allowed:
            return {"status": BLOCKED, "stage": result.stage, "reason": result.reason,
                    "trace": st["trace"] + [f"guard: BLOCKED at {result.stage}"]}
        note = " (LIMIT enforced)" if result.limit_applied else ""
        return {"final_sql": result.sql, "limit_applied": result.limit_applied,
                "trace": st["trace"] + [f"guard: passed{note}"]}

    def _sql_failure(self, st: State, node: str, err: SqlError) -> dict:
        message = str(err)[:500]
        trace = st["trace"] + [f"{node}: SQL error"]
        retries_left = st["attempts"] <= self.s.max_sql_retries and not st.get("provided_sql")
        if retries_left:
            return {"error": message, "trace": trace}
        return {"status": ERROR, "stage": node, "reason": message, "error": message, "trace": trace}

    def dry_run(self, st: State) -> dict:
        try:
            scanned = self.wh.dry_run(st["final_sql"])
        except SqlError as err:
            return self._sql_failure(st, "dry_run", err)
        trace = st["trace"] + [f"dry_run: ~{scanned:,} bytes"]
        if scanned > self.s.max_bytes_billed:
            return {"status": BLOCKED, "stage": "cost", "bytes_estimated": scanned, "trace": trace,
                    "reason": f"would scan {scanned:,} bytes; limit is {self.s.max_bytes_billed:,}"}
        return {"bytes_estimated": scanned, "trace": trace}

    def execute(self, st: State) -> dict:
        try:
            frame = self.wh.query(st["final_sql"], analyst=True)
        except SqlError as err:
            return self._sql_failure(st, "execute", err)
        return {"result": frame, "status": ALLOWED,
                "trace": st["trace"] + [f"execute: {len(frame)} rows"]}

    def audit(self, st: State) -> dict:
        frame = st.get("result")
        row = {
            "audit_id": uuid.uuid4().hex, "ts": dt.datetime.now(dt.timezone.utc),
            "user_name": st["user"], "question": st["question"],
            "sql_text": st.get("final_sql") if st["status"] == ALLOWED else st.get("sql"),
            "status": st["status"], "block_stage": st.get("stage"),
            "block_reason": st.get("reason"),
            "rows_returned": 0 if frame is None else len(frame),
            "bytes_estimated": st.get("bytes_estimated"), "attempts": st.get("attempts", 0),
            "writer": "direct" if st.get("provided_sql") else self.writer.name,
        }
        try:
            self.wh.write_rows(self.s.governance_dataset, AUDIT, [row], AUDIT_SCHEMA)
        except Exception as err:
            return {"status": ERROR, "stage": "audit", "result": None,
                    "reason": f"audit write failed, results withheld: {type(err).__name__}",
                    "trace": st["trace"] + ["audit: FAILED, results withheld"]}
        return {"trace": st["trace"] + [f"audit: logged {st['status']}"]}
