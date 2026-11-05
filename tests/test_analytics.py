from dataclasses import replace

import pytest

from phi_gov.analytics.agent import ALLOWED, BLOCKED, ERROR, AnalyticsAgent
from phi_gov.analytics.writer import SqlDraft, TemplateSqlWriter, schema_context
from phi_gov.discovery.agent import DiscoveryAgent

GOOD = "SELECT payer_name, COUNT(*) AS n FROM phi_deid.fct_claim GROUP BY payer_name"
BAD_COLUMN = "SELECT no_such_column FROM phi_deid.fct_claim"
PHI = "SELECT ssn FROM phi_gold.gold_dim_patient"


class Scripted:
    name = "scripted"

    def __init__(self, *sqls):
        self.sqls, self.calls = list(sqls), []

    def write(self, question, schema, previous=None, error=None):
        self.calls.append({"previous": previous, "error": error})
        return SqlDraft(sql=self.sqls.pop(0), cannot_answer=False, reason="")


class Declines:
    name = "declines"

    def write(self, *args, **kwargs):
        return SqlDraft(sql=None, cannot_answer=True, reason="no such data")


class Crashes:
    name = "crashes"

    def write(self, *args, **kwargs):
        raise RuntimeError("boom")


@pytest.fixture
def ready(fresh):
    s, wh = fresh
    DiscoveryAgent(wh, s).run()
    return s, wh


def audit_rows(wh, s):
    return wh.query(f"SELECT * FROM {s.governance_dataset}.query_audit ORDER BY ts")


def test_demo_blocked_then_allowed_then_logged(ready):
    s, wh = ready
    agent = AnalyticsAgent(wh, s, writer=TemplateSqlWriter(s))
    blocked = agent.ask("alice", "list patient names with diabetes")
    allowed = agent.ask("alice", "readmission rate by payer in 2025")
    assert blocked.status == BLOCKED and blocked.rows is None
    assert "phi_gold" in blocked.reason and "first_name" in blocked.reason
    assert allowed.status == ALLOWED and allowed.rows_returned == 6
    log = audit_rows(wh, s)
    assert list(log.status) == [BLOCKED, ALLOWED]
    assert list(log.user_name) == ["alice", "alice"]
    assert log.question[1] == "readmission rate by payer in 2025"
    assert "phi_deid.fct_encounter" in log.sql_text[1] and log.rows_returned[1] == 6
    assert "phi_gold" in log.sql_text[0]


def test_rate_matches_a_hand_computed_value_from_gold(ready):
    s, wh = ready
    answer = AnalyticsAgent(wh, s, writer=TemplateSqlWriter(s)).ask(
        "a", "readmission rate by payer in 2025")
    truth = wh.query(
        f"SELECT payer_name, ROUND(AVG(IF(readmitted_30d, 1, 0)), 3) AS r "
        f"FROM {s.gold_dataset}.gold_fct_encounter "
        f"WHERE EXTRACT(YEAR FROM admit_date) = 2025 GROUP BY payer_name")
    assert dict(zip(answer.rows.payer_name, answer.rows.readmission_rate)) == \
        dict(zip(truth.payer_name, truth.r))


def test_self_corrects_on_sql_error(ready):
    s, wh = ready
    writer = Scripted(BAD_COLUMN, GOOD)
    answer = AnalyticsAgent(wh, s, writer=writer).ask("a", "q")
    assert answer.status == ALLOWED and answer.attempts == 2
    assert writer.calls[1]["previous"] == BAD_COLUMN and "no_such_column" in writer.calls[1]["error"]


def test_stops_after_two_retries(ready):
    s, wh = ready
    writer = Scripted(BAD_COLUMN, BAD_COLUMN, BAD_COLUMN, GOOD)
    answer = AnalyticsAgent(wh, s, writer=writer).ask("a", "q")
    assert answer.status == ERROR and answer.attempts == 3 and len(writer.calls) == 3
    assert audit_rows(wh, s).attempts[0] == 3


def test_retry_cannot_smuggle_phi_past_the_guard(ready):
    s, wh = ready
    writer = Scripted(BAD_COLUMN, PHI)
    answer = AnalyticsAgent(wh, s, writer=writer).ask("a", "q")
    assert answer.status == BLOCKED and answer.rows is None


def test_guardrail_block_is_never_retried(ready):
    s, wh = ready
    writer = Scripted(PHI, GOOD)
    answer = AnalyticsAgent(wh, s, writer=writer).ask("a", "q")
    assert answer.status == BLOCKED and len(writer.calls) == 1


def test_model_declining_is_logged_as_blocked(ready):
    s, wh = ready
    answer = AnalyticsAgent(wh, s, writer=Declines()).ask("a", "show me John's address")
    assert answer.status == BLOCKED and answer.stage == "model_declined"
    assert audit_rows(wh, s).block_stage[0] == "model_declined"


def test_writer_crash_is_logged(ready):
    s, wh = ready
    answer = AnalyticsAgent(wh, s, writer=Crashes()).ask("a", "q")
    assert answer.status == ERROR and len(audit_rows(wh, s)) == 1


def test_cost_limit_blocks_before_execution(ready):
    s, wh = ready
    capped = replace(s, max_bytes_billed=1)
    answer = AnalyticsAgent(wh, capped, writer=Scripted(GOOD)).ask("a", "q")
    assert answer.status == BLOCKED and answer.stage == "cost" and answer.rows is None
    assert audit_rows(wh, s).bytes_estimated[0] > 1


def test_no_audit_no_data(ready, monkeypatch):
    s, wh = ready
    agent = AnalyticsAgent(wh, s, writer=Scripted(GOOD))

    def fail(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(wh, "write_rows", fail)
    answer = agent.ask("a", "q")
    assert answer.status == ERROR and answer.stage == "audit"
    assert answer.rows is None and answer.rows_returned == 0


def test_direct_sql_skips_writer_but_not_guard(ready):
    s, wh = ready
    agent = AnalyticsAgent(wh, s, writer=Crashes())
    assert agent.run_sql("red", PHI).status == BLOCKED
    assert agent.run_sql("red", GOOD).status == ALLOWED
    assert list(audit_rows(wh, s).writer) == ["direct", "direct"]


def test_schema_given_to_the_llm_holds_no_raw_names(scanned):
    s, wh, _ = scanned
    context = schema_context(wh, s)
    assert "phi_deid.fct_encounter" in context
    assert s.gold_dataset not in context
    for raw in ("ssn", "first_name", "clinical_note", "dob", "email"):
        assert raw not in context
