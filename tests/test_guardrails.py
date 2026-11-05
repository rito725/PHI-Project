import json
from dataclasses import replace

import pytest

from phi_gov.analytics.guardrails import check_sql, load_policy
from phi_gov.config import ROOT
from phi_gov.evaluation import eval_policy
from phi_gov.warehouse.base import SqlError

CASES = json.loads((ROOT / "eval" / "guardrail_cases.json").read_text())
POLICY = eval_policy()


@pytest.mark.parametrize("case", CASES["attacks"], ids=lambda c: c["name"])
def test_attack_is_blocked(case):
    result = check_sql(case["sql"], POLICY)
    assert not result.allowed and result.violations and result.sql is None


@pytest.mark.parametrize("case", CASES["legitimate"], ids=lambda c: c["name"])
def test_legitimate_query_is_allowed(case):
    assert check_sql(case["sql"], POLICY).allowed


@pytest.mark.parametrize("sql,expected", [
    ("SELECT state FROM phi_deid.dim_patient", "LIMIT 1000"),
    ("SELECT state FROM phi_deid.dim_patient LIMIT 99999999", "LIMIT 1000"),
    ("SELECT state FROM phi_deid.dim_patient LIMIT 1+99999", "LIMIT 1000"),
    ("SELECT state FROM phi_deid.dim_patient LIMIT 5", "LIMIT 5"),
    ("SELECT state FROM phi_deid.dim_patient UNION ALL "
     "SELECT state FROM phi_deid.dim_patient", "LIMIT 1000"),
])
def test_limit_enforced(sql, expected):
    assert check_sql(sql, POLICY).sql.endswith(expected)


def test_inner_limit_does_not_satisfy_outer_limit():
    sql = "SELECT state FROM (SELECT state FROM phi_deid.dim_patient LIMIT 5) t"
    assert check_sql(sql, POLICY).sql.endswith("LIMIT 1000")


def test_comments_do_not_reach_the_warehouse():
    result = check_sql("SELECT state /* note */ FROM phi_deid.dim_patient -- x\nLIMIT 5", POLICY)
    assert result.allowed and "note" not in result.sql and "--" not in result.sql


def test_empty_registry_blocks_everything(tmp_path):
    from tests.conftest import build
    s, wh = build(tmp_path, n_patients=10)
    for dataset in (s.deid_dataset, s.governance_dataset):
        wh.ensure_dataset(dataset)
    policy = load_policy(wh, s)
    assert not check_sql("SELECT state FROM phi_deid.dim_patient", policy).allowed


def test_real_registry_blocks_real_phi_columns(scanned):
    s, wh, _ = scanned
    policy = load_policy(wh, s)
    for column in ("ssn", "mrn", "dob", "zip", "first_name", "cust_attr_9", "clinical_note",
                   "provider_name"):
        assert column in policy.blocked_columns
    for column in ("gender", "state", "zip3", "birth_year"):
        assert column not in policy.blocked_columns
    assert "patient_key" in policy.pseudonym_columns


def test_every_legitimate_query_runs_on_the_warehouse(scanned):
    """The corpus must hold up on a real engine, not just parse."""
    s, wh, _ = scanned
    policy = replace(load_policy(wh, s), project="my-proj")
    for case in CASES["legitimate"]:
        result = check_sql(case["sql"], policy)
        assert result.allowed, case["name"]
        wh.query(result.sql, analyst=True)


def test_analyst_connection_cannot_write(scanned):
    s, wh, _ = scanned
    with pytest.raises(SqlError):
        wh.query(f"DELETE FROM {s.gold_dataset}.gold_fct_claim WHERE TRUE", analyst=True)


def test_analyst_connection_cannot_read_files(scanned):
    with pytest.raises(SqlError):
        scanned[1].query("SELECT * FROM read_csv('/etc/hosts')", analyst=True)
