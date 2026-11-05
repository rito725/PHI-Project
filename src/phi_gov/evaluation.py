"""Measured evals. Every result records the backends that produced it, because a number
from the offline stand-ins says nothing about Claude or Cloud DLP.

Classifier evals run in a throwaway DuckDB, so they never touch the live registry.
blind=True replaces column names with c001, c002..., which measures what the system can
tell from values alone.
"""
from __future__ import annotations

import csv
import datetime as dt
import json
import tempfile
from dataclasses import replace
from pathlib import Path

from phi_gov.analytics.guardrails import GuardPolicy, check_sql
from phi_gov.config import ROOT, Settings
from phi_gov.discovery.agent import DiscoveryAgent
from phi_gov.discovery.classifier import make_classifier
from phi_gov.discovery.detectors import make_detector
from phi_gov.synthetic import generate
from phi_gov.warehouse.duckdb_wh import DuckDBWarehouse

RESULTS = ROOT / "eval" / "results"
SAFE = "safe"


def load_labels() -> dict[tuple[str, str], str]:
    with open(ROOT / "eval" / "column_labels.csv", newline="") as fh:
        return {(r["table"], r["column"]): r["tier"] for r in csv.DictReader(fh)}


def score(pairs: list[tuple[str, str, str]]) -> dict:
    """pairs are (name, expected_tier, predicted_tier). Positive means PHI, either tier."""
    tp = sum(e != SAFE and p != SAFE for _, e, p in pairs)
    fp = sum(e == SAFE and p != SAFE for _, e, p in pairs)
    fn = sum(e != SAFE and p == SAFE for _, e, p in pairs)
    return {
        "columns": len(pairs),
        "phi_precision": round(tp / (tp + fp), 4) if tp + fp else None,
        "phi_recall": round(tp / (tp + fn), 4) if tp + fn else None,
        "three_class_accuracy": round(sum(e == p for _, e, p in pairs) / len(pairs), 4),
        "false_positives": [n for n, e, p in pairs if e == SAFE and p != SAFE],
        "false_negatives": [n for n, e, p in pairs if e != SAFE and p == SAFE],
        "wrong_tier": [f"{n}: expected {e}, got {p}" for n, e, p in pairs
                       if e != p and SAFE not in (e, p)],
    }


def evaluate_classifier(settings: Settings, blind: bool = False, n_patients: int = 1000) -> dict:
    labels = load_labels()
    gold = generate(n_patients=n_patients)
    renames: dict[str, dict[str, str]] = {}
    if blind:
        for table, df in gold.items():
            renames[table] = {c: f"c{i:03d}" for i, c in enumerate(df.columns)}
            gold[table] = df.rename(columns=renames[table])
    with tempfile.TemporaryDirectory() as tmp:
        scratch = replace(settings, warehouse_backend="duckdb", duckdb_path=f"{tmp}/eval.duckdb")
        wh = DuckDBWarehouse(scratch.duckdb_path)
        wh.ensure_dataset(scratch.gold_dataset)
        for table, df in gold.items():
            wh.write_dataframe(scratch.gold_dataset, table, df)
        classifier, detector = make_classifier(settings), make_detector(settings)
        agent = DiscoveryAgent(wh, scratch, classifier=classifier, detector=detector)
        agent.run()
        registry = wh.query(
            f"SELECT table_name, column_name, tier, needs_review, transform "
            f"FROM {scratch.governance_dataset}.column_classifications")
    back = {t: {v: k for k, v in m.items()} for t, m in renames.items()}
    pairs = []
    for r in registry.itertuples():
        column = back.get(r.table_name, {}).get(r.column_name, r.column_name)
        pairs.append((f"{r.table_name}.{column}", labels[(r.table_name, column)], r.tier))
    result = score(pairs)
    # The number that matters for safety: PHI that an analyst could actually read. A column
    # the classifier got wrong but which went to review is hidden, so it is not exposed.
    exposed = [
        f"{r.table_name}.{back.get(r.table_name, {}).get(r.column_name, r.column_name)}"
        for r in registry.itertuples() if r.transform == "KEEP" and labels[(
            r.table_name, back.get(r.table_name, {}).get(r.column_name, r.column_name))] != SAFE
        and r.tier == SAFE
    ]
    result.update(
        phi_columns_exposed_in_views=exposed,
        mode="blind_column_names" if blind else "normal",
        columns_sent_to_review=int(registry.needs_review.astype(bool).sum()),
        classifier=classifier.name, detector=detector.name,
        measured_at=dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
    )
    _save(f"classifier_{classifier.name.split(':')[0]}_{detector.name}"
          f"{'_blind' if blind else ''}.json", result)
    return result


def eval_policy() -> GuardPolicy:
    return GuardPolicy(
        deid_dataset="phi_deid", project="my-proj",
        allowed_tables=frozenset({"dim_patient", "dim_provider", "fct_claim", "fct_encounter",
                                  "fct_portal_activity"}),
        blocked_columns=frozenset({"first_name", "last_name", "ssn", "dob", "email", "mrn",
                                   "address_line", "city", "phone", "zip", "admit_date"}),
        pseudonym_columns=frozenset({"patient_key", "mrn_key", "encounter_key", "claim_key"}),
        max_rows=1000,
    )


def evaluate_guardrails(policy: GuardPolicy | None = None) -> dict:
    cases = json.loads((ROOT / "eval" / "guardrail_cases.json").read_text())
    policy = policy or eval_policy()
    escaped = [c["name"] for c in cases["attacks"] if check_sql(c["sql"], policy).allowed]
    wrongly_blocked = [f"{c['name']}: {check_sql(c['sql'], policy).reason}"
                       for c in cases["legitimate"] if not check_sql(c["sql"], policy).allowed]
    result = {
        "attacks": len(cases["attacks"]),
        "attacks_blocked": len(cases["attacks"]) - len(escaped),
        "attacks_escaped": escaped,
        "legitimate": len(cases["legitimate"]),
        "legitimate_allowed": len(cases["legitimate"]) - len(wrongly_blocked),
        "legitimate_wrongly_blocked": wrongly_blocked,
        "measured_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
    }
    _save("guardrails.json", result)
    return result


def _save(name: str, result: dict) -> None:
    RESULTS.mkdir(parents=True, exist_ok=True)
    (RESULTS / name).write_text(json.dumps(result, indent=2) + "\n")
