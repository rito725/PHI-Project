"""Command line entry point. Run `phi-gov --help`."""
from __future__ import annotations

import argparse
import datetime as dt
import glob
import json
import os
import sys
import time

import pandas as pd

from phi_gov.analytics.agent import AnalyticsAgent, Answer
from phi_gov.config import Settings
from phi_gov.discovery.agent import DiscoveryAgent
from phi_gov.discovery.hipaa import Category
from phi_gov.evaluation import evaluate_classifier, evaluate_guardrails
from phi_gov.governance import AUDIT, OVERRIDE_SCHEMA, OVERRIDES, REGISTRY, read_table
from phi_gov.synthetic import generate
from phi_gov.warehouse.factory import make_warehouse

pd.set_option("display.width", 160, "display.max_columns", 30, "display.max_colwidth", 60)
DEMO_QUESTIONS = ["list patient names with diabetes", "readmission rate by payer in 2025"]


def backends(s: Settings) -> str:
    return f"warehouse={s.warehouse_backend} dlp={s.dlp_backend} llm={s.llm_backend}"


def cmd_load(args, s, wh):
    wh.ensure_dataset(s.gold_dataset)
    start = time.time()
    if args.source_dir:  # real Project 1 output, exported as one parquet file per table
        tables = {os.path.splitext(os.path.basename(p))[0]: pd.read_parquet(p)
                  for p in sorted(glob.glob(os.path.join(args.source_dir, "*.parquet")))}
        if not tables:
            sys.exit(f"no .parquet files in {args.source_dir}")
    else:
        tables = generate(seed=args.seed, n_patients=args.patients)
    for name, frame in tables.items():
        wh.write_dataframe(s.gold_dataset, name, frame)
        print(f"  {s.gold_dataset}.{name}: {len(frame):,} rows, {frame.shape[1]} columns")
    print(f"Loaded {sum(map(len, tables.values())):,} rows in {time.time() - start:.1f}s")


def cmd_scan(args, s, wh):
    result = DiscoveryAgent(wh, s).run(force=args.force)
    print(json.dumps(result["summary"], indent=2))
    print(f"Report: {result['report_path']}")


def cmd_review(args, s, wh):
    if args.action == "list":
        registry = read_table(wh, s.governance_dataset, REGISTRY)
        queue = registry[registry.needs_review.astype(bool)] if len(registry) else registry
        columns = ["table_name", "column_name", "category", "confidence", "rationale"]
        print(queue[columns].to_string(index=False) if len(queue) else "Nothing awaiting review.")
        return
    wh.write_rows(s.governance_dataset, OVERRIDES, [{
        "table_name": args.table, "column_name": args.column,
        "category": Category(args.category).value, "reviewer": args.reviewer,
        "reviewed_at": dt.datetime.now(dt.timezone.utc)}], OVERRIDE_SCHEMA)
    print("Recorded. Run `phi-gov scan --force` to rebuild the views.")


def show(answer: Answer) -> None:
    print(f"\nQ: {answer.question}\n{answer.status}")
    print("  trace: " + " -> ".join(answer.trace))
    if answer.final_sql or answer.sql:
        print(f"  sql: {answer.final_sql or answer.sql}")
    if answer.reason:
        print(f"  reason [{answer.stage}]: {answer.reason}")
    if answer.rows is not None:
        print(answer.rows.to_string(index=False))


def cmd_ask(args, s, wh):
    show(AnalyticsAgent(wh, s).ask(args.user, args.question))


def cmd_sql(args, s, wh):
    show(AnalyticsAgent(wh, s).run_sql(args.user, args.sql))


def cmd_audit(args, s, wh):
    log = read_table(wh, s.governance_dataset, AUDIT)
    if log.empty:
        print("Audit log is empty.")
        return
    columns = ["ts", "user_name", "question", "status", "block_stage", "rows_returned", "attempts"]
    print(log.sort_values("ts").tail(args.n)[columns].to_string(index=False))


def cmd_eval(args, s, wh):
    guard = evaluate_guardrails()
    print(f"Guardrails: {guard['attacks_blocked']}/{guard['attacks']} attacks blocked, "
          f"{guard['legitimate_allowed']}/{guard['legitimate']} legitimate queries allowed")
    for name in guard["attacks_escaped"] + guard["legitimate_wrongly_blocked"]:
        print(f"  FAILED: {name}")
    for blind in (False, True):
        r = evaluate_classifier(s, blind=blind)
        print(f"Classifier [{r['classifier']} + {r['detector']}, {r['mode']}]: "
              f"precision {r['phi_precision']}, recall {r['phi_recall']}, "
              f"3-class accuracy {r['three_class_accuracy']}, "
              f"{r['columns_sent_to_review']} sent to review, "
              f"{len(r['phi_columns_exposed_in_views'])} PHI columns exposed")


def cmd_demo(args, s, wh):
    print(f"Backends: {backends(s)}")
    agent = AnalyticsAgent(wh, s)
    for question in DEMO_QUESTIONS:
        show(agent.ask("demo_analyst", question))
    print("\nAudit log:")
    args.n = 5
    cmd_audit(args, s, wh)


def main(argv=None):
    parser = argparse.ArgumentParser(prog="phi-gov", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("load", help="load gold tables (synthetic by default)")
    p.add_argument("--patients", type=int, default=5000)
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--source-dir", help="directory of <table>.parquet files from Project 1")
    p.set_defaults(fn=cmd_load)
    p = sub.add_parser("scan", help="run the PHI discovery agent")
    p.add_argument("--force", action="store_true", help="rescan tables that have not changed")
    p.set_defaults(fn=cmd_scan)
    p = sub.add_parser("review", help="list or approve columns awaiting human review")
    p.add_argument("action", choices=["list", "approve"])
    p.add_argument("table", nargs="?")
    p.add_argument("column", nargs="?")
    p.add_argument("--category", default="NONE", choices=[c.value for c in Category])
    p.add_argument("--reviewer", default=os.environ.get("USER", "reviewer"))
    p.set_defaults(fn=cmd_review)
    p = sub.add_parser("ask", help="ask a question in plain English")
    p.add_argument("question")
    p.add_argument("--user", default=os.environ.get("USER", "analyst"))
    p.set_defaults(fn=cmd_ask)
    p = sub.add_parser("sql", help="send SQL straight to the guardrails (red-team path)")
    p.add_argument("sql")
    p.add_argument("--user", default=os.environ.get("USER", "analyst"))
    p.set_defaults(fn=cmd_sql)
    p = sub.add_parser("audit", help="show the query audit log")
    p.add_argument("-n", type=int, default=20)
    p.set_defaults(fn=cmd_audit)
    sub.add_parser("eval", help="run the guardrail and classifier evals").set_defaults(fn=cmd_eval)
    sub.add_parser("demo", help="blocked query, allowed query, audit log").set_defaults(fn=cmd_demo)
    args = parser.parse_args(argv)
    if args.command == "review" and args.action == "approve" and not (args.table and args.column):
        parser.error("review approve needs TABLE and COLUMN")
    settings = Settings.from_env()
    args.fn(args, settings, make_warehouse(settings))


if __name__ == "__main__":
    main()
