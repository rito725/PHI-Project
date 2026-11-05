"""PHI discovery agent, a LangGraph pipeline.

discover -> sample_and_detect -> classify -> persist -> build_views -> verify_views
         -> apply_policy_tags -> report
"""
from __future__ import annotations

import datetime as dt
import hashlib
import secrets
import time
from pathlib import Path
from typing import TypedDict

import pandas as pd
from langgraph.graph import END, START, StateGraph

from phi_gov.config import Settings
from phi_gov.discovery.classifier import make_classifier
from phi_gov.discovery.deid import build_view_sql, create_view_ddl, view_name
from phi_gov.discovery.detectors import LocalDetector, make_detector, profile_column
from phi_gov.discovery.hipaa import Category, Tier, Transform, tier_of
from phi_gov.discovery.policy import Decision, fail_closed, reconcile, to_row
from phi_gov.governance import (OVERRIDES, REGISTRY, REGISTRY_SCHEMA, TAG_SCHEMA, TAGS,
                                read_table)
from phi_gov.warehouse.base import Warehouse

# A hit on any of these in view output means something leaked. Dates and ZIP-like values
# are excluded because years and ZIP3s are legitimate output.
_LEAK_CATEGORIES = {Category.SSN, Category.EMAIL, Category.PHONE, Category.IP_ADDRESS,
                    Category.URL, Category.NAME, Category.VEHICLE}
_VERIFY_SAMPLE = 500


class ScanState(TypedDict, total=False):
    started: float
    force: bool
    tables: dict[str, list]            # pending table -> columns
    hashes: dict[str, str]
    total_tables: int
    samples: dict[str, dict[str, list[str]]]
    profiles: dict[str, list]
    findings: dict[str, dict]
    decisions: dict[str, list[Decision]]
    views: dict[str, str]
    quarantined: dict[str, str]
    report_path: str
    summary: dict


def schema_hash(columns) -> str:
    text = ",".join(f"{c.name}:{c.data_type}" for c in columns)
    return hashlib.sha256(text.encode()).hexdigest()[:16]


def ensure_salt(wh: Warehouse, s: Settings) -> None:
    if wh.table_exists(s.restricted_dataset, "deid_secret"):
        return
    wh.write_rows(s.restricted_dataset, "deid_secret", [{"salt": secrets.token_hex(32)}],
                  [("salt", "STRING")])


class DiscoveryAgent:
    def __init__(self, wh: Warehouse, settings: Settings, classifier=None, detector=None):
        self.wh, self.s = wh, settings
        self.classifier = classifier or make_classifier(settings)
        self.detector = detector or make_detector(settings)
        self.graph = self._build()

    def _build(self):
        g = StateGraph(ScanState)
        for name in ("discover", "sample_and_detect", "classify", "persist", "build_views",
                     "verify_views", "apply_policy_tags", "report"):
            g.add_node(name, getattr(self, name))
        g.add_edge(START, "discover")
        g.add_conditional_edges("discover", lambda st: "work" if st["tables"] else "idle",
                                {"work": "sample_and_detect", "idle": "report"})
        for a, b in [("sample_and_detect", "classify"), ("classify", "persist"),
                     ("persist", "build_views"), ("build_views", "verify_views"),
                     ("verify_views", "apply_policy_tags"), ("apply_policy_tags", "report"),
                     ("report", END)]:
            g.add_edge(a, b)
        return g.compile()

    def run(self, force: bool = False) -> ScanState:
        return self.graph.invoke({"started": time.time(), "force": force})

    def discover(self, st: ScanState) -> dict:
        s = self.s
        for dataset in (s.gold_dataset, s.deid_dataset, s.governance_dataset, s.restricted_dataset):
            self.wh.ensure_dataset(dataset)
        ensure_salt(self.wh, s)
        registry = read_table(self.wh, s.governance_dataset, REGISTRY)
        known = {} if registry.empty else dict(zip(registry.table_name, registry.schema_hash))
        pending, hashes = {}, {}
        all_tables = self.wh.list_tables(s.gold_dataset)
        for table in all_tables:
            columns = self.wh.columns(s.gold_dataset, table)
            hashes[table] = schema_hash(columns)
            if st.get("force") or known.get(table) != hashes[table]:
                pending[table] = columns
        return {"tables": pending, "hashes": hashes, "total_tables": len(all_tables)}

    def sample_and_detect(self, st: ScanState) -> dict:
        samples, profiles, findings = {}, {}, {}
        for table, columns in st["tables"].items():
            samples[table] = {c.name: self.wh.sample_column(
                self.s.gold_dataset, table, c.name, self.s.sample_size) for c in columns}
            profiles[table] = [profile_column(table, c.name, c.data_type, samples[table][c.name])
                               for c in columns]
            findings[table] = self.detector.inspect(table, samples[table])
        # Raw samples are dropped here, before any node that talks to the LLM.
        return {"profiles": profiles, "findings": findings, "samples": {}}

    def classify(self, st: ScanState) -> dict:
        overrides = read_table(self.wh, self.s.governance_dataset, OVERRIDES)
        reviewed = {} if overrides.empty else {
            (r.table_name, r.column_name): {"category": r.category, "reviewer": r.reviewer}
            for r in overrides.sort_values("reviewed_at").itertuples()}
        decisions: dict[str, list[Decision]] = {}
        for table, columns in st["tables"].items():
            findings = st["findings"][table]
            try:
                verdicts = {v.column: v for v in self.classifier.classify(
                    table, st["profiles"][table], findings)}
                failure = "Classifier returned no verdict for this column."
            except Exception as err:  # any failure must hide data, not expose it
                verdicts, failure = {}, f"Classifier failed: {type(err).__name__}."
            out = []
            for c in columns:
                column_findings = findings.get(c.name, [])
                override = reviewed.get((table, c.name))
                if c.name in verdicts or override:
                    out.append(reconcile(table, c.name, c.data_type, verdicts.get(c.name),
                                         column_findings, self.s.review_confidence, override))
                else:
                    out.append(fail_closed(table, c.name, c.data_type, column_findings, failure))
            decisions[table] = out
        return {"decisions": decisions}

    def persist(self, st: ScanState) -> dict:
        s = self.s
        now = dt.datetime.now(dt.timezone.utc)
        rows = [to_row(d, st["hashes"][t], self.classifier.name, self.detector.name, now)
                for t, ds in st["decisions"].items() for d in ds]
        existing = read_table(self.wh, s.governance_dataset, REGISTRY)
        if not existing.empty:
            keep = existing[~existing.table_name.isin(st["decisions"])]
            keep = keep.astype(object).where(keep.notna(), None)
            rows = keep.to_dict("records") + rows
        self.wh.write_rows(s.governance_dataset, REGISTRY, rows, REGISTRY_SCHEMA, truncate=True)
        return {}

    def build_views(self, st: ScanState) -> dict:
        views = {}
        for table, decisions in st["decisions"].items():
            sql = build_view_sql(table, decisions, self.s)
            if sql is None:
                self.wh.execute(f"DROP VIEW IF EXISTS {self.s.deid_dataset}.{view_name(table)}")
                continue
            self.wh.execute(create_view_ddl(table, sql, self.s))
            views[table] = sql
        self.wh.authorize_views(self.s.gold_dataset, self.s.deid_dataset)
        self.wh.authorize_views(self.s.restricted_dataset, self.s.deid_dataset)
        return {"views": views}

    def verify_views(self, st: ScanState) -> dict:
        """Scan what the views actually return. If identifiers show up, the view is
        dropped, so a classification mistake cannot reach analysts."""
        s, detector = self.s, LocalDetector()
        quarantined: dict[str, str] = {}
        for table in st["views"]:
            view = view_name(table)
            approved = {d.output_column for d in st["decisions"][table] if d.reviewed}
            df = self.wh.query(f"SELECT * FROM {s.deid_dataset}.{view} LIMIT {_VERIFY_SAMPLE}")
            leaks = []
            for column in df.columns:
                if column in approved:
                    continue
                values = df[column].dropna().astype(str).tolist()
                leaks += [f"{column}:{f.info_type}" for f in detector.inspect(
                    view, {column: values})[column] if f.category in _LEAK_CATEGORIES and f.strong]
            if leaks:
                self.wh.execute(f"DROP VIEW IF EXISTS {s.deid_dataset}.{view}")
                quarantined[table] = ", ".join(leaks)
        return {"quarantined": quarantined}

    def apply_policy_tags(self, st: ScanState) -> dict:
        now = dt.datetime.now(dt.timezone.utc)
        rows = []
        for table, decisions in st["decisions"].items():
            tags = {d.column: _tag_for(d) for d in decisions if _tag_for(d)}
            self.wh.apply_policy_tags(self.s.gold_dataset, table, tags)
            rows += [{"table_name": table, "column_name": c, "policy_tag": t, "applied_at": now}
                     for c, t in tags.items()]
        existing = read_table(self.wh, self.s.governance_dataset, TAGS)
        if not existing.empty:
            rows = existing[~existing.table_name.isin(st["decisions"])].to_dict("records") + rows
        self.wh.write_rows(self.s.governance_dataset, TAGS, rows, TAG_SCHEMA, truncate=True)
        return {}

    def report(self, st: ScanState) -> dict:
        registry = read_table(self.wh, self.s.governance_dataset, REGISTRY)
        summary = {
            "tables_in_gold": st.get("total_tables", 0),
            "tables_scanned_this_run": len(st["tables"]),
            "columns_scanned_this_run": sum(len(c) for c in st["tables"].values()),
            "runtime_seconds": round(time.time() - st["started"], 2),
            "views_created": len(st.get("views", {})) - len(st.get("quarantined", {})),
            "views_quarantined": st.get("quarantined", {}),
        }
        path = write_report(registry, summary, self.s, self.wh)
        return {"report_path": str(path), "summary": summary}


def _tag_for(d: Decision) -> str | None:
    if tier_of(d.category) is Tier.SAFE:
        return None
    if d.transform is Transform.HASH:
        return "pseudonymized_identifier"
    return d.tier.value


def write_report(registry: pd.DataFrame, summary: dict, s: Settings, wh: Warehouse) -> Path:
    path = Path(s.reports_dir) / "governance_report.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = ["# PHI governance report", "",
             f"Generated {dt.datetime.now(dt.timezone.utc):%Y-%m-%d %H:%M} UTC.", "",
             f"- Warehouse: `{wh.name}`",
             f"- Classifier: `{', '.join(sorted(registry.classifier.unique())) if len(registry) else 'n/a'}`",
             f"- Detector: `{', '.join(sorted(registry.detector.unique())) if len(registry) else 'n/a'}`"]
    lines += [f"- {k.replace('_', ' ').capitalize()}: {v}" for k, v in summary.items()]
    if len(registry):
        lines += ["", "## Columns by tier", "", "| Tier | Columns |", "|---|---|"]
        lines += [f"| {t} | {n} |" for t, n in registry.tier.value_counts().items()]
        lines += ["", "## Columns by transform", "", "| Transform | Columns |", "|---|---|"]
        lines += [f"| {t} | {n} |" for t, n in registry["transform"].value_counts().items()]
        review = registry[registry.needs_review.astype(bool)]
        lines += ["", f"## Awaiting human review ({len(review)})", ""]
        if len(review):
            lines += ["These columns are hidden from every view until someone approves them.", "",
                      "| Table | Column | Proposed category | Confidence | Why |", "|---|---|---|---|---|"]
            lines += [f"| {r.table_name} | {r.column_name} | {r.category} | {r.confidence:.2f} | "
                      f"{r.rationale.replace('|', '/')} |" for r in review.itertuples()]
        lines += ["", "## All columns", "",
                  "| Table | Column | Tier | Category | Confidence | Transform | Output |",
                  "|---|---|---|---|---|---|---|"]
        lines += [f"| {r.table_name} | {r.column_name} | {r.tier} | {r.category} | "
                  f"{r.confidence:.2f} | {r.transform} | {r.output_column or ''} |"
                  for r in registry.sort_values(['table_name', 'column_name']).itertuples()]
    path.write_text("\n".join(lines) + "\n")
    return path
