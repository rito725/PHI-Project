"""Streamlit UI: run with `streamlit run app/streamlit_app.py`."""
from __future__ import annotations

import streamlit as st

from phi_gov.analytics.agent import ALLOWED, BLOCKED, AnalyticsAgent, Answer
from phi_gov.cli import DEMO_QUESTIONS
from phi_gov.config import Settings
from phi_gov.discovery.deid import view_name
from phi_gov.governance import AUDIT, REGISTRY, read_table
from phi_gov.warehouse.factory import make_warehouse

st.set_page_config(page_title="PHI governance", layout="wide")


@st.cache_resource
def services():
    settings = Settings.from_env()
    warehouse = make_warehouse(settings)
    return settings, warehouse, AnalyticsAgent(warehouse, settings)


settings, wh, agent = services()
registry = read_table(wh, settings.governance_dataset, REGISTRY)

st.title("PHI governance and guarded analytics")
st.caption("All data here is synthetic. Personal project, not a certified HIPAA system.")

with st.sidebar:
    st.subheader("Backends")
    st.write(f"Warehouse: `{settings.warehouse_backend}`")
    st.write(f"Detector: `{settings.dlp_backend}`")
    st.write(f"LLM: `{settings.llm_backend}`")
    if settings.llm_backend == "offline":
        st.info("Offline mode: SQL comes from fixed templates, not Claude. "
                "Set ANTHROPIC_API_KEY for free-form questions.")
    user = st.text_input("Analyst", "demo_analyst")

if registry.empty:
    st.warning("No governance data yet. Run `phi-gov load`, then `phi-gov scan`.")
    st.stop()


def render(answer: Answer) -> None:
    if answer.status == ALLOWED:
        st.success(f"ALLOWED: {answer.rows_returned} rows")
    elif answer.status == BLOCKED:
        st.error(f"BLOCKED at {answer.stage}")
    else:
        st.warning(f"ERROR at {answer.stage}")
    if answer.reason:
        st.write(answer.reason)
    if answer.final_sql or answer.sql:
        st.code(answer.final_sql or answer.sql, language="sql")
    if answer.rows is not None:
        st.dataframe(answer.rows, hide_index=True, width="stretch")
    st.caption(" → ".join(answer.trace))


demo, ask, governance, audit = st.tabs(["Demo", "Ask", "Governance", "Audit log"])

with demo:
    st.write("The same agent handles both questions. One is stopped before it reaches the warehouse.")
    if st.button("Run demo", type="primary"):
        st.session_state["demo"] = [agent.ask(user, q) for q in DEMO_QUESTIONS]
    if "demo" in st.session_state:
        for column, answer in zip(st.columns(2), st.session_state["demo"]):
            with column:
                st.subheader(answer.question)
                render(answer)

with ask:
    question = st.text_input("Question", "readmission rate by payer in 2025")
    if st.button("Ask"):
        render(agent.ask(user, question))
    st.divider()
    st.subheader("Red team")
    st.write("Send SQL directly to the guardrails, skipping the SQL writer.")
    sql = st.text_area("SQL", "SELECT ssn FROM phi_gold.gold_dim_patient")
    if st.button("Run through guardrails"):
        render(agent.run_sql(user, sql))

with governance:
    review = registry[registry.needs_review.astype(bool)]
    a, b, c, d = st.columns(4)
    a.metric("Columns scanned", len(registry))
    b.metric("Direct identifiers", int((registry.tier == "direct_identifier").sum()))
    c.metric("Quasi-identifiers", int((registry.tier == "quasi_identifier").sum()))
    d.metric("Awaiting review", len(review))
    if len(review):
        st.subheader("Awaiting human review")
        st.caption("Hidden from all views until approved with `phi-gov review approve`.")
        st.dataframe(review[["table_name", "column_name", "category", "confidence", "rationale"]],
                     hide_index=True, width="stretch")
    st.subheader("Classifications")
    table = st.selectbox("Table", sorted(registry.table_name.unique()))
    shown = registry[registry.table_name == table]
    st.dataframe(
        shown[["column_name", "tier", "category", "confidence", "transform", "output_column"]],
        hide_index=True, width="stretch")
    st.caption(f"View: {settings.deid_dataset}.{view_name(table)}")

with audit:
    log = read_table(wh, settings.governance_dataset, AUDIT)
    if log.empty:
        st.write("No queries yet.")
    else:
        columns = ["ts", "user_name", "question", "status", "block_stage", "block_reason",
                   "rows_returned", "bytes_estimated", "attempts", "sql_text"]
        st.dataframe(log.sort_values("ts", ascending=False)[columns],
                     hide_index=True, width="stretch")
