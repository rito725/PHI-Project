"""The Claude, DLP and BigQuery paths can't be called from CI. These pin down what can be
checked without credentials: real SDK request building and response parsing against a
local stub, and real proto types for DLP."""
import json
import threading
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest.mock import MagicMock, patch

import anthropic
import pytest
from google.cloud import bigquery, dlp_v2

from phi_gov.analytics.writer import ClaudeSqlWriter
from phi_gov.config import Settings
from phi_gov.discovery.agent import DiscoveryAgent
from phi_gov.discovery.classifier import ClaudeClassifier, render_prompt
from phi_gov.discovery.detectors import CloudDlpDetector, Finding, profile_column
from phi_gov.discovery.hipaa import Category


@pytest.fixture
def stub_api():
    state = {"requests": [], "reply": {}, "stop_reason": "end_turn"}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["content-length"])))
            state["requests"].append({"path": self.path, "body": body,
                                      "beta": self.headers.get("anthropic-beta")})
            payload = json.dumps({
                "id": "msg_1", "type": "message", "role": "assistant", "model": body["model"],
                "content": [{"type": "text", "text": json.dumps(state["reply"])}],
                "stop_reason": state["stop_reason"], "stop_sequence": None,
                "usage": {"input_tokens": 1, "output_tokens": 1},
            }).encode()
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    client = anthropic.Anthropic(api_key="test", base_url=f"http://127.0.0.1:{server.server_port}",
                                 max_retries=0)
    yield client, state
    server.shutdown()


def test_classifier_request_and_response(stub_api):
    client, state = stub_api
    state["reply"] = {"columns": [{"column": "ssn", "category": "SSN", "confidence": .98,
                                   "rationale": "shape"}]}
    profile = profile_column("t", "ssn", "STRING", ["123-45-6789"])
    verdicts = ClaudeClassifier("claude-opus-5-5", client).classify("t", [profile], {})
    assert verdicts[0].category == "SSN"
    request = state["requests"][0]
    body = request["body"]
    assert body["model"] == "claude-opus-5-5"
    assert body["output_config"]["effort"] == "medium"
    assert body["output_config"]["format"]["type"] == "json_schema"
    assert body["fallbacks"] == "default"
    assert "server-side-fallback-2026-07-01" in request["beta"]
    assert "temperature" not in body and "thinking" not in body


def test_classifier_refusal_raises(stub_api):
    client, state = stub_api
    state["stop_reason"], state["reply"] = "refusal", {"columns": []}
    with pytest.raises(RuntimeError):
        ClaudeClassifier("claude-opus-5-5", client).classify(
            "t", [profile_column("t", "c", "STRING", ["x"])], {})


def test_sql_writer_request_and_response(stub_api):
    client, state = stub_api
    state["reply"] = {"sql": "SELECT 1", "cannot_answer": False, "reason": "ok"}
    draft = ClaudeSqlWriter("claude-opus-5-5", client).write("q", "schema", "SELECT x", "bad column")
    assert draft.sql == "SELECT 1"
    text = state["requests"][0]["body"]["messages"][0]["content"]
    assert "bad column" in text and "SELECT x" in text


def test_no_raw_value_reaches_the_llm(tmp_path):
    from tests.conftest import build

    class Recorder:
        name = "recorder"
        prompts: list[str] = []

        def classify(self, table, profiles, findings):
            self.prompts.append(render_prompt(table, profiles, findings))
            return []

    s, wh = build(tmp_path, n_patients=100)
    recorder = Recorder()
    DiscoveryAgent(wh, s, classifier=recorder).run()
    sent = "\n".join(recorder.prompts)
    raw = wh.query(f"SELECT ssn, email, phone, last_name, mrn FROM {s.gold_dataset}.gold_dim_patient")
    for column in raw.columns:
        for value in raw[column]:
            assert str(value) not in sent, f"{column} value reached the prompt"
    notes = wh.query(f"SELECT clinical_note FROM {s.gold_dataset}.gold_fct_encounter").clinical_note
    assert not any(note in sent for note in notes)


def test_dlp_request_is_a_valid_proto_and_never_asks_for_quotes():
    detector = CloudDlpDetector("proj", client=MagicMock())
    request = detector.build_request({"a": ["1", "2"], "b": ["x"]})
    proto = dlp_v2.InspectContentRequest(request)
    assert proto.parent == "projects/proj/locations/global"
    assert len(proto.item.table.rows) == 2 and proto.item.table.rows[1].values[1].string_value == ""
    assert proto.inspect_config.include_quote is False
    assert proto.inspect_config.min_likelihood == dlp_v2.Likelihood.POSSIBLE


def test_dlp_response_is_parsed_into_findings():
    def finding(column, row, likelihood, info_type="US_SOCIAL_SECURITY_NUMBER"):
        return dlp_v2.Finding(
            info_type={"name": info_type}, likelihood=likelihood,
            location={"content_locations": [{"record_location": {
                "field_id": {"name": column}, "table_location": {"row_index": row}}}]})

    response = dlp_v2.InspectContentResponse(result={"findings": [
        finding("a", 0, dlp_v2.Likelihood.VERY_LIKELY),
        finding("a", 1, dlp_v2.Likelihood.LIKELY),
        finding("b", 0, dlp_v2.Likelihood.POSSIBLE, "DATE"),
    ]})
    client = MagicMock()
    client.inspect_content.return_value = response
    found = CloudDlpDetector("proj", client=client).inspect(
        "t", {"a": ["1", "2"], "b": ["1", "2"], "c": ["1"]})
    assert found["a"] == [Finding(Category.SSN, "US_SOCIAL_SECURITY_NUMBER", 1.0, True)]
    assert found["b"] == [Finding(Category.DATE, "DATE", .5, False)]
    assert found["c"] == []


def test_every_info_type_maps_to_a_category():
    from phi_gov.discovery.detectors import INFO_TYPES
    assert all(isinstance(c, Category) for c in INFO_TYPES.values())


@pytest.fixture
def bq():
    with patch("phi_gov.warehouse.bigquery_wh.bigquery.Client"):
        from phi_gov.warehouse.bigquery_wh import BigQueryWarehouse
        yield BigQueryWarehouse(replace(Settings(), gcp_project="proj"))


def test_policy_tags_are_merged_into_the_schema(bq):
    table = MagicMock()
    table.schema = [bigquery.SchemaField("ssn", "STRING"), bigquery.SchemaField("state", "STRING")]
    bq.client.get_table.return_value = table
    with patch.object(bq, "_policy_tags", return_value={"direct_identifier": "tag/1"}):
        bq.apply_policy_tags("phi_gold", "t", {"ssn": "direct_identifier"})
    ssn, state = table.schema
    assert ssn.to_api_repr()["policyTags"]["names"] == ["tag/1"]
    assert not state.to_api_repr().get("policyTags", {}).get("names")
    bq.client.update_table.assert_called_once_with(table, ["schema"])


def test_view_authorization_is_idempotent_and_targets_views(bq):
    dataset = MagicMock()
    dataset.access_entries = []
    bq.client.get_dataset.return_value = dataset
    bq.authorize_views("phi_gold", "phi_deid")
    entry = dataset.access_entries[0].to_api_repr()
    assert entry["dataset"] == {"dataset": {"projectId": "proj", "datasetId": "phi_deid"},
                                "targetTypes": ["VIEWS"]}
    bq.authorize_views("phi_gold", "phi_deid")
    assert len(dataset.access_entries) == 1


def test_write_rows_payload_is_json_serialisable(bq):
    """Registry rows come back through pandas holding numpy scalars and Timestamps."""
    import numpy as np
    import pandas as pd
    rows = [{"a": np.bool_(True), "b": np.float64(.5), "c": pd.Timestamp("2026-01-01"), "d": None}]
    bq.write_rows("d", "t", rows, [("a", "BOOL"), ("b", "FLOAT64"), ("c", "TIMESTAMP"), ("d", "STRING")])
    payload = bq.client.load_table_from_json.call_args.args[0]
    assert json.loads(json.dumps(payload)) == [
        {"a": True, "b": .5, "c": "2026-01-01T00:00:00", "d": None}]


def test_write_rows_with_nothing_to_write_is_a_no_op(bq):
    bq.write_rows("d", "t", [], [("a", "STRING")], truncate=True)
    bq.client.load_table_from_json.assert_not_called()
