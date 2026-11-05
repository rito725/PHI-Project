from phi_gov.analytics.guardrails import load_policy
from phi_gov.discovery.agent import DiscoveryAgent
from phi_gov.discovery.classifier import ColumnVerdict, RuleBasedClassifier
from phi_gov.discovery.detectors import Finding, LocalDetector, profile_column, shape_of
from phi_gov.discovery.hipaa import POLICY, Category, Transform
from phi_gov.discovery.policy import fail_closed, reconcile
from phi_gov.governance import OVERRIDE_SCHEMA, OVERRIDES, REGISTRY


class AllSafe:
    name = "all-safe"

    def classify(self, table, profiles, findings):
        return [ColumnVerdict(column=p.column, category="NONE", confidence=.99, rationale="x")
                for p in profiles]


class NoFindings:
    name = "none"

    def inspect(self, table, samples):
        return {c: [] for c in samples}


class Broken:
    name = "broken"

    def classify(self, table, profiles, findings):
        raise RuntimeError("API down")


def registry(wh, s):
    return wh.query(f"SELECT * FROM {s.governance_dataset}.{REGISTRY}")


def row(frame, table, column):
    return frame[(frame.table_name == table) & (frame.column_name == column)].iloc[0]


def test_every_category_has_a_policy():
    assert set(POLICY) == set(Category)


def test_all_18_safe_harbor_identifiers_are_covered_by_the_fixture(scanned):
    s, wh, _ = scanned
    found = set(registry(wh, s).category)
    expected = {"NAME", "GEOGRAPHIC", "ZIP", "BIRTH_DATE", "DATE", "PHONE", "FAX", "EMAIL", "SSN",
                "MRN", "HEALTH_PLAN_ID", "ACCOUNT_NUMBER", "LICENSE", "VEHICLE", "DEVICE", "URL",
                "IP_ADDRESS", "BIOMETRIC", "PHOTO", "OTHER_UNIQUE_ID"}
    assert expected <= found


def test_hidden_phi_found_from_values_not_names(scanned):
    s, wh, _ = scanned
    frame = registry(wh, s)
    assert row(frame, "gold_dim_patient", "cust_attr_9").category == "SSN"
    assert row(frame, "gold_dim_patient", "ext_ref_1").category == "PHONE"


def test_zip_lookalike_cpt_code_is_not_flagged():
    values = ["99213", "71046", "93000"]
    assert not [f for f in LocalDetector._inspect_column(values) if f.strong]


def test_shapes_hide_content():
    assert shape_of("(212) 555-0199") == "(999) 999-9999"
    assert shape_of("John Smith") == "Aaaa Aaaaa"
    profile = profile_column("t", "c", "VARCHAR", ["123-45-6789", "John Smith"])
    assert "123-45-6789" not in str(profile) and "John" not in str(profile)


def test_classifier_cannot_silently_overrule_a_strong_detector_hit():
    hit = Finding(Category.SSN, "US_SOCIAL_SECURITY_NUMBER", 1.0, True)
    confident = ColumnVerdict(column="c", category="NONE", confidence=.99, rationale="r")
    d = reconcile("t", "c", "STRING", confident, [hit], .7)
    assert d.needs_review and d.transform is Transform.EXCLUDE_PENDING_REVIEW
    unsure = ColumnVerdict(column="c", category="NONE", confidence=.5, rationale="r")
    d = reconcile("t", "c", "STRING", unsure, [hit], .7)
    assert d.category is Category.SSN and d.needs_review


def test_classifier_may_raise_sensitivity_alone():
    verdict = ColumnVerdict(column="c", category="NAME", confidence=.9, rationale="r")
    d = reconcile("t", "c", "STRING", verdict, [], .7)
    assert d.category is Category.NAME and not d.needs_review


def test_low_confidence_goes_to_review():
    verdict = ColumnVerdict(column="c", category="NONE", confidence=.4, rationale="r")
    assert reconcile("t", "c", "STRING", verdict, [], .7).transform \
        is Transform.EXCLUDE_PENDING_REVIEW


def test_failed_column_is_excluded():
    d = fail_closed("t", "c", "STRING", [], "no verdict")
    assert d.transform is Transform.EXCLUDE_PENDING_REVIEW and d.output_column is None


def test_classifier_outage_exposes_nothing(fresh):
    s, wh = fresh
    DiscoveryAgent(wh, s, classifier=Broken()).run()
    assert wh.list_tables(s.deid_dataset) == []
    assert registry(wh, s).needs_review.all()


def test_classifier_omitting_a_column_hides_that_column(fresh):
    class Partial(RuleBasedClassifier):
        def classify(self, table, profiles, findings):
            return [v for v in super().classify(table, profiles, findings)
                    if v.column != "risk_score"]

    s, wh = fresh
    DiscoveryAgent(wh, s, classifier=Partial()).run()
    assert "risk_score" not in {c.name for c in wh.columns(s.deid_dataset, "dim_patient")}


def test_conflicting_classifier_cannot_expose_detected_phi(fresh):
    s, wh = fresh
    DiscoveryAgent(wh, s, classifier=AllSafe()).run()
    columns = {c.name for c in wh.columns(s.deid_dataset, "dim_patient")}
    assert not {"ssn", "email", "phone", "cust_attr_9"} & columns


def test_verification_quarantines_a_leaking_view(fresh):
    """Worst case: classifier and detector both miss everything. The view is built, then
    the post-build scan finds identifiers in its output and removes it."""
    s, wh = fresh
    result = DiscoveryAgent(wh, s, classifier=AllSafe(), detector=NoFindings()).run()
    assert "gold_dim_patient" in result["quarantined"]
    assert "dim_patient" not in wh.list_tables(s.deid_dataset)
    assert "dim_patient" not in load_policy(wh, s).allowed_tables


def test_only_new_tables_are_scanned(fresh):
    s, wh = fresh
    agent = DiscoveryAgent(wh, s)
    assert agent.run()["summary"]["tables_scanned_this_run"] == 5
    assert agent.run()["summary"]["tables_scanned_this_run"] == 0
    wh.execute(f"CREATE TABLE {s.gold_dataset}.gold_lab_result AS "
               f"SELECT 'x@example.org' AS contact_email, 1.5 AS result_value")
    summary = agent.run()["summary"]
    assert summary["tables_scanned_this_run"] == 1 and summary["tables_in_gold"] == 6
    columns = {c.name for c in wh.columns(s.deid_dataset, "lab_result")}
    assert "contact_email" not in columns
    assert len(registry(wh, s).table_name.unique()) == 6


def test_new_column_stays_hidden_until_scanned(fresh):
    s, wh = fresh
    agent = DiscoveryAgent(wh, s)
    agent.run()
    wh.execute(f"CREATE OR REPLACE TABLE {s.gold_dataset}.gold_dim_provider AS "
               f"SELECT *, 'secret' AS new_col FROM {s.gold_dataset}.gold_dim_provider")
    assert "new_col" not in {c.name for c in wh.columns(s.deid_dataset, "dim_provider")}
    assert agent.run()["summary"]["tables_scanned_this_run"] == 1


def test_human_approval_releases_a_column(fresh):
    s, wh = fresh
    agent = DiscoveryAgent(wh, s)
    agent.run()
    assert "provider_name" not in {c.name for c in wh.columns(s.deid_dataset, "dim_provider")}
    wh.write_rows(s.governance_dataset, OVERRIDES, [{
        "table_name": "gold_dim_provider", "column_name": "provider_name", "category": "NONE",
        "reviewer": "privacy.officer", "reviewed_at": "2026-01-01 00:00:00"}], OVERRIDE_SCHEMA)
    result = agent.run(force=True)
    assert "gold_dim_provider" not in result["quarantined"]
    assert "provider_name" in {c.name for c in wh.columns(s.deid_dataset, "dim_provider")}
    assert row(registry(wh, s), "gold_dim_provider", "provider_name").human_reviewed


def test_policy_tags_follow_the_tier(scanned):
    s, wh, _ = scanned
    tags = wh.query(f"SELECT * FROM {s.governance_dataset}.policy_tag_assignments")
    lookup = {(r.table_name, r.column_name): r.policy_tag for r in tags.itertuples()}
    assert lookup[("gold_dim_patient", "ssn")] == "direct_identifier"
    assert lookup[("gold_dim_patient", "mrn")] == "pseudonymized_identifier"
    assert lookup[("gold_dim_patient", "dob")] == "quasi_identifier"
    assert ("gold_dim_patient", "state") not in lookup


def test_report_is_written(scanned):
    _, _, result = scanned
    with open(result["report_path"]) as fh:
        text = fh.read()
    assert "Awaiting human review" in text and "offline-rules" in text
