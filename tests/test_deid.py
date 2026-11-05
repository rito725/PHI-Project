"""Do the views actually de-identify? These assert on rows returned, not on SQL text."""
import sqlglot

from phi_gov.discovery.deid import build_view_sql
from phi_gov.discovery.hipaa import RESTRICTED_ZIP3


def view_cells(wh, s):
    cells = set()
    for view in wh.list_tables(s.deid_dataset):
        frame = wh.query(f"SELECT * FROM {s.deid_dataset}.{view}")
        for column in frame.columns:
            cells |= set(frame[column].dropna().astype(str))
    return cells


def test_no_raw_identifier_appears_in_any_view(scanned):
    s, wh, _ = scanned
    cells = view_cells(wh, s)
    allowed_overlap = set(wh.query(f"SELECT DISTINCT race FROM {s.deid_dataset}.dim_patient").race)
    targets = {
        "gold_dim_patient": ["mrn", "ssn", "first_name", "last_name", "email", "phone", "fax",
                             "address_line", "city", "zip", "ext_ref_1", "cust_attr_9",
                             "account_number", "drivers_license", "vehicle_plate",
                             "emergency_contact_name", "employer_name"],
        "gold_fct_encounter": ["encounter_id", "clinical_note", "implant_device_serial"],
        "gold_fct_claim": ["claim_id", "member_id"],
        "gold_fct_portal_activity": ["login_ip", "device_id", "portal_url", "photo_url",
                                     "fingerprint_template"],
    }
    for table, columns in targets.items():
        for column in columns:
            raw = wh.query(f"SELECT DISTINCT CAST(`{column}` AS STRING) AS v "
                           f"FROM {s.gold_dataset}.{table} WHERE `{column}` IS NOT NULL")
            # Surnames such as White and Black are also legitimate race values.
            leaked = (set(raw["v"]) & cells) - allowed_overlap
            assert not leaked, f"{table}.{column} leaked {list(leaked)[:3]}"


def test_no_date_finer_than_year(scanned):
    s, wh, _ = scanned
    for view in wh.list_tables(s.deid_dataset):
        for column in wh.columns(s.deid_dataset, view):
            assert column.data_type not in ("DATE", "TIMESTAMP"), f"{view}.{column.name}"
    years = wh.query(f"SELECT DISTINCT admit_year FROM {s.deid_dataset}.fct_encounter")
    assert years.admit_year.between(2023, 2027).all()


def test_restricted_zip3_become_000(scanned):
    s, wh, _ = scanned
    deid = set(wh.query(f"SELECT DISTINCT zip3 FROM {s.deid_dataset}.dim_patient").zip3)
    assert "000" in deid, "fixture should contain low-population ZIP3s"
    assert not deid & set(RESTRICTED_ZIP3)
    assert all(len(z) == 3 for z in deid)


def test_ages_over_89_are_aggregated(scanned):
    s, wh, _ = scanned
    frame = wh.query(f"SELECT birth_year, age_capped FROM {s.deid_dataset}.dim_patient")
    assert frame.age_capped.max() == 90, "fixture should contain patients over 89"
    this_year = wh.query("SELECT EXTRACT(YEAR FROM CURRENT_DATE()) AS y").y[0]
    assert (this_year - frame.birth_year.dropna()).max() <= 89
    assert frame.birth_year.isna().sum() > 0


def test_pseudonyms_join_across_views(scanned):
    s, wh, _ = scanned
    matched = wh.query(
        f"SELECT COUNT(*) AS n FROM {s.deid_dataset}.fct_encounter e "
        f"JOIN {s.deid_dataset}.dim_patient p ON e.patient_key = p.patient_key").n[0]
    total = wh.query(f"SELECT COUNT(*) AS n FROM {s.gold_dataset}.gold_fct_encounter").n[0]
    assert matched == total


def test_hash_is_salted_and_salt_stays_out_of_view_text(scanned):
    s, wh, result = scanned
    salt = wh.query(f"SELECT salt FROM {s.restricted_dataset}.deid_secret").salt[0]
    assert all(salt not in sql for sql in result["views"].values())
    keys = set(wh.query(f"SELECT mrn_key FROM {s.deid_dataset}.dim_patient").mrn_key)
    unsalted = wh.query(f"SELECT TO_HEX(SHA256(mrn)) AS h FROM {s.gold_dataset}.gold_dim_patient").h
    assert not keys & set(unsalted)


def test_null_keys_stay_null(fresh):
    """BigQuery CONCAT returns NULL on NULL input but DuckDB's does not. A NULL key must
    not turn into the hash of the bare salt on either engine."""
    from phi_gov.discovery.agent import DiscoveryAgent
    s, wh = fresh
    wh.execute(f"CREATE OR REPLACE TABLE {s.gold_dataset}.gold_fct_claim AS "
               f"SELECT * REPLACE (CAST(NULL AS STRING) AS encounter_id) "
               f"FROM {s.gold_dataset}.gold_fct_claim")
    DiscoveryAgent(wh, s).run()
    keys = wh.query(f"SELECT encounter_key FROM {s.deid_dataset}.fct_claim").encounter_key
    assert len(keys) > 0 and keys.isna().all()


def test_view_sql_is_valid_bigquery(scanned):
    _, _, result = scanned
    for sql in result["views"].values():
        sqlglot.parse_one(sql, dialect="bigquery")
        assert "SELECT *" not in sql


def test_unsafe_column_name_is_never_templated(scanned):
    from phi_gov.discovery.hipaa import Category
    from phi_gov.discovery.policy import Decision
    s, _, _ = scanned
    evil = "x` FROM phi_gold.t; DROP TABLE y; --"
    decisions = [Decision("gold_t", evil, "STRING", Category.NONE, 1.0, ""),
                 Decision("gold_t", "ok", "STRING", Category.NONE, 1.0, "")]
    sql = build_view_sql("gold_t", decisions, s)
    assert "DROP" not in sql and "`ok`" in sql
