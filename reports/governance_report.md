# PHI governance report

Generated 2026-11-04 17:24 UTC.

- Warehouse: `duckdb`
- Classifier: `offline-rules`
- Detector: `local-regex`
- Tables in gold: 5
- Tables scanned this run: 5
- Columns scanned this run: 71
- Runtime seconds: 1.91
- Views created: 5
- Views quarantined: {}

## Columns by tier

| Tier | Columns |
|---|---|
| direct_identifier | 33 |
| safe | 26 |
| quasi_identifier | 12 |

## Columns by transform

| Transform | Columns |
|---|---|
| KEEP | 27 |
| DROP | 23 |
| HASH | 10 |
| YEAR | 6 |
| EXCLUDE_PENDING_REVIEW | 2 |
| BIRTH_YEAR | 1 |
| AGE_CAP | 1 |
| ZIP3 | 1 |

## Awaiting human review (2)

These columns are hidden from every view until someone approves them.

| Table | Column | Proposed category | Confidence | Why |
|---|---|---|---|---|
| gold_dim_provider | provider_name | NONE | 0.90 | Provider or facility data, not about a patient. Conflict: Detector found PERSON_NAME on 100% of sampled values. |
| gold_dim_provider | facility_phone | NONE | 0.90 | Provider or facility data, not about a patient. Conflict: Detector found PHONE_NUMBER on 100% of sampled values. |

## All columns

| Table | Column | Tier | Category | Confidence | Transform | Output |
|---|---|---|---|---|---|---|
| gold_dim_patient | account_number | direct_identifier | ACCOUNT_NUMBER | 0.90 | DROP | nan |
| gold_dim_patient | address_line | direct_identifier | GEOGRAPHIC | 0.92 | DROP | nan |
| gold_dim_patient | age | quasi_identifier | AGE | 0.90 | AGE_CAP | age_capped |
| gold_dim_patient | city | direct_identifier | GEOGRAPHIC | 0.92 | DROP | nan |
| gold_dim_patient | cust_attr_9 | direct_identifier | SSN | 1.00 | DROP | nan |
| gold_dim_patient | dob | quasi_identifier | BIRTH_DATE | 0.95 | BIRTH_YEAR | birth_year |
| gold_dim_patient | drivers_license | direct_identifier | LICENSE | 0.90 | DROP | nan |
| gold_dim_patient | email | direct_identifier | EMAIL | 1.00 | DROP | nan |
| gold_dim_patient | emergency_contact_name | direct_identifier | NAME | 1.00 | DROP | nan |
| gold_dim_patient | employer_name | direct_identifier | NAME | 0.92 | DROP | nan |
| gold_dim_patient | ext_ref_1 | direct_identifier | PHONE | 1.00 | DROP | nan |
| gold_dim_patient | fax | direct_identifier | FAX | 0.90 | DROP | nan |
| gold_dim_patient | first_name | direct_identifier | NAME | 0.92 | DROP | nan |
| gold_dim_patient | gender | quasi_identifier | DEMOGRAPHIC | 0.85 | KEEP | gender |
| gold_dim_patient | is_current | safe | NONE | 0.80 | KEEP | is_current |
| gold_dim_patient | last_name | direct_identifier | NAME | 0.92 | DROP | nan |
| gold_dim_patient | mrn | direct_identifier | MRN | 0.95 | HASH | mrn_key |
| gold_dim_patient | patient_sk | direct_identifier | OTHER_UNIQUE_ID | 0.80 | HASH | patient_key |
| gold_dim_patient | phone | direct_identifier | PHONE | 1.00 | DROP | nan |
| gold_dim_patient | preferred_language | quasi_identifier | DEMOGRAPHIC | 0.85 | KEEP | preferred_language |
| gold_dim_patient | race | quasi_identifier | DEMOGRAPHIC | 0.85 | KEEP | race |
| gold_dim_patient | risk_score | safe | NONE | 0.80 | KEEP | risk_score |
| gold_dim_patient | ssn | direct_identifier | SSN | 1.00 | DROP | nan |
| gold_dim_patient | state | safe | NONE | 0.80 | KEEP | state |
| gold_dim_patient | valid_from | quasi_identifier | DATE | 1.00 | YEAR | valid_from_year |
| gold_dim_patient | valid_to | quasi_identifier | DATE | 1.00 | YEAR | valid_to_year |
| gold_dim_patient | vehicle_plate | direct_identifier | VEHICLE | 0.90 | DROP | nan |
| gold_dim_patient | zip | quasi_identifier | ZIP | 0.90 | ZIP3 | zip3 |
| gold_dim_provider | facility_id | safe | NONE | 0.90 | KEEP | facility_id |
| gold_dim_provider | facility_name | safe | NONE | 0.90 | KEEP | facility_name |
| gold_dim_provider | facility_phone | safe | NONE | 0.90 | EXCLUDE_PENDING_REVIEW | nan |
| gold_dim_provider | facility_zip | safe | NONE | 0.90 | KEEP | facility_zip |
| gold_dim_provider | npi | safe | NONE | 0.90 | KEEP | npi |
| gold_dim_provider | provider_name | safe | NONE | 0.90 | EXCLUDE_PENDING_REVIEW | nan |
| gold_dim_provider | specialty | safe | NONE | 0.90 | KEEP | specialty |
| gold_fct_claim | billed_amount | safe | NONE | 0.80 | KEEP | billed_amount |
| gold_fct_claim | claim_id | direct_identifier | OTHER_UNIQUE_ID | 0.80 | HASH | claim_key |
| gold_fct_claim | claim_status | safe | NONE | 0.80 | KEEP | claim_status |
| gold_fct_claim | denial_reason | safe | NONE | 0.80 | KEEP | denial_reason |
| gold_fct_claim | encounter_id | direct_identifier | OTHER_UNIQUE_ID | 0.80 | HASH | encounter_key |
| gold_fct_claim | member_id | direct_identifier | HEALTH_PLAN_ID | 0.90 | DROP | nan |
| gold_fct_claim | mrn | direct_identifier | MRN | 0.95 | HASH | mrn_key |
| gold_fct_claim | paid_amount | safe | NONE | 0.80 | KEEP | paid_amount |
| gold_fct_claim | payer_name | safe | NONE | 0.80 | KEEP | payer_name |
| gold_fct_claim | procedure_code | safe | NONE | 0.80 | KEEP | procedure_code |
| gold_fct_claim | service_date | quasi_identifier | DATE | 1.00 | YEAR | service_year |
| gold_fct_encounter | admit_date | quasi_identifier | DATE | 1.00 | YEAR | admit_year |
| gold_fct_encounter | attending_npi | safe | NONE | 0.90 | KEEP | attending_npi |
| gold_fct_encounter | clinical_note | direct_identifier | FREE_TEXT | 0.90 | DROP | nan |
| gold_fct_encounter | discharge_date | quasi_identifier | DATE | 1.00 | YEAR | discharge_year |
| gold_fct_encounter | drg_code | safe | NONE | 0.80 | KEEP | drg_code |
| gold_fct_encounter | dx_category | safe | NONE | 0.80 | KEEP | dx_category |
| gold_fct_encounter | encounter_id | direct_identifier | OTHER_UNIQUE_ID | 0.80 | HASH | encounter_key |
| gold_fct_encounter | encounter_type | safe | NONE | 0.80 | KEEP | encounter_type |
| gold_fct_encounter | facility_id | safe | NONE | 0.90 | KEEP | facility_id |
| gold_fct_encounter | implant_device_serial | direct_identifier | DEVICE | 0.88 | DROP | nan |
| gold_fct_encounter | length_of_stay_days | safe | NONE | 0.80 | KEEP | length_of_stay_days |
| gold_fct_encounter | mrn | direct_identifier | MRN | 0.95 | HASH | mrn_key |
| gold_fct_encounter | patient_sk | direct_identifier | OTHER_UNIQUE_ID | 0.80 | HASH | patient_key |
| gold_fct_encounter | payer_name | safe | NONE | 0.80 | KEEP | payer_name |
| gold_fct_encounter | primary_dx_code | safe | NONE | 0.80 | KEEP | primary_dx_code |
| gold_fct_encounter | readmitted_30d | safe | NONE | 0.80 | KEEP | readmitted_30d |
| gold_fct_portal_activity | activity_id | direct_identifier | OTHER_UNIQUE_ID | 0.80 | HASH | activity_key |
| gold_fct_portal_activity | device_id | direct_identifier | DEVICE | 0.88 | DROP | nan |
| gold_fct_portal_activity | fingerprint_template | direct_identifier | BIOMETRIC | 0.90 | DROP | nan |
| gold_fct_portal_activity | login_ip | direct_identifier | IP_ADDRESS | 1.00 | DROP | nan |
| gold_fct_portal_activity | login_ts | quasi_identifier | DATE | 1.00 | YEAR | login_year |
| gold_fct_portal_activity | mrn | direct_identifier | MRN | 0.95 | HASH | mrn_key |
| gold_fct_portal_activity | page_views | safe | NONE | 0.80 | KEEP | page_views |
| gold_fct_portal_activity | photo_url | direct_identifier | PHOTO | 0.90 | DROP | nan |
| gold_fct_portal_activity | portal_url | direct_identifier | URL | 1.00 | DROP | nan |
