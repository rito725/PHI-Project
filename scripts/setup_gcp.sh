#!/usr/bin/env bash
# Least-privilege identities for the BigQuery path. Review before running.
# Usage: PROJECT=my-project ./scripts/setup_gcp.sh
set -euo pipefail
: "${PROJECT:?set PROJECT}"
GOV_SA="phi-governance@${PROJECT}.iam.gserviceaccount.com"
ANALYST_SA="phi-analytics@${PROJECT}.iam.gserviceaccount.com"

gcloud services enable bigquery.googleapis.com dlp.googleapis.com \
  datacatalog.googleapis.com --project "$PROJECT"

gcloud iam service-accounts create phi-governance --project "$PROJECT" || true
gcloud iam service-accounts create phi-analytics --project "$PROJECT" || true

# Governance agent: owns datasets, views, taxonomy and DLP calls.
for role in roles/bigquery.admin roles/dlp.user roles/datacatalog.categoryAdmin; do
  gcloud projects add-iam-policy-binding "$PROJECT" --condition=None --quiet \
    --member "serviceAccount:${GOV_SA}" --role "$role"
done

# Analytics agent: can run jobs. It gets no project-level data access.
gcloud projects add-iam-policy-binding "$PROJECT" --condition=None --quiet \
  --member "serviceAccount:${ANALYST_SA}" --role roles/bigquery.jobUser

cat <<NOTE

Two grants remain, and they must follow the first 'phi-gov scan', because the
dataset and the policy tags do not exist until then:

1. In BigQuery, give ${ANALYST_SA} BigQuery Data Viewer on phi_deid only.
   Do NOT grant it anything on phi_gold, phi_restricted or phi_governance.

2. In the phi_governance taxonomy, give ${ANALYST_SA} Fine-Grained Reader on
   'quasi_identifier' and 'pseudonymized_identifier' only.

   Authorized views do not bypass policy tags, so without this the views fail.
   Withholding it on 'direct_identifier' means columns the views drop stay
   unreadable even to this account.
NOTE
