"""BigQuery warehouse, including policy tags and authorized views."""
from __future__ import annotations

import pandas as pd
from google.api_core import exceptions as gexc
from google.cloud import bigquery, datacatalog_v1

from phi_gov.config import Settings
from phi_gov.warehouse.base import Column, Schema, SqlError, Warehouse

TAXONOMY = "phi_governance"
TAGS = ("direct_identifier", "pseudonymized_identifier", "quasi_identifier")


def _json_safe(value):
    """Registry rows round-trip through pandas, so they can hold numpy and pandas scalars."""
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return value.item() if hasattr(value, "item") else value


class BigQueryWarehouse(Warehouse):
    name = "bigquery"

    def __init__(self, settings: Settings):
        if not settings.gcp_project:
            raise ValueError("GCP_PROJECT must be set for the BigQuery backend")
        self.s = settings
        self.project = settings.gcp_project
        self.client = bigquery.Client(project=self.project, location=settings.bq_location)
        # The analytics agent should run as its own service account, which has no
        # access to the gold dataset. IAM is the real boundary; guardrails are the second.
        self.analyst_client = (
            bigquery.Client.from_service_account_json(
                settings.analyst_credentials_file, project=self.project,
                location=settings.bq_location)
            if settings.analyst_credentials_file else self.client
        )

    def _ref(self, dataset: str, table: str) -> str:
        return f"{self.project}.{dataset}.{table}"

    def ensure_dataset(self, dataset):
        ds = bigquery.Dataset(f"{self.project}.{dataset}")
        ds.location = self.s.bq_location
        self.client.create_dataset(ds, exists_ok=True)

    def list_tables(self, dataset):
        try:
            return sorted(t.table_id for t in self.client.list_tables(dataset))
        except gexc.NotFound:
            return []

    def columns(self, dataset, table):
        schema = self.client.get_table(self._ref(dataset, table)).schema
        return [Column(f.name, f.field_type) for f in schema]

    def _run(self, client, sql, config=None):
        try:
            return client.query(sql, job_config=config)
        except (gexc.BadRequest, gexc.Forbidden, gexc.NotFound) as err:
            raise SqlError(getattr(err, "message", str(err))) from err

    def query(self, sql, analyst=False):
        client = self.analyst_client if analyst else self.client
        config = bigquery.QueryJobConfig(
            maximum_bytes_billed=self.s.max_bytes_billed) if analyst else None
        try:
            return self._run(client, sql, config).result().to_dataframe()
        except (gexc.BadRequest, gexc.Forbidden, gexc.NotFound) as err:
            raise SqlError(getattr(err, "message", str(err))) from err

    def execute(self, sql):
        try:
            self._run(self.client, sql).result()
        except (gexc.BadRequest, gexc.Forbidden, gexc.NotFound) as err:
            raise SqlError(getattr(err, "message", str(err))) from err

    def dry_run(self, sql):
        config = bigquery.QueryJobConfig(dry_run=True, use_query_cache=False)
        return int(self._run(self.analyst_client, sql, config).total_bytes_processed or 0)

    def write_dataframe(self, dataset, table, df):
        config = bigquery.LoadJobConfig(write_disposition="WRITE_TRUNCATE")
        self.client.load_table_from_dataframe(
            df, self._ref(dataset, table), job_config=config).result()

    def write_rows(self, dataset, table, rows, schema, truncate=False):
        # Load jobs, not streaming inserts: rows in the streaming buffer cannot be
        # rewritten by a later truncate.
        if not rows:
            return
        config = bigquery.LoadJobConfig(
            schema=[bigquery.SchemaField(n, t) for n, t in schema],
            write_disposition="WRITE_TRUNCATE" if truncate else "WRITE_APPEND",
        )
        payload = [{k: _json_safe(v) for k, v in r.items()} for r in rows]
        self.client.load_table_from_json(
            payload, self._ref(dataset, table), job_config=config).result()

    def _policy_tags(self) -> dict[str, str]:
        ptm = datacatalog_v1.PolicyTagManagerClient()
        parent = f"projects/{self.project}/locations/{self.s.bq_location.lower()}"
        taxonomy = next((t for t in ptm.list_taxonomies(parent=parent)
                         if t.display_name == TAXONOMY), None)
        if taxonomy is None:
            taxonomy = ptm.create_taxonomy(parent=parent, taxonomy=datacatalog_v1.Taxonomy(
                display_name=TAXONOMY,
                activated_policy_types=[
                    datacatalog_v1.Taxonomy.PolicyType.FINE_GRAINED_ACCESS_CONTROL],
            ))
        existing = {t.display_name: t.name for t in ptm.list_policy_tags(parent=taxonomy.name)}
        for tag in TAGS:
            if tag not in existing:
                existing[tag] = ptm.create_policy_tag(
                    parent=taxonomy.name,
                    policy_tag=datacatalog_v1.PolicyTag(display_name=tag)).name
        return existing

    def apply_policy_tags(self, dataset, table, tags):
        if not tags:
            return
        names = self._policy_tags()
        ref = self.client.get_table(self._ref(dataset, table))
        schema = []
        for field in ref.schema:
            data = field.to_api_repr()
            if field.name in tags:
                data["policyTags"] = {"names": [names[tags[field.name]]]}
            schema.append(bigquery.SchemaField.from_api_repr(data))
        ref.schema = schema
        self.client.update_table(ref, ["schema"])

    def authorize_views(self, source_dataset, view_dataset):
        """Authorize every view in view_dataset, present and future, on the source.

        This covers dataset ACLs only. Policy tags still apply through authorized
        views, so the analyst account also needs Fine-Grained Reader on the tags of
        transformed columns (scripts/setup_gcp.sh)."""
        ds = self.client.get_dataset(f"{self.project}.{source_dataset}")
        target = {"dataset": {"projectId": self.project, "datasetId": view_dataset},
                  "targetTypes": ["VIEWS"]}
        entries = list(ds.access_entries)
        if any(e.entity_id == target for e in entries):
            return
        entries.append(bigquery.AccessEntry(None, "dataset", target))
        ds.access_entries = entries
        self.client.update_dataset(ds, ["access_entries"])
