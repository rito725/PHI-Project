"""Column classification. The LLM sees format shapes, statistics and detector
findings only. Raw sampled values never leave the warehouse boundary."""
from __future__ import annotations

import json
import re
from dataclasses import asdict
from typing import Literal

import anthropic
from pydantic import BaseModel

from phi_gov.discovery.detectors import ColumnProfile, Finding
from phi_gov.discovery.hipaa import Category

FALLBACK_BETA = "server-side-fallback-2026-07-01"


class ColumnVerdict(BaseModel):
    column: str
    category: Literal[tuple(c.value for c in Category)]  # type: ignore[valid-type]
    confidence: float
    rationale: str


class TableVerdicts(BaseModel):
    columns: list[ColumnVerdict]


SYSTEM = """You classify database columns for HIPAA Safe Harbor de-identification.
For each column choose exactly one category. Base the decision on the column name, type,
format shapes, statistics and detector findings. You never see raw values: digits appear
as 9 and letters as a or A.

Categories: NAME (of a patient, relative, household member or employer), GEOGRAPHIC
(address, city or county: anything below state), ZIP, BIRTH_DATE, DATE (any other date or
timestamp tied to an individual, such as admission, discharge, service or login time),
AGE, PHONE, FAX, EMAIL, SSN, MRN, HEALTH_PLAN_ID, ACCOUNT_NUMBER, LICENSE, VEHICLE, DEVICE,
URL, IP_ADDRESS, BIOMETRIC, PHOTO, OTHER_UNIQUE_ID (row or surrogate key that links back to
a patient's records), FREE_TEXT (narrative that may embed identifiers), DEMOGRAPHIC (gender,
race, language), NONE (not about an individual).

Judgement rules:
- Safe Harbor protects patients, their relatives, employers and household members. Provider
  and facility data (names, NPIs, facility phones and ZIPs) is NONE: it describes the
  workforce, not the patient.
- State is allowed by Safe Harbor, so it is NONE.
- Clinical and billing codes are NONE, even when shaped like something else. A CPT code
  looks like a ZIP.
- Meaningless names such as ext_ref_1 tell you nothing. Trust the shapes and findings.
- Set confidence between 0 and 1. If you cannot tell, say so with a low confidence: a low
  score sends the column to a human and hides it meanwhile, which is the safe outcome."""


def render_prompt(table: str, profiles: list[ColumnProfile],
                  findings: dict[str, list[Finding]]) -> str:
    rows = [{
        **{k: v for k, v in asdict(p).items() if k != "table"},
        "detector_findings": [f.to_dict() for f in findings.get(p.column, [])],
    } for p in profiles]
    return f"Table: {table}\nColumns:\n{json.dumps(rows, indent=1)}"


class ClaudeClassifier:
    name = "claude"

    def __init__(self, model: str, client=None):
        self.client = client or anthropic.Anthropic()
        self.model = model
        self.name = f"claude:{model}"

    def classify(self, table, profiles, findings) -> list[ColumnVerdict]:
        response = self.client.beta.messages.parse(
            model=self.model,
            max_tokens=16000,
            betas=[FALLBACK_BETA],
            fallbacks="default",
            output_config={"effort": "medium"},
            system=SYSTEM,
            messages=[{"role": "user", "content": render_prompt(table, profiles, findings)}],
            output_format=TableVerdicts,
        )
        if response.stop_reason == "refusal" or response.parsed_output is None:
            raise RuntimeError(f"no classification for {table}: stop_reason={response.stop_reason}")
        return response.parsed_output.columns


_NAME_RULES = [
    (r"(^|_)(first|last|full)_?name$|contact_name|employer", Category.NAME, .92),
    (r"ssn|social", Category.SSN, .95),
    (r"^mrn$|medical_record", Category.MRN, .95),
    (r"^(dob|birth)|date_of_birth", Category.BIRTH_DATE, .95),
    (r"(^|_)age$", Category.AGE, .9),
    (r"zip|postal", Category.ZIP, .9),
    (r"address|(^|_)city$|county", Category.GEOGRAPHIC, .92),
    (r"(^|_)fax", Category.FAX, .9),
    (r"phone|mobile", Category.PHONE, .9),
    (r"email", Category.EMAIL, .95),
    (r"member_id|subscriber|beneficiary", Category.HEALTH_PLAN_ID, .9),
    (r"account", Category.ACCOUNT_NUMBER, .9),
    (r"license|licence", Category.LICENSE, .9),
    (r"(^|_)plate|(^|_)vin$|vehicle", Category.VEHICLE, .9),
    (r"device|serial|imei", Category.DEVICE, .88),
    (r"photo|image", Category.PHOTO, .9),
    (r"url|link", Category.URL, .88),
    (r"(^|_)ip(_|$)", Category.IP_ADDRESS, .9),
    (r"fingerprint|retina|voice|biometric", Category.BIOMETRIC, .9),
    (r"note|comment|narrative", Category.FREE_TEXT, .9),
    (r"(_date|_ts|_at)$|^valid_(from|to)$", Category.DATE, .9),
    (r"(^|_)(sk|id)$", Category.OTHER_UNIQUE_ID, .8),
    (r"gender|sex|race|ethnic|language", Category.DEMOGRAPHIC, .85),
]
_SAFE_HINT = re.compile(
    r"amount|code|status|type|score|category|specialty|flag|days|count|views|payer|reason"
    r"|readmitted|^is_|^state$")
_WORKFORCE = re.compile(r"npi|^facility_|^provider_|^specialty$")


class RuleBasedClassifier:
    """Offline stand-in for the LLM, so the pipeline runs with no API key. Eval numbers
    from this path describe these rules, not Claude, and are labelled as such."""
    name = "offline-rules"

    def classify(self, table, profiles, findings) -> list[ColumnVerdict]:
        return [self._one(p, findings.get(p.column, [])) for p in profiles]

    @staticmethod
    def _one(profile: ColumnProfile, column_findings: list[Finding]) -> ColumnVerdict:
        name = profile.column.lower()
        if _WORKFORCE.search(name):
            return ColumnVerdict(column=profile.column, category="NONE", confidence=.9,
                                 rationale="Provider or facility data, not about a patient.")
        for pattern, category, confidence in _NAME_RULES:
            if re.search(pattern, name):
                return ColumnVerdict(column=profile.column, category=category.value,
                                     confidence=confidence,
                                     rationale=f"Column name matches {category.value}.")
        strong = [f for f in column_findings if f.strong]
        if strong:
            best = max(strong, key=lambda f: f.hit_rate)
            return ColumnVerdict(column=profile.column, category=best.category.value,
                                 confidence=.85,
                                 rationale=f"Values match {best.info_type}.")
        if _SAFE_HINT.search(name):
            return ColumnVerdict(column=profile.column, category="NONE", confidence=.8,
                                 rationale="Name indicates a non-identifying attribute.")
        return ColumnVerdict(column=profile.column, category="NONE", confidence=.4,
                             rationale="No signal either way.")


def make_classifier(settings):
    if settings.llm_backend == "claude":
        return ClaudeClassifier(settings.claude_model)
    return RuleBasedClassifier()
