"""Value-level detection: what the data looks like, whatever the column is called.

CloudDlpDetector is the production path. LocalDetector is an offline stand-in with
the same interface, used by default so the project runs with no cloud account.
"""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass

from faker.providers.person.en_US import Provider as _Names

from phi_gov.discovery.hipaa import Category

STRONG_HIT_RATE = 0.2
MAX_VALUE_CHARS = 500  # keeps a Cloud DLP request well under its 0.5 MB content limit


@dataclass(frozen=True)
class Finding:
    category: Category
    info_type: str
    hit_rate: float
    strong: bool

    def to_dict(self) -> dict:
        return {**asdict(self), "category": self.category.value}


@dataclass(frozen=True)
class ColumnProfile:
    """Everything a classifier is allowed to see. It holds format shapes and
    statistics, never raw values, so no PHI reaches the LLM."""
    table: str
    column: str
    data_type: str
    n_sampled: int
    distinct_ratio: float
    avg_length: float
    shapes: tuple[str, ...]


def shape_of(value: str) -> str:
    """'(212) 555-0199' -> '(999) 999-9999'. Preserves format, destroys content."""
    if len(value) > 40:
        return f"<text, {len(value.split())} words>"
    out = re.sub(r"[0-9]", "9", value)
    out = re.sub(r"[A-Z]", "A", out)
    return re.sub(r"[a-z]", "a", out)


def profile_column(table: str, column: str, data_type: str, samples: list[str]) -> ColumnProfile:
    n = len(samples)
    counts: dict[str, int] = {}
    for sample in samples:
        shape = shape_of(sample)
        counts[shape] = counts.get(shape, 0) + 1
    top = sorted(counts, key=counts.get, reverse=True)[:5]
    return ColumnProfile(
        table=table, column=column, data_type=data_type, n_sampled=n,
        distinct_ratio=round(len(set(samples)) / n, 3) if n else 0.0,
        avg_length=round(sum(map(len, samples)) / n, 1) if n else 0.0,
        shapes=tuple(top),
    )


_FIRST = {n.lower() for n in _Names.first_names}
_NAME_PAIR = re.compile(r"\b([A-Z][a-z]+)\s+(?:[A-Z]\.?\s+)?[A-Z][a-z']+\b")

# (info type, category, pattern, strong). Weak patterns are too ambiguous to overrule
# a classifier: five digits could be a ZIP or a CPT code.
_PATTERNS = [
    ("US_SOCIAL_SECURITY_NUMBER", Category.SSN, re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), True),
    ("EMAIL_ADDRESS", Category.EMAIL, re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"), True),
    ("PHONE_NUMBER", Category.PHONE, re.compile(r"\(?\b\d{3}\)?[-. ]\d{3}[-. ]\d{4}\b"), True),
    ("IP_ADDRESS", Category.IP_ADDRESS, re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), True),
    ("URL", Category.URL, re.compile(r"https?://\S+"), True),
    ("VEHICLE_IDENTIFICATION_NUMBER", Category.VEHICLE, re.compile(r"\b[A-HJ-NPR-Z0-9]{17}\b"), True),
    ("DATE", Category.DATE, re.compile(r"\b\d{4}-\d{2}-\d{2}\b"), True),
    ("ZIP_LIKE", Category.ZIP, re.compile(r"^\d{5}(-\d{4})?$"), False),
]


class LocalDetector:
    name = "local-regex"

    def inspect(self, table: str, samples: dict[str, list[str]]) -> dict[str, list[Finding]]:
        return {col: self._inspect_column(values) for col, values in samples.items()}

    @staticmethod
    def _inspect_column(values: list[str]) -> list[Finding]:
        if not values:
            return []
        n, found = len(values), []
        for info_type, category, pattern, strong in _PATTERNS:
            rate = sum(bool(pattern.search(v)) for v in values) / n
            if rate:
                found.append(Finding(category, info_type, round(rate, 3),
                                     strong and rate >= STRONG_HIT_RATE))
        names = sum(any(m.group(1).lower() in _FIRST for m in _NAME_PAIR.finditer(v))
                    for v in values) / n
        if names:
            found.append(Finding(Category.NAME, "PERSON_NAME", round(names, 3),
                                 names >= STRONG_HIT_RATE))
        return found


INFO_TYPES: dict[str, Category] = {
    "PERSON_NAME": Category.NAME, "FIRST_NAME": Category.NAME, "LAST_NAME": Category.NAME,
    "EMAIL_ADDRESS": Category.EMAIL, "PHONE_NUMBER": Category.PHONE,
    "US_SOCIAL_SECURITY_NUMBER": Category.SSN, "DATE_OF_BIRTH": Category.BIRTH_DATE,
    "DATE": Category.DATE, "STREET_ADDRESS": Category.GEOGRAPHIC,
    "LOCATION": Category.GEOGRAPHIC, "IP_ADDRESS": Category.IP_ADDRESS, "URL": Category.URL,
    "MAC_ADDRESS": Category.DEVICE, "IMEI_HARDWARE_ID": Category.DEVICE,
    "MEDICAL_RECORD_NUMBER": Category.MRN, "US_HEALTHCARE_NPI": Category.OTHER_UNIQUE_ID,
    "US_MEDICARE_BENEFICIARY_ID_NUMBER": Category.HEALTH_PLAN_ID,
    "US_DRIVERS_LICENSE_NUMBER": Category.LICENSE,
    "VEHICLE_IDENTIFICATION_NUMBER": Category.VEHICLE,
    "US_VEHICLE_IDENTIFICATION_NUMBER": Category.VEHICLE,
}


class CloudDlpDetector:
    name = "cloud-dlp"

    def __init__(self, project: str, client=None):
        if client is None:
            from google.cloud import dlp_v2
            client = dlp_v2.DlpServiceClient()
        self.client = client
        self.parent = f"projects/{project}/locations/global"

    def build_request(self, samples: dict[str, list[str]]) -> dict:
        columns = list(samples)
        depth = max((len(v) for v in samples.values()), default=0)
        rows = [{"values": [{"string_value": samples[c][i][:MAX_VALUE_CHARS]
                             if i < len(samples[c]) else ""} for c in columns]}
                for i in range(depth)]
        return {
            "parent": self.parent,
            "item": {"table": {"headers": [{"name": c} for c in columns], "rows": rows}},
            "inspect_config": {
                "info_types": [{"name": n} for n in INFO_TYPES],
                "min_likelihood": "POSSIBLE",
                "include_quote": False,  # findings must not copy PHI into logs or reports
                "limits": {"max_findings_per_request": 0},
            },
        }

    def inspect(self, table: str, samples: dict[str, list[str]]) -> dict[str, list[Finding]]:
        result = self.client.inspect_content(request=self.build_request(samples)).result
        hits: dict[tuple[str, str], set[int]] = {}
        strong: set[tuple[str, str]] = set()
        for finding in result.findings:
            for location in finding.location.content_locations:
                record = location.record_location
                key = (record.field_id.name, finding.info_type.name)
                hits.setdefault(key, set()).add(int(record.table_location.row_index))
                if int(finding.likelihood) >= 4:  # LIKELY or VERY_LIKELY
                    strong.add(key)
        out: dict[str, list[Finding]] = {c: [] for c in samples}
        for (column, info_type), rows in hits.items():
            rate = round(len(rows) / max(len(samples[column]), 1), 3)
            out[column].append(Finding(INFO_TYPES[info_type], info_type, rate,
                                       (column, info_type) in strong and rate >= STRONG_HIT_RATE))
        return out


def make_detector(settings):
    if settings.dlp_backend == "cloud":
        return CloudDlpDetector(settings.gcp_project)
    return LocalDetector()
