"""Turn detector findings plus a classifier verdict into one decision per column."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from phi_gov.discovery.classifier import ColumnVerdict
from phi_gov.discovery.detectors import Finding
from phi_gov.discovery.hipaa import TIER_RANK, Category, Tier, Transform, tier_of, transform_of

OVERRULE_CONFIDENCE = 0.85


@dataclass
class Decision:
    table: str
    column: str
    data_type: str
    category: Category
    confidence: float
    rationale: str
    needs_review: bool = False
    findings: list[Finding] = field(default_factory=list)
    reviewed: bool = False

    @property
    def tier(self) -> Tier:
        return tier_of(self.category)

    @property
    def transform(self) -> Transform:
        if self.needs_review:
            return Transform.EXCLUDE_PENDING_REVIEW
        return transform_of(self.category)

    @property
    def output_column(self) -> str | None:
        return output_name(self.column, self.transform)


def output_name(column: str, transform: Transform) -> str | None:
    match transform:
        case Transform.HASH:
            return re.sub(r"_(id|sk)$", "", column) + "_key"
        case Transform.BIRTH_YEAR:
            return "birth_year"
        case Transform.YEAR:
            return re.sub(r"_(date|ts|at)$", "", column) + "_year"
        case Transform.ZIP3:
            return "zip3"
        case Transform.AGE_CAP:
            return f"{column}_capped"
        case Transform.KEEP:
            return column
    return None


def reconcile(table: str, column: str, data_type: str, verdict: ColumnVerdict,
              findings: list[Finding], review_confidence: float,
              override: dict | None = None) -> Decision:
    """Two independent signals, with disagreement resolved towards safety.

    The classifier can raise a column's sensitivity on its own. It cannot quietly lower
    it: if a detector has a strong hit and the classifier says otherwise, a human decides,
    and the column stays out of the views until they do.
    """
    if override:
        return Decision(table, column, data_type, Category(override["category"]), 1.0,
                        f"Human review by {override['reviewer']}.", False, findings, True)

    category, confidence = Category(verdict.category), min(max(verdict.confidence, 0.0), 1.0)
    rationale, needs_review = verdict.rationale, False
    strong = sorted((f for f in findings if f.strong),
                    key=lambda f: (TIER_RANK[tier_of(f.category)], f.hit_rate), reverse=True)
    if strong:
        top = strong[0]
        if TIER_RANK[tier_of(top.category)] > TIER_RANK[tier_of(category)]:
            needs_review = True
            note = f"Detector found {top.info_type} on {top.hit_rate:.0%} of sampled values."
            if confidence >= OVERRULE_CONFIDENCE:
                rationale = f"{rationale} Conflict: {note}"
            else:
                category, confidence = top.category, top.hit_rate
                rationale = f"{note} Classifier disagreed with low confidence: {rationale}"
        elif top.category == category:
            confidence = max(confidence, top.hit_rate)
    if confidence < review_confidence:
        needs_review = True
    return Decision(table, column, data_type, category, confidence, rationale,
                    needs_review, findings)


def fail_closed(table: str, column: str, data_type: str, findings: list[Finding],
                reason: str) -> Decision:
    """Classification failed, so the column is hidden and queued for a human."""
    strong = [f for f in findings if f.strong]
    category = strong[0].category if strong else Category.OTHER_UNIQUE_ID
    return Decision(table, column, data_type, category, 0.0, reason, True, findings)


def to_row(d: Decision, schema_hash: str, classifier: str, detector: str, scanned_at) -> dict:
    return {
        "table_name": d.table, "column_name": d.column, "data_type": d.data_type,
        "tier": d.tier.value, "category": d.category.value,
        "confidence": round(d.confidence, 3), "transform": d.transform.value,
        "output_column": d.output_column, "needs_review": d.needs_review,
        "human_reviewed": d.reviewed, "rationale": d.rationale,
        "findings": json.dumps([f.to_dict() for f in d.findings]),
        "classifier": classifier, "detector": detector,
        "schema_hash": schema_hash, "scanned_at": scanned_at,
    }
