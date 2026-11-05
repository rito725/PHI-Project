"""The 18 HIPAA Safe Harbor identifiers (45 CFR 164.514(b)(2)) and the policy
that maps each one to a tier and a de-identification transform.

The classifier only ever picks a Category. Tier and transform are looked up
here, so a model can never choose SQL, and policy changes in exactly one place.
"""
from __future__ import annotations

from enum import Enum


class Category(str, Enum):
    NAME = "NAME"                         # (A) names, including relatives and employers
    GEOGRAPHIC = "GEOGRAPHIC"             # (B) street, city, county: anything below state
    ZIP = "ZIP"                           # (B) ZIP codes
    BIRTH_DATE = "BIRTH_DATE"             # (C) birth date
    DATE = "DATE"                         # (C) admission, discharge, service dates
    AGE = "AGE"                           # (C) ages over 89 must be aggregated
    PHONE = "PHONE"                       # (D)
    FAX = "FAX"                           # (E)
    EMAIL = "EMAIL"                       # (F)
    SSN = "SSN"                           # (G)
    MRN = "MRN"                           # (H)
    HEALTH_PLAN_ID = "HEALTH_PLAN_ID"     # (I)
    ACCOUNT_NUMBER = "ACCOUNT_NUMBER"     # (J)
    LICENSE = "LICENSE"                   # (K)
    VEHICLE = "VEHICLE"                   # (L)
    DEVICE = "DEVICE"                     # (M)
    URL = "URL"                           # (N)
    IP_ADDRESS = "IP_ADDRESS"             # (O)
    BIOMETRIC = "BIOMETRIC"               # (P)
    PHOTO = "PHOTO"                       # (Q)
    OTHER_UNIQUE_ID = "OTHER_UNIQUE_ID"   # (R) record keys that link back to a person
    FREE_TEXT = "FREE_TEXT"               # narrative text, which can embed any of the above
    DEMOGRAPHIC = "DEMOGRAPHIC"           # gender, race: quasi-identifying, not on the list
    NONE = "NONE"                         # not about an individual


class Tier(str, Enum):
    DIRECT = "direct_identifier"
    QUASI = "quasi_identifier"
    SAFE = "safe"


class Transform(str, Enum):
    DROP = "DROP"
    HASH = "HASH"
    BIRTH_YEAR = "BIRTH_YEAR"
    YEAR = "YEAR"
    ZIP3 = "ZIP3"
    AGE_CAP = "AGE_CAP"
    KEEP = "KEEP"
    EXCLUDE_PENDING_REVIEW = "EXCLUDE_PENDING_REVIEW"


_D, _Q, _S = Tier.DIRECT, Tier.QUASI, Tier.SAFE

POLICY: dict[Category, tuple[Tier, Transform]] = {
    Category.NAME: (_D, Transform.DROP),
    Category.GEOGRAPHIC: (_D, Transform.DROP),
    Category.PHONE: (_D, Transform.DROP),
    Category.FAX: (_D, Transform.DROP),
    Category.EMAIL: (_D, Transform.DROP),
    Category.SSN: (_D, Transform.DROP),
    Category.HEALTH_PLAN_ID: (_D, Transform.DROP),
    Category.ACCOUNT_NUMBER: (_D, Transform.DROP),
    Category.LICENSE: (_D, Transform.DROP),
    Category.VEHICLE: (_D, Transform.DROP),
    Category.DEVICE: (_D, Transform.DROP),
    Category.URL: (_D, Transform.DROP),
    Category.IP_ADDRESS: (_D, Transform.DROP),
    Category.BIOMETRIC: (_D, Transform.DROP),
    Category.PHOTO: (_D, Transform.DROP),
    Category.FREE_TEXT: (_D, Transform.DROP),
    # Pseudonymised rather than dropped because analytics needs them as join keys.
    Category.MRN: (_D, Transform.HASH),
    Category.OTHER_UNIQUE_ID: (_D, Transform.HASH),
    Category.BIRTH_DATE: (_Q, Transform.BIRTH_YEAR),
    Category.DATE: (_Q, Transform.YEAR),
    Category.ZIP: (_Q, Transform.ZIP3),
    Category.AGE: (_Q, Transform.AGE_CAP),
    Category.DEMOGRAPHIC: (_Q, Transform.KEEP),
    Category.NONE: (_S, Transform.KEEP),
}

TIER_RANK = {Tier.SAFE: 0, Tier.QUASI: 1, Tier.DIRECT: 2}

# 3-digit ZIP prefixes with 20,000 or fewer people (HHS guidance, 2000 Census).
# Safe Harbor requires these to be reported as 000.
RESTRICTED_ZIP3 = (
    "036", "059", "063", "102", "203", "556", "692", "790", "821",
    "823", "830", "831", "878", "879", "884", "890", "893",
)


def tier_of(category: Category) -> Tier:
    return POLICY[category][0]


def transform_of(category: Category) -> Transform:
    return POLICY[category][1]
