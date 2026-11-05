"""Deterministic synthetic gold layer, shaped like Project 1's output.

Every value is fake. The tables cover all 18 Safe Harbor identifiers and include
two kinds of trap for the classifier:
  * PHI hidden behind meaningless names (ext_ref_1, cust_attr_9)
  * safe data that looks like PHI (CPT codes that look like ZIPs, facility phones,
    provider names, which are workforce data rather than patient data)
"""
from __future__ import annotations

import datetime as dt
import hashlib

import numpy as np
import pandas as pd
from faker import Faker

from phi_gov.discovery.hipaa import RESTRICTED_ZIP3

AS_OF = dt.date(2025, 12, 31)
PAYERS = {  # payer -> base 30-day readmission probability
    "Medicare": 0.20, "Medicaid": 0.23, "Aetna": 0.12,
    "BlueCross": 0.11, "UnitedHealthcare": 0.13, "SelfPay": 0.17,
}
DIAGNOSES = {
    "Diabetes": "E11.9", "Heart Failure": "I50.9", "COPD": "J44.9",
    "Pneumonia": "J18.9", "Sepsis": "A41.9", "Acute MI": "I21.9",
    "CKD": "N18.9", "Hip Fracture": "S72.001A",
}
DX_RISK = {"Heart Failure": 1.5, "COPD": 1.3, "Sepsis": 1.2, "Diabetes": 1.1}
CPT = ["99213", "99214", "99223", "99232", "71046", "93000", "80053", "36415", "27130"]
DENIALS = ["Missing authorization", "Not medically necessary", "Duplicate claim", "Eligibility"]
SPECIALTIES = ["Cardiology", "Endocrinology", "Hospitalist", "Pulmonology", "Orthopedics"]


def generate(seed: int = 42, n_patients: int = 5000) -> dict[str, pd.DataFrame]:
    rng = np.random.default_rng(seed)
    fake = Faker("en_US")
    Faker.seed(seed)
    patients, payer_of = _patients(rng, fake, n_patients)
    providers = _providers(rng, fake)
    encounters = _encounters(rng, fake, patients, payer_of, providers)
    return {
        "gold_dim_patient": patients,
        "gold_dim_provider": providers,
        "gold_fct_encounter": encounters,
        "gold_fct_claim": _claims(rng, encounters),
        "gold_fct_portal_activity": _portal(rng, fake, patients),
    }


def _patients(rng, fake, n):
    rows, payer_of = [], {}
    names, weights = list(PAYERS), [0.3, 0.15, 0.17, 0.18, 0.15, 0.05]
    for i in range(n):
        age = int(np.clip(rng.normal(58, 21), 0, 101))
        dob = AS_OF - dt.timedelta(days=age * 365 + int(rng.integers(0, 364)))
        zip_code = fake.zipcode()
        if rng.random() < 0.02:  # low-population ZIP3s, which Safe Harbor zeroes out
            zip_code = str(rng.choice(RESTRICTED_ZIP3)) + "01"
        first, last = fake.first_name(), fake.last_name()
        mrn = f"MRN{1000000 + i}"
        payer_of[mrn] = str(rng.choice(names, p=weights))
        base = {
            "mrn": mrn, "first_name": first, "last_name": last, "ssn": fake.ssn(),
            "dob": dob, "age": age, "gender": str(rng.choice(["F", "M"])),
            "race": str(rng.choice(["White", "Black", "Asian", "Hispanic", "Other"])),
            "preferred_language": str(rng.choice(["English", "Spanish", "Other"], p=[.8, .15, .05])),
            "address_line": fake.street_address(), "city": fake.city(),
            "state": fake.state_abbr(), "zip": zip_code,
            "phone": fake.numerify("(###) 555-####"), "fax": fake.numerify("###-555-####"),
            "email": f"{first}.{last}{i}@example.org".lower(),
            "emergency_contact_name": fake.name(), "employer_name": fake.company(),
            "drivers_license": fake.bothify("?#######").upper(),
            "vehicle_plate": fake.license_plate(),
            "account_number": f"{rng.integers(10**9, 10**10)}",
            "ext_ref_1": fake.numerify("###-555-####"),  # trap: a phone number
            "cust_attr_9": fake.ssn(),                   # trap: an SSN
            "risk_score": round(float(rng.uniform(0, 1)), 3),
        }
        changed = rng.random() < 0.10  # SCD2: some patients moved
        start = dt.date(2023, 1, 1)
        if changed:
            moved = start + dt.timedelta(days=int(rng.integers(100, 900)))
            rows.append({**base, "valid_from": start, "valid_to": moved, "is_current": False})
            base = {**base, "address_line": fake.street_address(), "city": fake.city()}
            start = moved
        rows.append({**base, "valid_from": start, "valid_to": None, "is_current": True})
    df = pd.DataFrame(rows)
    df.insert(0, "patient_sk", np.arange(1, len(df) + 1))
    for col in ("dob", "valid_from", "valid_to"):
        df[col] = pd.to_datetime(df[col]).dt.date
    return df, payer_of


def _providers(rng, fake):
    rows = []
    for i in range(120):
        facility = i % 8
        rows.append({
            "npi": f"1{rng.integers(10**8, 10**9)}",
            "provider_name": fake.name(),
            "specialty": str(rng.choice(SPECIALTIES)),
            "facility_id": f"FAC{facility:03d}",
            "facility_name": f"Example Health Campus {facility}",
            "facility_phone": f"212-555-01{facility:02d}",
            "facility_zip": f"100{facility:02d}",
        })
    return pd.DataFrame(rows)


def _encounters(rng, fake, patients, payer_of, providers):
    current = patients[patients.is_current]
    start, days = dt.date(2023, 1, 1), 1085
    rows = []

    def add(p, admit, dx):
        los = int(rng.geometric(0.28))
        rows.append({
            "patient_sk": int(p.patient_sk), "mrn": p.mrn,
            "admit_date": admit, "discharge_date": admit + dt.timedelta(days=los),
            "length_of_stay_days": los, "dx_category": dx,
            "primary_dx_code": DIAGNOSES[dx], "payer_name": payer_of[p.mrn],
            "_name": f"{p.first_name} {p.last_name}", "_phone": p.phone,
        })
        return rows[-1]["discharge_date"]

    for p in current.itertuples():
        for _ in range(1 + rng.poisson(1.2)):
            admit = start + dt.timedelta(days=int(rng.integers(0, days)))
            dx = str(rng.choice(list(DIAGNOSES)))
            discharge = add(p, admit, dx)
            chance = PAYERS[payer_of[p.mrn]] * DX_RISK.get(dx, 1.0)
            if rng.random() < chance:
                add(p, discharge + dt.timedelta(days=int(rng.integers(3, 30))), dx)

    df = pd.DataFrame(rows).sort_values(["patient_sk", "admit_date"]).reset_index(drop=True)
    # The flag is computed here, in gold, because the de-identified layer only keeps
    # years and cannot express a 30-day window.
    next_admit = df.groupby("patient_sk")["admit_date"].shift(-1)
    gap = (pd.to_datetime(next_admit) - pd.to_datetime(df["discharge_date"])).dt.days
    df["readmitted_30d"] = gap.between(0, 30).fillna(False).astype(bool)

    n = len(df)
    df.insert(0, "encounter_id", [f"ENC{i:08d}" for i in range(1, n + 1)])
    df["facility_id"] = providers["facility_id"].to_numpy()[rng.integers(0, len(providers), n)]
    df["attending_npi"] = providers["npi"].to_numpy()[rng.integers(0, len(providers), n)]
    df["encounter_type"] = rng.choice(["Inpatient", "Observation", "ED"], n, p=[.7, .15, .15])
    df["drg_code"] = rng.choice(["291", "292", "190", "193", "470", "683"], n)
    df["implant_device_serial"] = [
        fake.bothify("SN-####-????").upper() if rng.random() < 0.08 else None for _ in range(n)
    ]
    df["clinical_note"] = [
        f"{name} called from {phone} about {dx.lower()} follow-up." if rng.random() < 0.6
        else f"Patient stable. Continue {dx.lower()} plan and review in clinic."
        for name, phone, dx in zip(df["_name"], df["_phone"], df["dx_category"])
    ]
    df = df.drop(columns=["_name", "_phone"])
    for col in ("admit_date", "discharge_date"):
        df[col] = pd.to_datetime(df[col]).dt.date
    return df


def _claims(rng, encounters):
    rows = []
    for e in encounters.itertuples():
        for _ in range(int(rng.integers(1, 4))):
            billed = round(float(rng.lognormal(7.2, 0.9)), 2)
            denied = rng.random() < (0.16 if e.payer_name == "Medicaid" else 0.09)
            rows.append({
                "encounter_id": e.encounter_id, "mrn": e.mrn,
                "member_id": f"W{int(hashlib.sha1(e.mrn.encode()).hexdigest(), 16) % 10**9:09d}",
                "payer_name": e.payer_name, "service_date": e.admit_date,
                "procedure_code": str(rng.choice(CPT)), "billed_amount": billed,
                "paid_amount": 0.0 if denied else round(billed * float(rng.uniform(.35, .9)), 2),
                "claim_status": "DENIED" if denied else "PAID",
                "denial_reason": str(rng.choice(DENIALS)) if denied else None,
            })
    df = pd.DataFrame(rows)
    df.insert(0, "claim_id", [f"CLM{i:09d}" for i in range(1, len(df) + 1)])
    df["service_date"] = pd.to_datetime(df["service_date"]).dt.date
    return df


def _portal(rng, fake, patients):
    current = patients[patients.is_current]
    chosen = current.sample(frac=0.6, random_state=int(rng.integers(1 << 31)))
    rows = []
    for p in chosen.itertuples():
        for _ in range(int(rng.integers(1, 4))):
            rows.append({
                "mrn": p.mrn,
                "login_ts": pd.Timestamp("2025-01-01") + pd.Timedelta(minutes=int(rng.integers(0, 525000))),
                "login_ip": fake.ipv4_public(), "device_id": fake.uuid4(),
                "portal_url": f"https://portal.example.org/patient/{p.mrn}",
                "photo_url": f"https://cdn.example.org/photos/{p.mrn}.jpg",
                "fingerprint_template": hashlib.sha256(p.mrn.encode()).hexdigest(),
                "page_views": int(rng.integers(1, 30)),
            })
    df = pd.DataFrame(rows)
    df.insert(0, "activity_id", np.arange(1, len(df) + 1))
    return df
