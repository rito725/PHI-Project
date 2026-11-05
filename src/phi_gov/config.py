"""Runtime settings, read from the environment."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _load_dotenv(path: Path) -> None:
    """Minimal .env reader, so the project needs no extra dependency for it."""
    if not path.exists():
        return
    for line in path.read_text().splitlines():
        line = line.split(" #")[0].strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if value.strip():
            os.environ.setdefault(key.strip(), value.strip())


@dataclass(frozen=True)
class Settings:
    warehouse_backend: str = "duckdb"
    dlp_backend: str = "local"
    llm_backend: str = "offline"
    claude_model: str = "claude-opus-5-5"
    duckdb_path: str = str(ROOT / "data" / "phi_demo.duckdb")
    reports_dir: str = str(ROOT / "reports")
    gcp_project: str = ""
    bq_location: str = "US"
    analyst_credentials_file: str = ""
    gold_dataset: str = "phi_gold"
    deid_dataset: str = "phi_deid"
    governance_dataset: str = "phi_governance"
    restricted_dataset: str = "phi_restricted"
    max_rows: int = 1000
    max_bytes_billed: int = 1_000_000_000
    max_sql_retries: int = 2
    sample_size: int = 50
    review_confidence: float = 0.70

    @classmethod
    def from_env(cls) -> "Settings":
        _load_dotenv(ROOT / ".env")
        env = os.environ.get
        llm = env("LLM_BACKEND", "auto")
        if llm == "auto":
            llm = "claude" if env("ANTHROPIC_API_KEY") else "offline"
        return cls(
            warehouse_backend=env("WAREHOUSE_BACKEND", "duckdb"),
            dlp_backend=env("DLP_BACKEND", "local"),
            llm_backend=llm,
            claude_model=env("CLAUDE_MODEL", cls.claude_model),
            duckdb_path=env("DUCKDB_PATH", cls.duckdb_path),
            gcp_project=env("GCP_PROJECT", ""),
            bq_location=env("BQ_LOCATION", "US"),
            analyst_credentials_file=env("ANALYST_CREDENTIALS_FILE", ""),
            max_rows=int(env("MAX_ROWS", cls.max_rows)),
            max_bytes_billed=int(env("MAX_BYTES_BILLED", cls.max_bytes_billed)),
        )
