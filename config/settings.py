# config/settings.py
"""
Central configuration for ACT AWARE pipeline.
Supports dynamic environment loading (.env) with fallbacks for both
distributed team networking and local air-gapped offline operation.
"""

import os
from typing import List
from dotenv import load_dotenv

load_dotenv()


class Settings:
    # ── Environment & Logging ──────────────────────────
    PIPELINE_ENV: str = os.getenv("PIPELINE_ENV", "development")
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
    SCHEMA_VERSION: str = os.getenv("SCHEMA_VERSION", "1.1.0")

    # ── Elasticsearch Connection ───────────────────────
    # Reads from .env (e.g. 172.20.132.59 or localhost)
    ES_HOST_RAW: str = os.getenv("ES_HOST", "172.20.132.59")
    ES_PORT: int = int(os.getenv("ES_PORT", "9200"))
    ES_USERNAME: str = os.getenv("ES_USERNAME", "elastic")
    ES_PASSWORD: str = os.getenv("ES_PASSWORD", "actaware123")
    ES_VERIFY_CERTS: bool = False

    @property
    def ES_HOST(self) -> str:
        raw = self.ES_HOST_RAW.strip()
        if raw.startswith("http://") or raw.startswith("https://"):
            return raw if ":" in raw[8:] else f"{raw}:{self.ES_PORT}"
        return f"http://{raw}:{self.ES_PORT}"

    # ── Elasticsearch Unified Indices (Frozen Contract) ─
    ES_INDEX_EVENTS: str = os.getenv("ES_INDEX_EVENTS", "act_aware_events")
    ES_INDEX_BEHAVIORS: str = os.getenv("ES_INDEX_BEHAVIORS", "act_aware_behaviors")
    ES_INDEX_DETECTIONS: str = os.getenv("ES_INDEX_DETECTIONS", "act_aware_detections")
    ES_INDEX_INCIDENTS: str = os.getenv("ES_INDEX_INCIDENTS", "act_aware_incidents")
    ES_INDEX_FIDELITY: str = os.getenv("ES_INDEX_FIDELITY", "act_aware_fidelity")
    ES_INDEX_PLAYBOOKS: str = os.getenv("ES_INDEX_PLAYBOOKS", "act_aware_playbooks")
    ES_INDEX_PROVENANCE: str = os.getenv("ES_INDEX_PROVENANCE", "act_aware_provenance")

    # ── Governance & Control Indices ───────────────────
    INDEX_AUDIT: str = os.getenv("INDEX_AUDIT", "soc_audit_log")
    INDEX_METRICS: str = os.getenv("INDEX_METRICS", "soc_evaluation_metrics")
    INDEX_FEEDBACK: str = os.getenv("INDEX_FEEDBACK", "soc_feedback")
    INDEX_ACTIONS: str = os.getenv("INDEX_ACTIONS", "soc_actions")

    # Backward compatibility aliases for existing routes
    @property
    def INDEX_PLAYBOOKS(self) -> str:
        return self.ES_INDEX_PLAYBOOKS

    @property
    def INDEX_INCIDENTS(self) -> str:
        return self.ES_INDEX_INCIDENTS

    @property
    def INDEX_FIDELITY(self) -> str:
        return self.ES_INDEX_FIDELITY

    # ── Ollama Local LLM Connection ────────────────────
    OLLAMA_HOST: str = os.getenv("OLLAMA_HOST", "http://172.20.132.59:11434")
    OLLAMA_MODEL: str = os.getenv("OLLAMA_MODEL", "mistral")

    # ── JWT Auth ───────────────────────────────────────
    SECRET_KEY: str = os.getenv("SECRET_KEY", "act-aware-banking-soc-supersecret-jwt-key")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 120

    # ── SOAR Safety Constraints ────────────────────────
    MAX_ACTIONS_PER_HOUR: int = 50
    CRITICAL_ACTIONS: List[str] = [
        "disable_account",
        "isolate_endpoint",
        "block_ip"
    ]
    STANDARD_ACTIONS: List[str] = [
        "alert_analyst",
        "increase_monitoring",
        "force_logout",
        "revoke_token",
        "quarantine_file"
    ]


settings = Settings()