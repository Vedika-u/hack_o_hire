# config/settings.py
"""
Central configuration for Layer 9-10.
All secrets and connection strings live here.
"""

from typing import List


class Settings:
    # Elasticsearch - CONNECT TO RUCHIKA'S CENTRAL ES
    ES_HOST: str = "http://97.86.32.151:9200"  # ← CHANGE: Add http:// and use Ruchika's IP
    ES_USERNAME: str = "elastic"                 # ← CORRECT
    ES_PASSWORD: str = "actaware123"             # ← CHANGE: Use correct password
    ES_VERIFY_CERTS: bool = False                # ← CORRECT

    # Index Names - MUST USE UNDERSCORES (act_aware_*) NOT HYPHENS (act-aware-*)
    INDEX_PLAYBOOKS: str = "act_aware_playbooks"       # ← CHANGE: underscore not hyphen
    INDEX_AUDIT: str = "soc_audit_log"                 # ← CHANGE: use soc_ prefix for your indices
    INDEX_METRICS: str = "soc_evaluation_metrics"      # ← CHANGE: use soc_ prefix
    INDEX_INCIDENTS: str = "act_aware_incidents"       # ← CHANGE: underscore not hyphen
    INDEX_FIDELITY: str = "act_aware_fidelity"         # ← CHANGE: underscore not hyphen
    INDEX_FEEDBACK: str = "soc_feedback"               # ← CHANGE: use soc_ prefix
    INDEX_ACTIONS: str = "soc_actions"                 # ← ADD THIS: for executed actions

    # JWT Auth
    SECRET_KEY: str = "your-secret-key-change-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    # SOAR Safety
    MAX_ACTIONS_PER_HOUR: int = 50
    CRITICAL_ACTIONS: List[str] = [
        "disable_account",
        "isolate_endpoint",
        "block_ip"
    ]
    STANDARD_ACTIONS: List[str] = [
        "alert_analyst",
        "increase_monitoring"
    ]


settings = Settings()