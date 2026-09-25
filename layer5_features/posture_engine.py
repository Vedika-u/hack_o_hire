# layer5_features/posture_engine.py
"""
Layer 5: Security Posture Engine
Evaluates entity privilege misuse, behavioral drift, and access anomalies.
Produces contextual risk signals that feed into Layer 8 Fidelity Scoring.
"""

from typing import Dict, Any
from config.schemas import AggregatedBehavior, BehaviorFeatures
import logging

logger = logging.getLogger(__name__)


class SecurityPostureEngine:
    def __init__(self):
        pass

    def evaluate_posture(self, behavior: AggregatedBehavior) -> Dict[str, Any]:
        """
        Calculates posture risk score [0.0, 1.0] and risk reasons
        based on privilege misuse and behavioral deviations.
        """
        f: BehaviorFeatures = behavior.features
        signals = []
        score = 0.0

        # Privilege misuse checks
        if f.privilege_escalation_attempts > 0:
            weight = min(0.35, f.privilege_escalation_attempts * 0.20)
            score += weight
            signals.append(f"Privilege escalation attempts detected ({f.privilege_escalation_attempts})")

        if f.admin_action_count > 3:
            score += 0.20
            signals.append(f"Unusual surge in administrative actions ({f.admin_action_count})")

        if f.failed_privilege_actions > 0:
            score += 0.15
            signals.append(f"Failed privileged operations ({f.failed_privilege_actions})")

        # Sensitive resource access
        if f.sensitive_resource_access_count > 0:
            score += 0.25
            signals.append(f"Sensitive resource access observed ({f.sensitive_resource_access_count})")

        # Database bulk retrieval
        if f.db_rows_accessed > 5000:
            score += 0.30
            signals.append(f"Abnormal bulk database rows retrieved ({f.db_rows_accessed:,} rows)")

        # Temporal anomaly
        if f.after_hours_activity or f.weekend_activity:
            score += 0.10
            signals.append("Out-of-hours / weekend operational activity")

        # Cap posture score at 1.0
        posture_score = min(1.0, round(score, 4))

        return {
            "posture_score": posture_score,
            "risk_signals": signals,
            "is_high_risk": posture_score >= 0.70,
        }


posture_engine = SecurityPostureEngine()
