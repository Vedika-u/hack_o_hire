# soar/actions/alert_analyst.py
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)


def execute_alert_analyst(
    target_entity: str,
    reason: str,
    incident_id: str,
) -> Dict[str, Any]:
    """
    Send alert to analyst.
    Safest action — always allowed.
    Production: send to Slack, email, PagerDuty.
    """
    logger.info(f"[SIMULATED] Alerting analyst about: {target_entity}")
    return {
        "action": "alert_analyst",
        "target": target_entity,
        "status": "simulated",
        "message": f"Analyst would be alerted about {target_entity}",
        "incident_id": incident_id,
    }