# soar/actions/force_logout.py
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)


def execute_force_logout(
    target_entity: str,
    reason: str,
    incident_id: str,
) -> Dict[str, Any]:
    """Force logout all sessions for a user."""
    logger.info(f"[SIMULATED] Forcing logout: {target_entity}")
    return {
        "action": "force_logout",
        "target": target_entity,
        "status": "simulated",
        "message": f"All sessions for {target_entity} would be terminated",
        "incident_id": incident_id,
    }
