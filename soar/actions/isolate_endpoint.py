# soar/actions/isolate_endpoint.py
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)


def execute_isolate_endpoint(
    target_entity: str,
    reason: str,
    incident_id: str,
) -> Dict[str, Any]:
    """
    Isolate an endpoint from the network via EDR.
    Production: call CrowdStrike/SentinelOne API.
    Currently: simulation mode.
    """
    logger.info(f"[SIMULATED] Isolating endpoint: {target_entity}")
    return {
        "action": "isolate_endpoint",
        "target": target_entity,
        "status": "simulated",
        "message": f"Endpoint {target_entity} would be isolated via EDR",
        "incident_id": incident_id,
    }
