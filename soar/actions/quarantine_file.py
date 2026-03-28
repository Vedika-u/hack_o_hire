# soar/actions/quarantine_file.py
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)


def execute_quarantine_file(
    target_entity: str,
    reason: str,
    incident_id: str,
) -> Dict[str, Any]:
    """Move a file to quarantine."""
    logger.info(f"[SIMULATED] Quarantining file: {target_entity}")
    return {
        "action": "quarantine_file",
        "target": target_entity,
        "status": "simulated",
        "message": f"File {target_entity} would be moved to quarantine",
        "incident_id": incident_id,
    }