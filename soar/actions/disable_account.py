# soar/actions/disable_account.py
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)


def execute_disable_account(
    target_entity: str,
    reason: str,
    incident_id: str,
) -> Dict[str, Any]:
    """
    Disable a user account in Active Directory / IAM.
    Production: call LDAP or IAM API.
    Currently: simulation mode.
    """
    logger.info(f"[SIMULATED] Disabling account: {target_entity}")
    return {
        "action": "disable_account",
        "target": target_entity,
        "status": "simulated",
        "message": f"Account {target_entity} would be disabled in AD/IAM",
        "incident_id": incident_id,
    }