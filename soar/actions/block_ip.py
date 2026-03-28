# soar/actions/block_ip.py
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)


def execute_block_ip(
    target_entity: str,
    reason: str,
    incident_id: str,
) -> Dict[str, Any]:
    """
    Block an IP address at the network perimeter.
    Production: call firewall API or write iptables rule.
    Currently: simulation mode.
    """
    logger.info(f"[SIMULATED] Blocking IP: {target_entity} | Reason: {reason}")
    return {
        "action": "block_ip",
        "target": target_entity,
        "status": "simulated",
        "message": f"IP {target_entity} would be blocked at firewall",
        "incident_id": incident_id,
    }