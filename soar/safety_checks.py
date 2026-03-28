# soar/safety_checks.py
"""
Pre-execution safety validation for SOAR actions.
Every action MUST pass through these checks before execution.
"""

from config.schemas import PlaybookStep, SOARConstraints
from config.settings import settings
from storage.es_client import es_client
from typing import List
import logging

logger = logging.getLogger(__name__)

# Blast radius hierarchy — lowest to highest impact
BLAST_RADIUS_ORDER = ["user", "host", "department", "network", "system"]

# Which blast radius each action affects
ACTION_BLAST_RADIUS = {
    "alert_analyst": "user",
    "increase_monitoring": "user",
    "force_logout": "user",
    "revoke_token": "user",
    "disable_account": "user",
    "quarantine_file": "host",
    "isolate_endpoint": "host",
    "block_ip": "network",
}


class SafetyCheckResult:
    def __init__(self):
        self.passed: bool = True
        self.errors: List[str] = []
        self.warnings: List[str] = []

    def fail(self, reason: str):
        self.passed = False
        self.errors.append(reason)

    def warn(self, reason: str):
        self.warnings.append(reason)


def check_action_allowed(
    step: PlaybookStep,
    constraints: SOARConstraints
) -> SafetyCheckResult:
    """
    Validate a single playbook step against SOAR constraints.
    Checks allowlist, approval, and blast radius.
    """
    result = SafetyCheckResult()

    # Check 1: Action must be in allowlist
    if step.action not in constraints.allowed_soar_actions:
        result.fail(
            f"Action '{step.action}' is NOT in allowed_soar_actions. "
            f"Allowed: {constraints.allowed_soar_actions}"
        )

    # Check 2: Must be approved by human
    if constraints.require_human_approval and not step.approved:
        result.fail(
            f"Step {step.step_number} requires human approval. "
            f"Current approval status: {step.approved}"
        )

    # Check 3: Blast radius must be within limit
    action_radius = ACTION_BLAST_RADIUS.get(step.action, "system")
    max_radius = constraints.max_blast_radius
    action_level = BLAST_RADIUS_ORDER.index(action_radius)
    max_level = BLAST_RADIUS_ORDER.index(max_radius)

    if action_level > max_level:
        result.fail(
            f"Action '{step.action}' has blast radius '{action_radius}' "
            f"which exceeds max allowed '{max_radius}'"
        )

    # Check 4: Must not already be executed
    if step.executed:
        result.fail(
            f"Step {step.step_number} has already been executed."
        )

    return result


def check_rate_limit() -> SafetyCheckResult:
    """
    Check if we exceeded the maximum actions per hour.
    Prevents runaway automation.
    """
    result = SafetyCheckResult()

    query = {
        "query": {
            "bool": {
                "must": [
                    {"match": {"action": "execute_soar_action"}},
                    {"match": {"outcome": "success"}},
                    {"range": {"timestamp": {"gte": "now-1h"}}}
                ]
            }
        }
    }

    count = es_client.count_audit(query)

    if count >= settings.MAX_ACTIONS_PER_HOUR:
        result.fail(
            f"Rate limit exceeded: {count} actions in last hour. "
            f"Max allowed: {settings.MAX_ACTIONS_PER_HOUR}"
        )
    elif count >= settings.MAX_ACTIONS_PER_HOUR * 0.8:
        result.warn(
            f"Approaching rate limit: {count}/{settings.MAX_ACTIONS_PER_HOUR}"
        )

    return result