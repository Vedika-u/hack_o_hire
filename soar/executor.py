# soar/executor.py
from config.schemas import PlaybookStep, SOARConstraints
from soar.safety_checks import check_action_allowed, check_rate_limit
from soar.audit import audit_logger
from soar.actions.block_ip import execute_block_ip
from soar.actions.disable_account import execute_disable_account
from soar.actions.isolate_endpoint import execute_isolate_endpoint
from soar.actions.force_logout import execute_force_logout
from soar.actions.revoke_token import execute_revoke_token
from soar.actions.quarantine_file import execute_quarantine_file
from soar.actions.alert_analyst import execute_alert_analyst
from typing import Dict, Any, Optional
from datetime import datetime, timezone
from uuid import uuid4
import logging

from storage.es_client import es_client
from config.settings import settings

logger = logging.getLogger(__name__)


ACTION_HANDLERS = {
    "block_ip": execute_block_ip,
    "disable_account": execute_disable_account,
    "isolate_endpoint": execute_isolate_endpoint,
    "force_logout": execute_force_logout,
    "revoke_token": execute_revoke_token,
    "quarantine_file": execute_quarantine_file,
    "alert_analyst": execute_alert_analyst,
    "increase_monitoring": execute_alert_analyst,
}


class ExecutionResult:
    def __init__(
        self,
        success: bool,
        message: str,
        details: Optional[Dict[str, Any]] = None
    ):
        self.success = success
        self.message = message
        self.details = details or {}


def execute_step(
    step: PlaybookStep,
    constraints: SOARConstraints,
    executor_username: str,
    executor_role: str,
    pipeline_id: str,
    incident_id: str,
) -> ExecutionResult:

    # Step 1: Safety Checks
    safety = check_action_allowed(step, constraints)
    if not safety.passed:
        audit_logger.log(
            action="execute_soar_action_blocked",
            actor=executor_username,
            actor_role=executor_role,
            target_type="playbook_step",
            target_id=f"step_{step.step_number}",
            details={
                "action": step.action,
                "target_entity": step.target_entity,
                "safety_errors": safety.errors,
            },
            outcome="denied",
            pipeline_id=pipeline_id,
        )
        return ExecutionResult(
            success=False,
            message=f"Safety check failed: {'; '.join(safety.errors)}"
        )

    # Step 2: Rate Limit Check
    rate_check = check_rate_limit()
    if not rate_check.passed:
        audit_logger.log(
            action="execute_soar_action_rate_limited",
            actor=executor_username,
            actor_role=executor_role,
            target_type="playbook_step",
            target_id=f"step_{step.step_number}",
            details={"rate_limit_errors": rate_check.errors},
            outcome="denied",
            pipeline_id=pipeline_id,
        )
        return ExecutionResult(
            success=False,
            message=f"Rate limit exceeded: {'; '.join(rate_check.errors)}"
        )

    # Step 3: Find Handler
    handler = ACTION_HANDLERS.get(step.action)
    if not handler:
        return ExecutionResult(
            success=False,
            message=f"No handler registered for action: {step.action}"
        )

    # Step 4: Execute
    try:
        logger.info(
            f"EXECUTING: {step.action} on {step.target_entity} "
            f"by {executor_username} for incident {incident_id}"
        )

        handler_result = handler(
            target_entity=step.target_entity,
            reason=step.reason,
            incident_id=incident_id,
        )

        # Step 5: Mark step as executed
        now = datetime.now(timezone.utc)
        step.executed = True
        step.executed_at = now

        # Step 6: Write to soc_actions
        # Step 6: Write to soc_actions
        try:
            action_doc = {
    "action_id": str(uuid4()),
    "playbook_id": pipeline_id,
    "step_number": step.step_number,
    "action": step.action,
    "target": step.target_entity,
    "reason": step.reason,
    "executed_by": executor_username,
    "executed_at": now.isoformat(),
    "success": True,
    "outcome": f"Successfully executed {step.action} on {step.target_entity}",
    "pipeline_id": pipeline_id,
    "incident_id": incident_id,
    "handler_message": str(handler_result.get("message", "")) if isinstance(handler_result, dict) else str(handler_result),
}
            write_result = es_client._index(
                settings.INDEX_ACTIONS,
                action_doc["action_id"],
                action_doc
            )
            print(f"SOC_ACTIONS WRITE: {write_result} | ID: {action_doc['action_id']}")
            logger.info(f"Written to soc_actions: {action_doc['action_id']}")
        except Exception as write_error:
            print(f"SOC_ACTIONS WRITE ERROR: {write_error}")
            logger.error(f"Failed to write to soc_actions: {write_error}")

        # Step 7: Audit Log Success
        audit_logger.log(
            action="execute_soar_action",
            actor=executor_username,
            actor_role=executor_role,
            target_type="playbook_step",
            target_id=f"step_{step.step_number}",
            details={
                "action": step.action,
                "target_entity": step.target_entity,
                "reason": step.reason,
                "handler_result": handler_result,
                "incident_id": incident_id,
            },
            outcome="success",
            pipeline_id=pipeline_id,
        )

        return ExecutionResult(
            success=True,
            message=f"Successfully executed {step.action} on {step.target_entity}",
            details=handler_result,
        )

    except Exception as e:
        logger.error(f"Action execution failed: {step.action} - {e}")

        # Write failed action to soc_actions too
        now = datetime.now(timezone.utc)
        action_doc = {
            "action_id": str(uuid4()),
            "playbook_id": pipeline_id,
            "step_number": step.step_number,
            "action": step.action,
            "target": step.target_entity,
            "executed_by": executor_username,
            "executed_at": now.isoformat(),
            "success": False,
            "outcome": f"Execution failed: {str(e)}",
            "pipeline_id": pipeline_id,
            "incident_id": incident_id,
        }
        es_client._index(
            settings.INDEX_ACTIONS,
            action_doc["action_id"],
            action_doc
        )
        logger.info(f"Written failed action to soc_actions: {action_doc['action_id']}")

        # Audit Log Failure
        audit_logger.log(
            action="execute_soar_action",
            actor=executor_username,
            actor_role=executor_role,
            target_type="playbook_step",
            target_id=f"step_{step.step_number}",
            details={
                "action": step.action,
                "target_entity": step.target_entity,
                "error": str(e),
            },
            outcome="failure",
            pipeline_id=pipeline_id,
        )

        return ExecutionResult(
            success=False,
            message=f"Execution failed: {str(e)}"
        )