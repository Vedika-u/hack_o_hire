# control_plane/routes/playbooks.py
"""
Playbook review, approval, rejection and execution workflow.
This is the human-in-the-loop control layer.

Workflow:
  1. Playbook arrives from LLM with status=pending_review
  2. Analyst reviews each step
  3. Analyst approves or rejects steps
  4. SOC Manager executes approved steps
  5. Every action logged to Elasticsearch
"""

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from typing import Optional
from datetime import datetime, timezone
from config.schemas import PlaybookOutput, SOARConstraints
from control_plane.auth import require_permission
from control_plane.rbac import User, Permission
from soar.audit import audit_logger
from soar.executor import execute_step
from storage.es_client import es_client
from config.settings import settings

router = APIRouter(prefix="/api/v1/playbooks", tags=["Playbooks"])


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


# ── Request Models ────────────────────────

class ApproveStepRequest(BaseModel):
    step_number: int
    comment: Optional[str] = None


class RejectPlaybookRequest(BaseModel):
    reason: str


class ExecuteStepRequest(BaseModel):
    step_number: int


# ── Endpoints ─────────────────────────────

@router.get("/")
async def list_playbooks(
    status_filter: Optional[str] = None,
    user: User = Depends(require_permission(Permission.VIEW_PLAYBOOKS))
):
    """List all playbooks stored in Elasticsearch."""
    must_clauses = []
    if status_filter:
        must_clauses.append({"match": {"status": status_filter}})

    query = {
        "query": {
            "bool": {
                "must": must_clauses if must_clauses else [{"match_all": {}}]
            }
        },
        "sort": [{"generated_at": {"order": "desc"}}]
    }

    results = es_client.search_playbooks(query)
    return {"count": len(results), "playbooks": results}


@router.get("/{playbook_id}")
async def get_playbook(
    playbook_id: str,
    user: User = Depends(require_permission(Permission.VIEW_PLAYBOOKS))
):
    """Get a specific playbook by ID."""
    result = es_client.get_playbook(playbook_id)
    if not result:
        raise HTTPException(status_code=404, detail="Playbook not found")
    return result


@router.post("/{playbook_id}/approve-step")
async def approve_step(
    playbook_id: str,
    request: ApproveStepRequest,
    user: User = Depends(require_permission(Permission.APPROVE_STANDARD_ACTIONS))
):
    """
    Approve a single step in a playbook.
    Critical actions require senior_analyst or higher.
    All approvals are logged to Elasticsearch audit trail.
    """
    playbook_data = es_client.get_playbook(playbook_id)
    if not playbook_data:
        raise HTTPException(status_code=404, detail="Playbook not found")

    playbook = PlaybookOutput(**playbook_data)

    # Find the step
    step = None
    for s in playbook.steps:
        if s.step_number == request.step_number:
            step = s
            break

    if not step:
        raise HTTPException(
            status_code=404,
            detail=f"Step {request.step_number} not found"
        )

    # Critical actions need higher role
    if step.action in settings.CRITICAL_ACTIONS:
        if not user.has_permission(Permission.APPROVE_CRITICAL_ACTIONS):
            audit_logger.log(
                action="approve_step_denied",
                actor=user.username,
                actor_role=user.role.value,
                target_type="playbook_step",
                target_id=f"{playbook_id}/step_{request.step_number}",
                details={
                    "action": step.action,
                    "reason": "Insufficient role for critical action"
                },
                outcome="denied",
                pipeline_id=playbook.pipeline_id,
            )
            raise HTTPException(
                status_code=403,
                detail=f"Action '{step.action}' is critical. "
                       f"Requires senior_analyst or higher."
            )

    # Approve the step
    step.approved = True
    step.approved_by = user.username
    step.approved_at = utc_now()

    # Update playbook status
    all_approved = all(s.approved for s in playbook.steps)
    any_approved = any(s.approved for s in playbook.steps)

    if all_approved:
        playbook.status = "approved"
    elif any_approved:
        playbook.status = "partially_approved"

    # Save updated playbook to Elasticsearch
    es_client.store_playbook(playbook_id, playbook.model_dump())

    # Audit log
    audit_logger.log(
        action="approve_playbook_step",
        actor=user.username,
        actor_role=user.role.value,
        target_type="playbook_step",
        target_id=f"{playbook_id}/step_{request.step_number}",
        details={
            "action": step.action,
            "target_entity": step.target_entity,
            "comment": request.comment,
        },
        outcome="success",
        pipeline_id=playbook.pipeline_id,
    )

    return {
        "message": f"Step {request.step_number} approved",
        "step_action": step.action,
        "approved_by": user.username,
        "playbook_status": playbook.status,
    }


@router.post("/{playbook_id}/reject")
async def reject_playbook(
    playbook_id: str,
    request: RejectPlaybookRequest,
    user: User = Depends(require_permission(Permission.REJECT_PLAYBOOK))
):
    """
    Reject an entire playbook.
    No steps can be executed after rejection.
    """
    playbook_data = es_client.get_playbook(playbook_id)
    if not playbook_data:
        raise HTTPException(status_code=404, detail="Playbook not found")

    playbook = PlaybookOutput(**playbook_data)
    playbook.status = "rejected"

    # Save to Elasticsearch
    es_client.store_playbook(playbook_id, playbook.model_dump())

    # Audit log
    audit_logger.log(
        action="reject_playbook",
        actor=user.username,
        actor_role=user.role.value,
        target_type="playbook",
        target_id=playbook_id,
        details={"reason": request.reason},
        outcome="success",
        pipeline_id=playbook.pipeline_id,
    )

    return {
        "message": "Playbook rejected",
        "playbook_id": playbook_id,
        "rejected_by": user.username,
        "reason": request.reason,
    }


@router.post("/{playbook_id}/execute-step")
async def execute_approved_step(
    playbook_id: str,
    request: ExecuteStepRequest,
    user: User = Depends(require_permission(Permission.EXECUTE_ACTIONS))
):
    """
    Execute an approved playbook step.
    Requires EXECUTE_ACTIONS permission (soc_manager or higher).
    Runs safety checks before executing.
    """
    playbook_data = es_client.get_playbook(playbook_id)
    if not playbook_data:
        raise HTTPException(status_code=404, detail="Playbook not found")

    playbook = PlaybookOutput(**playbook_data)

    if playbook.status == "rejected":
        raise HTTPException(
            status_code=400,
            detail="Cannot execute steps from a rejected playbook"
        )

    # Find step
    step = None
    for s in playbook.steps:
        if s.step_number == request.step_number:
            step = s
            break

    if not step:
        raise HTTPException(
            status_code=404,
            detail=f"Step {request.step_number} not found"
        )

    if not step.approved:
        raise HTTPException(
            status_code=400,
            detail=f"Step {request.step_number} has not been approved yet"
        )

    if step.executed:
        raise HTTPException(
            status_code=400,
            detail=f"Step {request.step_number} already executed"
        )

    # Use default constraints
    constraints = SOARConstraints()

    # Execute the step
    result = execute_step(
        step=step,
        constraints=constraints,
        executor_username=user.username,
        executor_role=user.role.value,
        pipeline_id=playbook.pipeline_id,
        incident_id=playbook.incident_id,
    )

    # Update playbook in Elasticsearch
    all_executed = all(
        s.executed for s in playbook.steps if s.approved
    )
    if all_executed and any(s.approved for s in playbook.steps):
        playbook.status = "executed"

    es_client.store_playbook(playbook_id, playbook.model_dump())

    if result.success:
        return {
            "message": result.message,
            "step_number": request.step_number,
            "action": step.action,
            "target": step.target_entity,
            "executed_by": user.username,
            "details": result.details,
        }
    else:
        raise HTTPException(status_code=400, detail=result.message)