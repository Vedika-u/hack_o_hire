# control_plane/routes/feedback.py
"""
Feedback loop endpoints.
Analysts submit feedback to improve detection accuracy.
"""

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from typing import Optional, Literal
from control_plane.auth import require_permission
from control_plane.rbac import User, Permission
from evaluation.feedback_loop import feedback_loop
from soar.audit import audit_logger

router = APIRouter(prefix="/api/v1/feedback", tags=["Feedback"])


class FeedbackRequest(BaseModel):
    incident_id: str
    playbook_id: Optional[str] = None
    feedback_type: Literal["true_positive", "false_positive", "needs_tuning"]
    severity_accurate: bool = True
    notes: str = ""


@router.post("/submit")
async def submit_feedback(
    request: FeedbackRequest,
    user: User = Depends(require_permission(Permission.VIEW_INCIDENTS))
):
    """
    Submit analyst feedback on an incident.
    Stored in Elasticsearch feedback index.
    Used to trigger model retraining when FP rate is too high.
    """
    result = feedback_loop.submit_feedback(
        incident_id=request.incident_id,
        analyst_username=user.username,
        feedback_type=request.feedback_type,
        severity_accurate=request.severity_accurate,
        notes=request.notes,
        playbook_id=request.playbook_id,
    )

    # Audit log
    audit_logger.log(
        action="submit_feedback",
        actor=user.username,
        actor_role=user.role.value,
        target_type="incident",
        target_id=request.incident_id,
        details={
            "feedback_type": request.feedback_type,
            "severity_accurate": request.severity_accurate,
            "notes": request.notes,
        },
        outcome="success",
    )

    return result


@router.get("/stats")
async def get_feedback_stats(
    time_range: str = "7d",
    user: User = Depends(require_permission(Permission.VIEW_METRICS))
):
    """
    Get feedback statistics.
    Shows false positive rate and retraining status.
    """
    return feedback_loop.get_stats(time_range)