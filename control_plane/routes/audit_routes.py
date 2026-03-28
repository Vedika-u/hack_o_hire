# control_plane/routes/audit_routes.py
"""
Audit trail endpoints.
Only senior analysts and above can view audit logs.
"""

from fastapi import APIRouter, Depends, Query
from control_plane.auth import require_permission
from control_plane.rbac import User, Permission
from soar.audit import audit_logger
from typing import Optional

router = APIRouter(prefix="/api/v1/audit", tags=["Audit Trail"])


@router.get("/")
async def get_audit_trail(
    target_id: Optional[str] = Query(None),
    actor: Optional[str] = Query(None),
    action: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=500),
    user: User = Depends(require_permission(Permission.VIEW_AUDIT_LOG))
):
    """
    View immutable audit trail from Elasticsearch.
    Every approval, rejection and execution is logged here.
    Requires senior_analyst or higher.
    """
    results = audit_logger.get_audit_trail(
        target_id=target_id,
        actor=actor,
        action=action,
        limit=limit
    )

    return {
        "count": len(results),
        "audit_entries": results,
        "queried_by": user.username,
    }