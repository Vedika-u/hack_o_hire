# control_plane/routes/metrics.py
"""
Evaluation and metrics endpoints.
"""

from fastapi import APIRouter, Depends, Query
from control_plane.auth import require_permission
from control_plane.rbac import User, Permission
from evaluation.metrics_engine import metrics_engine

router = APIRouter(prefix="/api/v1/metrics", tags=["Metrics"])


@router.get("/dashboard")
async def get_dashboard(
    time_range: str = Query(
        "24h",
        description="Time range: 1h, 6h, 24h, 7d, 30d"
    ),
    user: User = Depends(require_permission(Permission.VIEW_METRICS))
):
    """
    Get all system metrics.
    Shows alert reduction, playbook acceptance, action success rates.
    All computed from Elasticsearch data.
    """
    return metrics_engine.compute_all_metrics(time_range)