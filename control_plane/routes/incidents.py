# control_plane/routes/incidents.py
"""
Incident viewing endpoints.
Reads CorrelatedIncident records from Elasticsearch (written by Layer 7).
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from control_plane.auth import require_permission
from control_plane.rbac import User, Permission
from storage.es_client import es_client
from config.settings import settings
from typing import Optional

router = APIRouter(prefix="/api/v1/incidents", tags=["Incidents"])


@router.get("/")
async def list_incidents(
    severity: Optional[str] = Query(
        None,
        description="Filter by severity: low, medium, high, critical"
    ),
    limit: int = Query(50, ge=1, le=200),
    user: User = Depends(require_permission(Permission.VIEW_INCIDENTS))
):
    """
    List all incidents from Elasticsearch.
    Written by Layer 7 Correlation Engine.
    """
    must_clauses = []
    if severity:
        must_clauses.append({"match": {"severity": severity}})

    query = {
        "query": {
            "bool": {
                "must": must_clauses if must_clauses else [{"match_all": {}}]
            }
        },
        "sort": [{"created_at": {"order": "desc"}}]
    }

    results = es_client.search_incidents(query, size=limit)

    return {
        "count": len(results),
        "incidents": results,
        "queried_by": user.username,
    }


@router.get("/{incident_id}")
async def get_incident(
    incident_id: str,
    user: User = Depends(require_permission(Permission.VIEW_INCIDENTS))
):
    """Get a specific incident by ID."""
    result = es_client.get_incident(incident_id)
    if not result:
        raise HTTPException(status_code=404, detail="Incident not found")
    return result