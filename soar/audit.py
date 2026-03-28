# soar/audit.py
"""
Immutable audit logging for Layer 9-10.
Every action (approval, rejection, execution) is logged to Elasticsearch.
These logs CANNOT be modified after creation — they are the compliance trail.
"""

from config.settings import settings
from storage.es_client import es_client
from typing import Any, Dict, Optional
from uuid import uuid4
from datetime import datetime, timezone
import logging

logger = logging.getLogger(__name__)


def utc_now() -> datetime:
    """Current UTC time, timezone-aware."""
    return datetime.now(timezone.utc)


class AuditLogger:
    """
    Writes immutable audit records to Elasticsearch.
    Every significant action gets logged here.
    """

    def log(
        self,
        action: str,
        actor: str,
        actor_role: str,
        target_type: str,
        target_id: str,
        details: Dict[str, Any],
        outcome: str = "success",
        pipeline_id: Optional[str] = None,
    ) -> str:
        """
        Write an audit log entry.

        Args:
            action: What was done (e.g., "approve_playbook_step")
            actor: Username who performed the action
            actor_role: Role of the actor
            target_type: What was acted on (e.g., "playbook")
            target_id: ID of the target
            details: Additional context
            outcome: "success", "failure", "denied"
            pipeline_id: Trace back to pipeline execution

        Returns:
            audit_id: Unique ID for this audit entry
        """
        audit_id = str(uuid4())

        record = {
            "audit_id": audit_id,
            "timestamp": utc_now().isoformat(),
            "action": action,
            "actor": actor,
            "actor_role": actor_role,
            "target_type": target_type,
            "target_id": target_id,
            "details": details,
            "outcome": outcome,
            "pipeline_id": pipeline_id,
        }

        success = es_client.store_audit_log(audit_id, record)

        if success:
            logger.info(
                f"AUDIT | {action} | actor={actor} role={actor_role} | "
                f"target={target_type}:{target_id} | outcome={outcome}"
            )
        else:
            # Audit logging failure is CRITICAL
            logger.critical(
                f"AUDIT LOG FAILURE | {action} | actor={actor} | "
                f"target={target_type}:{target_id} | "
                f"THIS MUST BE INVESTIGATED"
            )

        return audit_id

    def get_audit_trail(
        self,
        target_id: Optional[str] = None,
        actor: Optional[str] = None,
        action: Optional[str] = None,
        limit: int = 100
    ) -> list:
        """Retrieve audit trail with optional filters."""
        must_clauses = []

        if target_id:
            must_clauses.append({"match": {"target_id": target_id}})
        if actor:
            must_clauses.append({"match": {"actor": actor}})
        if action:
            must_clauses.append({"match": {"action": action}})

        query = {
            "query": {
                "bool": {
                    "must": must_clauses if must_clauses else [{"match_all": {}}]
                }
            },
            "sort": [{"timestamp": {"order": "desc"}}]
        }

        return es_client.search_audit(query, size=limit)


# Singleton instance
audit_logger = AuditLogger()