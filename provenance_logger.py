# reasoning/provenance_logger.py
# Writes a complete audit trail of every reasoning decision
# to Elasticsearch.
#
# WHY THIS IS CRITICAL IN BANKING:
# Any automated system that influences security actions
# on financial infrastructure must be fully auditable.
# A compliance officer must be able to reconstruct:
# - Who triggered playbook generation
# - What data the LLM was given
# - What the LLM reasoned
# - What was validated and what was stripped
# - Who approved the final actions
# - When each action executed
#
# The pipeline_id is the thread connecting all of this
# across every layer from raw log to final action.
#
# FAILURE POLICY:
# Provenance write failures are FATAL.
# The system cannot take actions without an audit trail.
# If provenance logging fails, the pipeline halts.

import os
import sys
sys.path.append(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)

from datetime import datetime, timezone
from typing import Any, Dict, Optional
from uuid import uuid4
from elasticsearch import Elasticsearch
from loguru import logger
from dotenv import load_dotenv

load_dotenv()


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


# Event types written to provenance index
EVENT_TYPES = {
    "NODE_EXECUTION": "node_execution",
    "LLM_CALL": "llm_call",
    "CONSTRAINT_CHECK": "constraint_check",
    "HUMAN_TRIGGER": "human_trigger",
    "HUMAN_DECISION": "human_decision",
    "PIPELINE_START": "pipeline_start",
    "PIPELINE_END": "pipeline_end",
    "PIPELINE_ABORT": "pipeline_abort"
}

PROVENANCE_INDEX = "act_aware_provenance"


class ProvenanceLogger:

    def __init__(self, es_client: Elasticsearch):
        self.es = es_client
        self._ensure_index()

    def _ensure_index(self):
        """Creates provenance index if it does not exist."""
        try:
            if not self.es.indices.exists(
                index=PROVENANCE_INDEX
            ):
                self.es.indices.create(
                    index=PROVENANCE_INDEX,
                    body={
                        "mappings": {
                            "properties": {
                                "provenance_id": {
                                    "type": "keyword"
                                },
                                "pipeline_id": {
                                    "type": "keyword"
                                },
                                "incident_id": {
                                    "type": "keyword"
                                },
                                "event_type": {
                                    "type": "keyword"
                                },
                                "node_name": {
                                    "type": "keyword"
                                },
                                "timestamp": {
                                    "type": "date"
                                },
                                "duration_ms": {
                                    "type": "float"
                                },
                                "requested_by": {
                                    "type": "keyword"
                                },
                                "success": {
                                    "type": "boolean"
                                },
                                "payload": {
                                    "type": "object",
                                    "enabled": False
                                }
                            }
                        }
                    }
                )
                logger.info(
                    f"Created index: {PROVENANCE_INDEX}"
                )
        except Exception as e:
            logger.warning(
                f"Could not create provenance index "
                f"(may already exist): {e}"
            )

    def _write(self, doc: dict) -> str:
        """
        Writes a provenance record to Elasticsearch.
        FATAL on failure — provenance must never be silent.
        """
        provenance_id = doc.get(
            "provenance_id", str(uuid4())
        )
        try:
            self.es.index(
                index=PROVENANCE_INDEX,
                id=provenance_id,
                document=doc,
                refresh=False
            )
            return provenance_id
        except Exception as e:
            logger.error(
                f"PROVENANCE WRITE FAILURE: {e}\n"
                f"Document: {doc}"
            )
            raise RuntimeError(
                f"Provenance logging failed. "
                f"Pipeline cannot continue without audit trail. "
                f"Error: {e}"
            )

    def log_pipeline_start(
        self,
        pipeline_id: str,
        incident_id: str,
        fidelity_score: float,
        confidence: str,
        requested_by: str
    ) -> str:
        doc = {
            "provenance_id": str(uuid4()),
            "pipeline_id": pipeline_id,
            "incident_id": incident_id,
            "event_type": EVENT_TYPES["PIPELINE_START"],
            "node_name": "pipeline",
            "timestamp": utc_now().isoformat(),
            "duration_ms": 0,
            "requested_by": requested_by,
            "success": True,
            "payload": {
                "fidelity_score": fidelity_score,
                "confidence": confidence,
                "triggered_by": requested_by
            }
        }
        return self._write(doc)

    def log_node_execution(
        self,
        pipeline_id: str,
        incident_id: str,
        node_name: str,
        input_summary: Dict[str, Any],
        output_summary: Dict[str, Any],
        duration_ms: float,
        success: bool,
        requested_by: str = "system"
    ) -> str:
        doc = {
            "provenance_id": str(uuid4()),
            "pipeline_id": pipeline_id,
            "incident_id": incident_id,
            "event_type": EVENT_TYPES["NODE_EXECUTION"],
            "node_name": node_name,
            "timestamp": utc_now().isoformat(),
            "duration_ms": round(duration_ms, 2),
            "requested_by": requested_by,
            "success": success,
            "payload": {
                "input_summary": input_summary,
                "output_summary": output_summary
            }
        }
        return self._write(doc)

    def log_llm_call(
        self,
        pipeline_id: str,
        incident_id: str,
        prompt_chars: int,
        response_chars: int,
        duration_ms: float,
        retry_count: int,
        success: bool,
        error: Optional[str] = None
    ) -> str:
        doc = {
            "provenance_id": str(uuid4()),
            "pipeline_id": pipeline_id,
            "incident_id": incident_id,
            "event_type": EVENT_TYPES["LLM_CALL"],
            "node_name": "reasoning_node",
            "timestamp": utc_now().isoformat(),
            "duration_ms": round(duration_ms, 2),
            "requested_by": "system",
            "success": success,
            "payload": {
                "prompt_chars": prompt_chars,
                "response_chars": response_chars,
                "retry_count": retry_count,
                "error": error
            }
        }
        return self._write(doc)

    def log_constraint_check(
        self,
        pipeline_id: str,
        incident_id: str,
        steps_in: int,
        steps_out: int,
        violations: list,
        within_constraints: bool
    ) -> str:
        doc = {
            "provenance_id": str(uuid4()),
            "pipeline_id": pipeline_id,
            "incident_id": incident_id,
            "event_type": EVENT_TYPES["CONSTRAINT_CHECK"],
            "node_name": "validation_node",
            "timestamp": utc_now().isoformat(),
            "duration_ms": 0,
            "requested_by": "system",
            "success": within_constraints,
            "payload": {
                "steps_before_validation": steps_in,
                "steps_after_validation": steps_out,
                "violations_found": violations,
                "within_constraints": within_constraints
            }
        }
        return self._write(doc)

    def log_human_trigger(
        self,
        pipeline_id: str,
        incident_id: str,
        requested_by: str,
        fidelity_score: float
    ) -> str:
        """
        Records the moment a human explicitly requested
        playbook generation.
        This is the event that proves human-in-the-loop.
        """
        doc = {
            "provenance_id": str(uuid4()),
            "pipeline_id": pipeline_id,
            "incident_id": incident_id,
            "event_type": EVENT_TYPES["HUMAN_TRIGGER"],
            "node_name": "human_trigger",
            "timestamp": utc_now().isoformat(),
            "duration_ms": 0,
            "requested_by": requested_by,
            "success": True,
            "payload": {
                "triggered_by": requested_by,
                "fidelity_score_at_trigger": fidelity_score,
                "trigger_timestamp": utc_now().isoformat()
            }
        }
        return self._write(doc)

    def log_human_decision(
        self,
        pipeline_id: str,
        incident_id: str,
        playbook_id: str,
        decision: str,
        decided_by: str
    ) -> str:
        """
        Records approval or rejection of the playbook
        by a human analyst.
        """
        doc = {
            "provenance_id": str(uuid4()),
            "pipeline_id": pipeline_id,
            "incident_id": incident_id,
            "event_type": EVENT_TYPES["HUMAN_DECISION"],
            "node_name": "human_gate",
            "timestamp": utc_now().isoformat(),
            "duration_ms": 0,
            "requested_by": decided_by,
            "success": decision == "approved",
            "payload": {
                "playbook_id": playbook_id,
                "decision": decision,
                "decided_by": decided_by,
                "decision_timestamp": utc_now().isoformat()
            }
        }
        return self._write(doc)

    def log_pipeline_end(
        self,
        pipeline_id: str,
        incident_id: str,
        playbook_id: Optional[str],
        success: bool,
        reason: Optional[str] = None
    ) -> str:
        doc = {
            "provenance_id": str(uuid4()),
            "pipeline_id": pipeline_id,
            "incident_id": incident_id,
            "event_type": (
                EVENT_TYPES["PIPELINE_END"]
                if success else
                EVENT_TYPES["PIPELINE_ABORT"]
            ),
            "node_name": "pipeline",
            "timestamp": utc_now().isoformat(),
            "duration_ms": 0,
            "requested_by": "system",
            "success": success,
            "payload": {
                "playbook_id": playbook_id,
                "termination_reason": reason
            }
        }
        return self._write(doc)

    def get_full_trail(self, pipeline_id: str) -> list:
        """
        Returns complete ordered audit trail for one pipeline run.
        Used for compliance queries.
        """
        try:
            result = self.es.search(
                index=PROVENANCE_INDEX,
                body={
                    "query": {
                        "term": {"pipeline_id": pipeline_id}
                    },
                    "sort": [{"timestamp": {"order": "asc"}}],
                    "size": 200
                }
            )
            return [
                h['_source']
                for h in result['hits']['hits']
            ]
        except Exception as e:
            logger.error(
                f"Could not fetch provenance trail: {e}"
            )
            return []