# reasoning/agent.py
# Assembles nodes into LangGraph state machine.
# Exposes SOCReasoningAgent as the single entry point.
#
# GRAPH STRUCTURE:
#
#   START
#     ↓
#   assess_node
#     ↓ should_proceed=True    ↓ should_proceed=False
#   retrieve_context_node      END (with termination_reason)
#     ↓
#   reasoning_node
#     ↓ parsed_playbook exists  ↓ all retries failed
#   validation_node             END (with llm_error)
#     ↓ valid steps exist       ↓ no valid steps
#   write_playbook_node         END
#     ↓
#   END (playbook in pending_review, awaiting human)

import os
import sys
sys.path.append(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)

from typing import Literal
from langgraph.graph import StateGraph, END
from elasticsearch import Elasticsearch
from loguru import logger
from dotenv import load_dotenv
from uuid import uuid4

from reasoning.state import AgentState
from reasoning.nodes import (
    assess_node,
    retrieve_context_node,
    reasoning_node,
    validation_node,
    write_playbook_node
)
from reasoning.provenance_logger import ProvenanceLogger

load_dotenv()


def _get_es() -> Elasticsearch:
    return Elasticsearch(
        f"http://{os.getenv('ES_HOST', 'localhost')}:"
        f"{os.getenv('ES_PORT', '9200')}",
        basic_auth=(
            os.getenv('ES_USERNAME', 'elastic'),
            os.getenv('ES_PASSWORD', 'actaware123')
        )
    )


# ── Conditional edge functions ─────────────────────────────────────────────────

def route_after_assess(
    state: AgentState
) -> Literal["retrieve_context", "__end__"]:
    if state.get("should_proceed"):
        return "retrieve_context"
    return "__end__"


def route_after_reasoning(
    state: AgentState
) -> Literal["validate", "__end__"]:
    if state.get("parsed_playbook"):
        return "validate"
    return "__end__"


def route_after_validation(
    state: AgentState
) -> Literal["write_playbook", "__end__"]:
    playbook = state.get("validated_playbook")
    if playbook and len(playbook.get("steps", [])) > 0:
        return "write_playbook"
    return "__end__"


# ── Graph assembly ─────────────────────────────────────────────────────────────

def build_graph() -> StateGraph:
    graph = StateGraph(AgentState)

    graph.add_node("assess", assess_node)
    graph.add_node("retrieve_context", retrieve_context_node)
    graph.add_node("reason", reasoning_node)
    graph.add_node("validate", validation_node)
    graph.add_node("write_playbook", write_playbook_node)

    graph.set_entry_point("assess")

    graph.add_conditional_edges(
        "assess",
        route_after_assess,
        {
            "retrieve_context": "retrieve_context",
            "__end__": END
        }
    )

    graph.add_edge("retrieve_context", "reason")

    graph.add_conditional_edges(
        "reason",
        route_after_reasoning,
        {
            "validate": "validate",
            "__end__": END
        }
    )

    graph.add_conditional_edges(
        "validate",
        route_after_validation,
        {
            "write_playbook": "write_playbook",
            "__end__": END
        }
    )

    graph.add_edge("write_playbook", END)

    return graph.compile()


# ── Main entry point ───────────────────────────────────────────────────────────

class SOCReasoningAgent:
    """
    Single entry point for Layer 9 reasoning.

    Usage:
        agent = SOCReasoningAgent()
        result = agent.run(
            incident_id="abc-123",
            fidelity_id="def-456",
            requested_by="analyst_jane"
        )

    The requested_by field is mandatory.
    This is the proof that a human triggered reasoning.
    The system never calls this automatically.
    """

    def __init__(self):
        self.graph = build_graph()
        self.es = _get_es()
        self.provenance = ProvenanceLogger(self.es)
        logger.info("SOCReasoningAgent initialized")

    def _fetch_fidelity(self, fidelity_id: str) -> dict:
        result = self.es.get(
            index=os.getenv(
                'ES_INDEX_FIDELITY', 'act_aware_fidelity'
            ),
            id=fidelity_id
        )
        return result['_source']

    def _fetch_incident(self, incident_id: str) -> dict:
        result = self.es.get(
            index=os.getenv(
                'ES_INDEX_INCIDENTS', 'act_aware_incidents'
            ),
            id=incident_id
        )
        return result['_source']

    def run(
        self,
        incident_id: str,
        fidelity_id: str,
        requested_by: str
    ) -> dict:
        """
        Runs the full reasoning pipeline for one incident.
        Returns a result dict the API layer can return directly.
        """
        logger.info(
            f"SOCReasoningAgent.run: "
            f"incident={incident_id} "
            f"requested_by={requested_by}"
        )

        # Fetch required data
        try:
            fidelity_output = self._fetch_fidelity(fidelity_id)
            incident = self._fetch_incident(incident_id)
        except Exception as e:
            return {
                "success": False,
                "error": f"Could not fetch data: {e}",
                "incident_id": incident_id,
                "fidelity_id": fidelity_id,
                "playbook_id": None
            }

        pipeline_id = fidelity_output.get(
            "pipeline_id", str(uuid4())
        )

        # Log pipeline start
        self.provenance.log_pipeline_start(
            pipeline_id=pipeline_id,
            incident_id=incident_id,
            fidelity_score=fidelity_output.get(
                "fidelity_score", 0.0
            ),
            confidence=fidelity_output.get(
                "confidence", "unknown"
            ),
            requested_by=requested_by
        )

        # Build initial state
        initial_state: AgentState = {
            "incident_id": incident_id,
            "fidelity_output": fidelity_output,
            "incident": incident,
            "requested_by": requested_by,

            "should_proceed": None,
            "termination_reason": None,

            "historical_context": None,
            "enriched_context": None,

            "llm_raw_output": None,
            "reasoning_trace": None,
            "parsed_playbook": None,
            "llm_retry_count": 0,
            "llm_error": None,

            "validated_playbook": None,
            "validation_passed": None,
            "validation_errors": None,

            "awaiting_approval": False,
            "human_decision": None,
            "approved_by": None,

            "provenance_id": None,
            "node_execution_log": [],

            "final_playbook_id": None,
            "pipeline_complete": False
        }

        # Run the graph
        try:
            final_state = self.graph.invoke(initial_state)
        except Exception as e:
            logger.error(f"Graph execution failed: {e}")
            self.provenance.log_pipeline_end(
                pipeline_id=pipeline_id,
                incident_id=incident_id,
                playbook_id=None,
                success=False,
                reason=str(e)
            )
            return {
                "success": False,
                "error": str(e),
                "incident_id": incident_id,
                "playbook_id": None
            }

        # Build result
        if final_state.get("final_playbook_id"):
            return {
                "success": True,
                "incident_id": incident_id,
                "fidelity_id": fidelity_id,
                "playbook_id": final_state["final_playbook_id"],
                "status": "pending_review",
                "fidelity_score": fidelity_output.get(
                    "fidelity_score"
                ),
                "confidence": fidelity_output.get("confidence"),
                "steps_count": len(
                    final_state.get(
                        "validated_playbook", {}
                    ).get("steps", [])
                ),
                "awaiting_approval": True,
                "threat_narrative": final_state.get(
                    "validated_playbook", {}
                ).get("threat_narrative", ""),
                "node_execution_log": final_state.get(
                    "node_execution_log", []
                ),
                "pipeline_id": pipeline_id
            }
        else:
            self.provenance.log_pipeline_end(
                pipeline_id=pipeline_id,
                incident_id=incident_id,
                playbook_id=None,
                success=False,
                reason=final_state.get("termination_reason")
                       or final_state.get("llm_error")
            )
            return {
                "success": False,
                "incident_id": incident_id,
                "playbook_id": None,
                "termination_reason": final_state.get(
                    "termination_reason"
                ),
                "llm_error": final_state.get("llm_error"),
                "node_execution_log": final_state.get(
                    "node_execution_log", []
                ),
                "pipeline_id": pipeline_id
            }