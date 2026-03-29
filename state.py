# reasoning/state.py
# The state object flowing through every LangGraph node.
#
# WHY A TYPED DICT AND NOT A PYDANTIC MODEL:
# LangGraph requires TypedDict specifically because it needs
# to track which fields were updated by each node.
# Pydantic models don't support the partial update pattern
# LangGraph uses internally.
#
# Every field maps to a specific node's responsibility:
# - assess_node sets: should_proceed, termination_reason
# - retrieve_context_node sets: historical_context, enriched_context
# - reasoning_node sets: llm_raw_output, parsed_playbook, etc.
# - validation_node sets: validated_playbook, validation_passed
# - write_playbook_node sets: final_playbook_id, pipeline_complete

from typing import TypedDict, Optional, List, Dict, Any


class AgentState(TypedDict):

    # ── Mandatory inputs (set before graph starts) ────────────
    incident_id: str
    fidelity_output: dict       # Full FidelityOutput from Layer 8
    incident: dict              # Full CorrelatedIncident from Layer 7
    requested_by: str           # Who triggered this — NEVER auto-set

    # ── Assess node ───────────────────────────────────────────
    should_proceed: Optional[bool]
    termination_reason: Optional[str]

    # ── Context retrieval node ────────────────────────────────
    historical_context: Optional[List[dict]]
    enriched_context: Optional[dict]

    # ── Reasoning node ────────────────────────────────────────
    llm_raw_output: Optional[str]
    reasoning_trace: Optional[str]
    parsed_playbook: Optional[dict]
    llm_retry_count: int
    llm_error: Optional[str]

    # ── Validation node ───────────────────────────────────────
    validated_playbook: Optional[dict]
    validation_passed: Optional[bool]
    validation_errors: Optional[List[str]]

    # ── Human gate ────────────────────────────────────────────
    # The graph STOPS here. Nothing executes past this point
    # without a human setting human_decision = "approved"
    # through the FastAPI endpoint (your teammate's layer).
    awaiting_approval: bool
    human_decision: Optional[str]   # "approved" | "rejected"
    approved_by: Optional[str]

    # ── Provenance ────────────────────────────────────────────
    provenance_id: Optional[str]
    node_execution_log: List[dict]  # Every node + timing

    # ── Final output ──────────────────────────────────────────
    final_playbook_id: Optional[str]
    pipeline_complete: bool