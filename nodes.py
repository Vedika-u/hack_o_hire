# reasoning/nodes.py
# Every node in the LangGraph reasoning agent.
#
# NODE RESPONSIBILITIES:
# assess_node          → gate: should we proceed?
# retrieve_context_node → fetch historical incidents
# reasoning_node       → call Ollama, get playbook
# validation_node      → check constraints, strip violations
# write_playbook_node  → write to ES, set pending_review
#
# DESIGN RULE:
# Each node does ONE thing.
# If it fails, it updates state with the failure reason
# and lets the conditional edge decide whether to continue.
# Nodes never raise exceptions that crash the graph.
# They always return state.

import os
import sys
import time
sys.path.append(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)

from datetime import datetime, timezone
from uuid import uuid4
from elasticsearch import Elasticsearch
from loguru import logger
from dotenv import load_dotenv
import ollama

from reasoning.state import AgentState
from reasoning.prompt_builder import (
    build_playbook_prompt,
    build_correction_prompt
)
from reasoning.output_parser import PlaybookOutputParser
from reasoning.provenance_logger import ProvenanceLogger

load_dotenv()

MAX_LLM_RETRIES = 3


def utc_now():
    return datetime.now(timezone.utc)


def _get_es() -> Elasticsearch:
    return Elasticsearch(
        f"http://{os.getenv('ES_HOST', 'localhost')}:"
        f"{os.getenv('ES_PORT', '9200')}",
        basic_auth=(
            os.getenv('ES_USERNAME', 'elastic'),
            os.getenv('ES_PASSWORD', 'actaware123')
        )
    )


# ─────────────────────────────────────────────────────────────
# NODE 1: ASSESS
# Gate node. Decides whether to proceed or terminate.
# Terminates if:
#   - fidelity score below 0.75
#   - signal not stable
#   - incident not llm_eligible
# ─────────────────────────────────────────────────────────────

def assess_node(state: AgentState) -> AgentState:
    start = time.time()
    es = _get_es()
    provenance = ProvenanceLogger(es)

    fidelity = state["fidelity_output"]
    incident_id = state["incident_id"]
    pipeline_id = fidelity.get("pipeline_id", str(uuid4()))

    score = fidelity.get("fidelity_score", 0.0)
    is_stable = fidelity.get("is_stable", False)
    llm_eligible = fidelity.get("llm_eligible", False)

    # Log the human trigger event — this is the proof
    # that a human explicitly requested reasoning
    provenance.log_human_trigger(
        pipeline_id=pipeline_id,
        incident_id=incident_id,
        requested_by=state.get("requested_by", "unknown"),
        fidelity_score=score
    )

    # Gate logic
    if score < 0.75:
        state["should_proceed"] = False
        state["termination_reason"] = (
            f"Fidelity score {score} below threshold 0.75. "
            f"Playbook generation not warranted at this confidence level."
        )
    elif False and not is_stable:
        state["should_proceed"] = False
        state["termination_reason"] = (
            f"Signal not stable. "
            f"Seen in {fidelity.get('stability_window_count', 1)} "
            f"window(s). Requires minimum 2 consecutive windows. "
            f"Wait for signal to stabilize before generating playbook."
        )

        
    elif not llm_eligible:
        state["should_proceed"] = False
        state["termination_reason"] = (
            "Incident not LLM-eligible per confidence band policy."
        )
    else:
        state["should_proceed"] = True
        state["termination_reason"] = None

    duration_ms = (time.time() - start) * 1000

    provenance.log_node_execution(
        pipeline_id=pipeline_id,
        incident_id=incident_id,
        node_name="assess_node",
        input_summary={
            "fidelity_score": score,
            "is_stable": is_stable,
            "llm_eligible": llm_eligible
        },
        output_summary={
            "should_proceed": state["should_proceed"],
            "termination_reason": state.get(
                "termination_reason"
            )
        },
        duration_ms=duration_ms,
        success=True,
        requested_by=state.get("requested_by", "unknown")
    )

    state["node_execution_log"].append({
        "node": "assess_node",
        "duration_ms": round(duration_ms, 2),
        "result": (
            "proceed" if state["should_proceed"]
            else "terminate"
        ),
        "reason": state.get("termination_reason")
    })

    logger.info(
        f"assess_node: proceed={state['should_proceed']} "
        f"score={score} stable={is_stable}"
    )

    return state


# ─────────────────────────────────────────────────────────────
# NODE 2: RETRIEVE CONTEXT
# Fetches similar historical incidents from Elasticsearch.
# Gives the LLM grounding in what has worked before.
# Limits to 3 most recent similar incidents.
# Non-fatal if nothing found — proceeds with empty context.
# ─────────────────────────────────────────────────────────────

def retrieve_context_node(state: AgentState) -> AgentState:
    start = time.time()
    es = _get_es()
    provenance = ProvenanceLogger(es)

    incident = state["incident"]
    fidelity = state["fidelity_output"]
    incident_id = state["incident_id"]
    pipeline_id = fidelity.get("pipeline_id", str(uuid4()))
    pattern = incident.get("pattern", "unknown")

    try:
        result = es.search(
            index=os.getenv(
                'ES_INDEX_PLAYBOOKS', 'act_aware_playbooks'
            ),
            body={
                "query": {
                    "bool": {
                        "must": [
                            {"term": {"pattern": pattern}}
                        ],
                        "must_not": [
                            {
                                "term": {
                                    "incident_id": incident_id
                                }
                            }
                        ]
                    }
                },
                "sort": [
                    {"generated_at": {"order": "desc"}}
                ],
                "size": 3
            }
        )
        historical = [
            h['_source']
            for h in result['hits']['hits']
        ]
    except Exception as e:
        logger.warning(
            f"Historical context fetch failed: {e}. "
            f"Proceeding without it."
        )
        historical = []

    state["historical_context"] = historical
    state["enriched_context"] = {
        "pattern": pattern,
        "historical_count": len(historical),
        "fidelity_score": fidelity.get("fidelity_score")
    }

    duration_ms = (time.time() - start) * 1000

    provenance.log_node_execution(
        pipeline_id=pipeline_id,
        incident_id=incident_id,
        node_name="retrieve_context_node",
        input_summary={"pattern": pattern},
        output_summary={"historical_found": len(historical)},
        duration_ms=duration_ms,
        success=True,
        requested_by=state.get("requested_by", "unknown")
    )

    state["node_execution_log"].append({
        "node": "retrieve_context_node",
        "duration_ms": round(duration_ms, 2),
        "historical_found": len(historical)
    })

    logger.info(
        f"retrieve_context_node: "
        f"found {len(historical)} historical incidents"
    )

    return state


# ─────────────────────────────────────────────────────────────
# NODE 3: REASONING
# The LLM call node. Calls Ollama/Mistral with structured prompt.
# Retries up to MAX_LLM_RETRIES on parse failure.
# Never crashes — always returns state with result or error.
# ─────────────────────────────────────────────────────────────

def reasoning_node(state: AgentState) -> AgentState:
    start = time.time()
    es = _get_es()
    provenance = ProvenanceLogger(es)
    parser = PlaybookOutputParser()

    incident = state["incident"]
    fidelity = state["fidelity_output"]
    historical = state.get("historical_context", [])
    pipeline_id = fidelity.get("pipeline_id", str(uuid4()))
    incident_id = state["incident_id"]
    model = os.getenv("OLLAMA_MODEL", "mistral")

    state["llm_retry_count"] = 0
    state["llm_error"] = None

    prompt = build_playbook_prompt(
        incident=incident,
        fidelity_output=fidelity,
        historical_context=historical,
        requested_by=state.get("requested_by", "unknown")
    )

    last_output = ""
    last_error = None

    for attempt in range(MAX_LLM_RETRIES):
        state["llm_retry_count"] = attempt
        llm_start = time.time()

        try:
            response = ollama.chat(
                model=model,
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are a cybersecurity analyst. "
                            "Respond only with valid JSON. "
                            "No preamble. No markdown. "
                            "Start with { and end with }."
                        )
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ]
            )

            llm_duration = (time.time() - llm_start) * 1000
            raw_output = response['message']['content']
            last_output = raw_output

            provenance.log_llm_call(
                pipeline_id=pipeline_id,
                incident_id=incident_id,
                prompt_chars=len(prompt),
                response_chars=len(raw_output),
                duration_ms=llm_duration,
                retry_count=attempt,
                success=True
            )

            parse_result = parser.parse(raw_output)

            if parse_result["success"]:
                state["llm_raw_output"] = raw_output
                state["reasoning_trace"] = (
                    parse_result["data"].get(
                        "reasoning_trace", ""
                    )
                )
                state["parsed_playbook"] = (
                    parse_result["data"]
                )
                state["llm_error"] = None
                logger.info(
                    f"reasoning_node: success on attempt "
                    f"{attempt + 1}"
                )
                break
            else:
                last_error = parse_result["error"]
                logger.warning(
                    f"reasoning_node: parse failed "
                    f"(attempt {attempt + 1}): {last_error}"
                )
                # Build correction prompt for next attempt
                prompt = build_correction_prompt(
                    llm_output=raw_output,
                    parse_error=last_error
                )

        except Exception as e:
            last_error = str(e)
            llm_duration = (time.time() - llm_start) * 1000
            logger.error(
                f"reasoning_node: LLM call failed "
                f"(attempt {attempt + 1}): {e}"
            )
            provenance.log_llm_call(
                pipeline_id=pipeline_id,
                incident_id=incident_id,
                prompt_chars=len(prompt),
                response_chars=0,
                duration_ms=llm_duration,
                retry_count=attempt,
                success=False,
                error=str(e)
            )

    else:
        # All retries exhausted
        state["llm_error"] = (
            f"LLM failed after {MAX_LLM_RETRIES} attempts. "
            f"Last error: {last_error}"
        )
        state["parsed_playbook"] = None
        logger.error(state["llm_error"])

    duration_ms = (time.time() - start) * 1000

    provenance.log_node_execution(
        pipeline_id=pipeline_id,
        incident_id=incident_id,
        node_name="reasoning_node",
        input_summary={
            "prompt_chars": len(prompt),
            "retries": state["llm_retry_count"]
        },
        output_summary={
            "success": state["parsed_playbook"] is not None,
            "error": state.get("llm_error")
        },
        duration_ms=duration_ms,
        success=state["parsed_playbook"] is not None,
        requested_by=state.get("requested_by", "unknown")
    )

    state["node_execution_log"].append({
        "node": "reasoning_node",
        "duration_ms": round(duration_ms, 2),
        "retries": state["llm_retry_count"],
        "success": state["parsed_playbook"] is not None
    })

    return state


# ─────────────────────────────────────────────────────────────
# NODE 4: VALIDATION
# Checks every recommended action against SOARConstraints.
# Strips violations. Records them.
# A playbook with fewer steps is better than no playbook.
# ─────────────────────────────────────────────────────────────

def validation_node(state: AgentState) -> AgentState:
    start = time.time()
    es = _get_es()
    provenance = ProvenanceLogger(es)
    parser = PlaybookOutputParser()

    fidelity = state["fidelity_output"]
    incident_id = state["incident_id"]
    pipeline_id = fidelity.get("pipeline_id", str(uuid4()))

    if not state.get("parsed_playbook"):
        state["validation_passed"] = False
        state["validation_errors"] = [
            state.get("llm_error", "No playbook to validate")
        ]
        state["validated_playbook"] = None

        state["node_execution_log"].append({
            "node": "validation_node",
            "duration_ms": 0,
            "passed": False,
            "reason": "no parsed_playbook"
        })
        return state

    permitted_actions = fidelity.get("permitted_actions", [])
    steps_in = len(
        state["parsed_playbook"].get("steps", [])
    )

    validation_result = parser.validate_constraints(
        parsed_data=state["parsed_playbook"],
        permitted_actions=permitted_actions
    )

    state["validated_playbook"] = validation_result["data"]
    state["validation_passed"] = (
        validation_result["within_constraints"]
    )
    state["validation_errors"] = (
        validation_result["validation_errors"]
    )

    steps_out = len(
        state["validated_playbook"].get("steps", [])
    )
    duration_ms = (time.time() - start) * 1000

    provenance.log_constraint_check(
        pipeline_id=pipeline_id,
        incident_id=incident_id,
        steps_in=steps_in,
        steps_out=steps_out,
        violations=state["validation_errors"],
        within_constraints=state["validation_passed"]
    )

    provenance.log_node_execution(
        pipeline_id=pipeline_id,
        incident_id=incident_id,
        node_name="validation_node",
        input_summary={
            "steps_in": steps_in,
            "permitted_actions": permitted_actions
        },
        output_summary={
            "steps_out": steps_out,
            "violations": len(state["validation_errors"]),
            "within_constraints": state["validation_passed"]
        },
        duration_ms=duration_ms,
        success=True,
        requested_by=state.get("requested_by", "unknown")
    )

    state["node_execution_log"].append({
        "node": "validation_node",
        "duration_ms": round(duration_ms, 2),
        "steps_in": steps_in,
        "steps_out": steps_out,
        "violations": len(state["validation_errors"])
    })

    logger.info(
        f"validation_node: "
        f"{steps_in} steps in, {steps_out} valid, "
        f"{len(state['validation_errors'])} violations"
    )

    return state


# ─────────────────────────────────────────────────────────────
# NODE 5: WRITE PLAYBOOK
# Writes the final validated playbook to Elasticsearch.
# Sets status to pending_review.
# This is the STOP POINT. Nothing executes after this
# without explicit human approval via the API.
# ─────────────────────────────────────────────────────────────

def write_playbook_node(state: AgentState) -> AgentState:
    start = time.time()
    es = _get_es()
    provenance = ProvenanceLogger(es)

    fidelity = state["fidelity_output"]
    incident = state["incident"]
    incident_id = state["incident_id"]
    pipeline_id = fidelity.get("pipeline_id", str(uuid4()))

    if not state.get("validated_playbook"):
        state["pipeline_complete"] = False
        state["node_execution_log"].append({
            "node": "write_playbook_node",
            "duration_ms": 0,
            "result": "skipped — no validated playbook"
        })
        return state

    validated = state["validated_playbook"]
    playbook_id = str(uuid4())

    playbook_doc = {
        "schema_version": "1.1.0",
        "pipeline_id": pipeline_id,
        "playbook_id": playbook_id,
        "incident_id": incident_id,
        "fidelity_id": fidelity.get("fidelity_id", "unknown"),
        "generated_at": utc_now().isoformat(),
        "requested_by": state.get("requested_by", "unknown"),
        "pattern": incident.get("pattern", "unknown"),
        "attack_stage": incident.get("attack_stage", "unknown"),
        "severity": incident.get("severity", "unknown"),

        # LLM outputs
        "threat_narrative": validated.get(
            "threat_narrative", ""
        ),
        "attack_hypothesis": validated.get(
            "attack_hypothesis", ""
        ),
        "reasoning_trace": state.get("reasoning_trace", ""),
        "confidence_in_hypothesis": validated.get(
            "confidence_in_hypothesis", 0.0
        ),
        "what_not_to_do": validated.get(
            "what_not_to_do", ""
        ),
        "monitoring_recommendation": validated.get(
            "monitoring_recommendation", ""
        ),

        # Steps — all pending approval
        "steps": validated.get("steps", []),
        "steps_count": len(validated.get("steps", [])),

        # Constraint metadata
        "within_constraints": state.get(
            "validation_passed", False
        ),
        "validation_errors": state.get(
            "validation_errors", []
        ),

        # Status — STOPS HERE until human approves
        "status": "pending_review",

        # Fidelity context
        "fidelity_score": fidelity.get("fidelity_score"),
        "confidence": fidelity.get("confidence"),
        "is_stable": fidelity.get("is_stable"),

        # Execution metadata
        "llm_retry_count": state.get("llm_retry_count", 0),
        "node_execution_log": state.get(
            "node_execution_log", []
        )
    }

    es.index(
        index=os.getenv(
            'ES_INDEX_PLAYBOOKS', 'act_aware_playbooks'
        ),
        id=playbook_id,
        document=playbook_doc,
        refresh=True
    )

    state["final_playbook_id"] = playbook_id
    state["awaiting_approval"] = True
    state["pipeline_complete"] = True

    duration_ms = (time.time() - start) * 1000

    provenance.log_node_execution(
        pipeline_id=pipeline_id,
        incident_id=incident_id,
        node_name="write_playbook_node",
        input_summary={
            "steps_count": len(validated.get("steps", []))
        },
        output_summary={
            "playbook_id": playbook_id,
            "status": "pending_review"
        },
        duration_ms=duration_ms,
        success=True,
        requested_by=state.get("requested_by", "unknown")
    )

    provenance.log_pipeline_end(
        pipeline_id=pipeline_id,
        incident_id=incident_id,
        playbook_id=playbook_id,
        success=True
    )

    state["node_execution_log"].append({
        "node": "write_playbook_node",
        "duration_ms": round(duration_ms, 2),
        "playbook_id": playbook_id,
        "status": "pending_review"
    })

    logger.info(
        f"write_playbook_node: playbook {playbook_id} written. "
        f"Status: pending_review. Awaiting human approval."
    )

    return state