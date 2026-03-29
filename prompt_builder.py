# reasoning/prompt_builder.py
# Builds the structured prompt sent to Ollama/Mistral.
#
# PROMPT ARCHITECTURE:
# Section 1 — Role: tells the model what it is
# Section 2 — Hard constraints: what it CANNOT do
# Section 3 — Incident context: the actual threat data
# Section 4 — Historical context: what worked before
# Section 5 — Output schema: exact JSON it must produce
# Section 6 — Reasoning instruction: think before outputting
#
# The constraints section is the most important.
# It defines the boundary between a useful AI assistant
# and an uncontrolled system that recommends dangerous actions.

from typing import List


def build_playbook_prompt(
    incident: dict,
    fidelity_output: dict,
    historical_context: List[dict],
    requested_by: str
) -> str:

    # Condense timeline to max 8 entries
    timeline = incident.get("timeline", [])[-8:]
    if timeline:
        timeline_text = "\n".join([
            f"  [{str(e.get('timestamp', ''))[:19]}] "
            f"{e.get('entity_id', 'unknown')} "
            f"→ {e.get('action', 'unknown')} "
            f"on {e.get('resource', 'unknown')}"
            for e in timeline
        ])
    else:
        timeline_text = "  No timeline data available."

    # Score breakdown
    breakdown = fidelity_output.get("score_breakdown", {})
    breakdown_text = "\n".join([
        f"  {k}: {round(float(v), 3)}"
        for k, v in breakdown.items()
        if k != "weights" and isinstance(v, (int, float))
    ])

    # Permitted actions for this confidence band
    permitted = fidelity_output.get("permitted_actions", [])
    permitted_text = (
        ", ".join(permitted) if permitted else "alert_analyst"
    )

    # Top anomalous features from fidelity reasoning
    reasoning = fidelity_output.get("reasoning", {})
    anomaly_detail = reasoning.get("anomaly_detail", {})
    model_details = anomaly_detail.get("detail", [])
    if model_details:
        features_text = "\n".join([
            f"  {d.get('model', 'unknown')}: "
            f"score={d.get('normalized', 0):.3f}"
            for d in model_details[:4]
        ])
    else:
        features_text = "  No model detail available."

    # Graph context
    graph = incident.get("graph_context", {})
    lateral = graph.get("lateral_movement_detected", False)
    pivot = graph.get("pivot_entity", "none identified")
    subgraph = graph.get("subgraph_size", 1)

    # Historical context
    if historical_context:
        hist_text = "\n".join([
            f"  - {h.get('pattern', 'unknown')} | "
            f"confidence: {h.get('confidence', 'unknown')} | "
            f"status: {h.get('status', 'unknown')}"
            for h in historical_context[:3]
        ])
    else:
        hist_text = "  No similar historical incidents found."

    prompt = f"""You are a senior SOC analyst at a major banking institution specializing in incident response for financial cybersecurity threats. You are methodical, precise, and always consider blast radius before recommending any action.

═══════════════════════════════════════════
HARD CONSTRAINTS — FOLLOW EXACTLY
═══════════════════════════════════════════

1. You may ONLY recommend actions from this exact list: [{permitted_text}]
2. You may NOT recommend any action not in the above list under any circumstance
3. ALL recommended actions require human approval before execution — never suggest autonomous execution
4. You must explain WHY each specific action targets each specific entity
5. If uncertain, recommend the LEAST disruptive action
6. This analysis was requested by: {requested_by}
7. Maximum 4 response steps — prioritize ruthlessly

═══════════════════════════════════════════
INCIDENT DATA
═══════════════════════════════════════════

Incident ID     : {incident.get('incident_id', 'unknown')}
Primary Entity  : {incident.get('primary_entity', 'unknown')}
Attack Pattern  : {incident.get('pattern', 'unknown')}
Attack Stage    : {incident.get('attack_stage', 'unknown')}
Severity        : {incident.get('severity', 'unknown')}
Duration        : {incident.get('duration_minutes', 0):.1f} minutes
Entities        : {', '.join(incident.get('entities', []))}

Fidelity Score  : {fidelity_output.get('fidelity_score', 0)} ({fidelity_output.get('confidence', 'unknown')} confidence)
Signal Stable   : {fidelity_output.get('is_stable', False)}
Windows Seen    : {fidelity_output.get('stability_window_count', 1)}

Score Breakdown:
{breakdown_text}

Model Anomaly Signals:
{features_text}

Graph Context:
  Lateral Movement : {lateral}
  Pivot Entity     : {pivot}
  Entities in Graph: {subgraph}

Attack Timeline (most recent 8 events):
{timeline_text}

═══════════════════════════════════════════
HISTORICAL CONTEXT
═══════════════════════════════════════════

{hist_text}

═══════════════════════════════════════════
REASONING INSTRUCTION
═══════════════════════════════════════════

Think through these five questions before writing your response:
1. What is the attacker most likely trying to accomplish?
2. Which single entity is the highest priority to contain right now?
3. What is the minimum response that stops the threat without disrupting banking operations?
4. What could go wrong if we act too aggressively?
5. What would confirm or deny this attack hypothesis?

═══════════════════════════════════════════
OUTPUT — RESPOND WITH ONLY THIS JSON
═══════════════════════════════════════════

No preamble. No explanation outside JSON. No markdown code blocks.
Respond with ONLY this exact JSON structure:

{{
  "reasoning_trace": "your step by step thinking answering the 5 questions above",
  "threat_narrative": "2-3 sentences explaining what is happening in plain analyst language referencing specific entities and actions",
  "attack_hypothesis": "your best hypothesis for attacker intent and most likely next move",
  "confidence_in_hypothesis": 0.85,
  "steps": [
    {{
      "step_number": 1,
      "action": "exact_action_from_permitted_list",
      "target_entity": "specific_entity_id",
      "reason": "specific reason this action on this entity right now",
      "requires_approval": true,
      "priority": "immediate"
    }}
  ],
  "what_not_to_do": "one sentence on what would be too aggressive and why",
  "monitoring_recommendation": "what to watch for in next 30 minutes to confirm or deny hypothesis"
}}"""

    return prompt


def build_correction_prompt(
    llm_output: str,
    parse_error: str
) -> str:
    """
    Sent to the LLM when its previous response failed JSON parsing.
    Includes the exact error so it understands what went wrong.
    """
    return f"""Your previous response failed JSON validation:

ERROR: {parse_error}

YOUR PREVIOUS RESPONSE (first 400 chars):
{llm_output[:400]}

Respond ONLY with valid JSON. No markdown. No preamble. No explanation.
Start your response with {{ and end with }}

Required structure:
{{
  "reasoning_trace": "string",
  "threat_narrative": "string",
  "attack_hypothesis": "string",
  "confidence_in_hypothesis": 0.0,
  "steps": [
    {{
      "step_number": 1,
      "action": "string",
      "target_entity": "string",
      "reason": "string",
      "requires_approval": true,
      "priority": "immediate"
    }}
  ],
  "what_not_to_do": "string",
  "monitoring_recommendation": "string"
}}"""