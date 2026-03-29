# fidelity/confidence_bands.py
# Maps fidelity scores to confidence bands and permitted SOAR actions.
# This is policy logic, not math.
# Change these thresholds to tune system sensitivity.

from typing import List, Literal

SOARAction = Literal[
    "block_ip", "disable_account", "isolate_endpoint",
    "force_logout", "revoke_token", "alert_analyst",
    "increase_monitoring", "quarantine_file"
]


# The complete policy definition.
# Each band defines:
#   min_score: lower bound (inclusive)
#   max_score: upper bound (exclusive, except 1.0)
#   confidence: human-readable label
#   llm_eligible: whether this band can trigger LLM reasoning
#   permitted_actions: what SOAR actions are allowed at this band
#   requires_escalation: whether mandatory human escalation applies

CONFIDENCE_BANDS = [
    {
        "min_score": 0.0,
        "max_score": 0.50,
        "confidence": "low",
        "llm_eligible": False,
        "permitted_actions": [],
        "requires_escalation": False,
        "description": "Noise or very weak signal. Log and monitor only."
    },
    {
        "min_score": 0.50,
        "max_score": 0.75,
        "confidence": "medium",
        "llm_eligible": False,
        "permitted_actions": ["alert_analyst", "increase_monitoring"],
        "requires_escalation": False,
        "description": "Possible threat. Alert analyst, increase monitoring. "
                       "No automated actions."
    },
    {
        "min_score": 0.75,
        "max_score": 0.90,
        "confidence": "high",
        "llm_eligible": True,
        "permitted_actions": [
            "alert_analyst",
            "increase_monitoring",
            "force_logout",
            "revoke_token"
        ],
        "requires_escalation": False,
        "description": "Likely threat. LLM playbook generation permitted "
                       "on human request. Advisory actions only."
    },
    {
        "min_score": 0.90,
        "max_score": 1.01,
        "confidence": "critical",
        "llm_eligible": True,
        "permitted_actions": [
            "block_ip",
            "disable_account",
            "isolate_endpoint",
            "force_logout",
            "revoke_token",
            "alert_analyst",
            "increase_monitoring",
            "quarantine_file"
        ],
        "requires_escalation": True,
        "description": "High-confidence threat. Full SOAR action suite permitted. "
                       "Mandatory human escalation before execution."
    }
]


def get_confidence_band(fidelity_score: float) -> dict:
    """
    Returns the full band definition for a given fidelity score.
    """
    for band in CONFIDENCE_BANDS:
        if band["min_score"] <= fidelity_score < band["max_score"]:
            return band
    # Fallback — should never reach here with valid 0-1 score
    return CONFIDENCE_BANDS[0]


def get_confidence_label(fidelity_score: float) -> str:
    return get_confidence_band(fidelity_score)["confidence"]


def get_permitted_actions(fidelity_score: float) -> List[str]:
    return get_confidence_band(fidelity_score)["permitted_actions"]


def is_llm_eligible(
    fidelity_score: float,
    is_stable: bool
) -> bool:
    """
    LLM reasoning is ONLY eligible when:
    1. Score is in a band that permits it (≥ 0.75)
    2. Signal is stable (appeared in multiple windows)

    Both conditions must be true. Either alone is not enough.
    """
    band = get_confidence_band(fidelity_score)
    return band["llm_eligible"] 


def requires_escalation(fidelity_score: float) -> bool:
    return get_confidence_band(fidelity_score)["requires_escalation"]