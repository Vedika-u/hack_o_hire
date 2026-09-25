# layer8_fidelity/fidelity_engine.py
"""
Layer 8: Fidelity Scoring Engine
Combines PyOD anomaly scores, Graph centrality & lateral movement,
Security posture signals, and Temporal dynamics into a single unified
belief strength score and stability assessment.
Writes FidelityOutput records conforming to Frozen Data Contract v1.1.0
to 'act_aware_fidelity'.
"""

from typing import List, Dict, Any, Optional
from datetime import datetime

from config.schemas import (
    CorrelatedIncident,
    DetectionOutput,
    FidelityOutput,
    ScoreBreakdown,
    ConfidenceLevel,
    utc_now,
)
from storage.es_client import es_client
from config.settings import settings
import logging

logger = logging.getLogger(__name__)


class FidelityScoringEngine:
    def __init__(self):
        self.es = es_client

    def evaluate_incident(
        self,
        incident: CorrelatedIncident,
        detections: List[DetectionOutput],
        stability_count: int = 2
    ) -> FidelityOutput:
        """
        Calculates weighted Fidelity Score:
          - Anomaly Component (40%)
          - Graph Component (30%)
          - Posture Component (20%)
          - Temporal Component (10%)
        """
        # 1. Anomaly Component (0.40)
        if detections:
            max_anomaly = max(d.anomaly_score for d in detections)
            avg_anomaly = sum(d.anomaly_score for d in detections) / len(detections)
            anomaly_comp = round(0.7 * max_anomaly + 0.3 * avg_anomaly, 4)
        else:
            anomaly_comp = 0.50

        # 2. Graph Component (0.30)
        graph_ctx = incident.graph_context
        graph_score = 0.20
        if graph_ctx.lateral_movement_detected:
            graph_score += 0.40
        if graph_ctx.subgraph_size >= 3:
            graph_score += 0.25
        if graph_ctx.centrality_scores:
            max_cent = max(graph_ctx.centrality_scores.values())
            graph_score += min(0.15, max_cent * 0.3)
        graph_comp = round(min(1.0, graph_score), 4)

        # 3. Posture Component (0.20)
        posture_score = 0.30
        if incident.pattern in ("data_exfiltration", "privilege_escalation"):
            posture_score += 0.50
        elif incident.pattern == "lateral_movement":
            posture_score += 0.40
        elif incident.pattern == "brute_force":
            posture_score += 0.30
        posture_comp = round(min(1.0, posture_score), 4)

        # 4. Temporal Component (0.10)
        # Higher duration / multi-step sequence implies persistent campaign, not transient spike
        dur = incident.duration_minutes
        temporal_score = 0.50
        if dur >= 5.0 or len(incident.timeline) >= 5:
            temporal_score = 0.85
        temporal_comp = round(temporal_score, 4)

        # Combine with weights
        weights = {"anomaly": 0.40, "graph": 0.30, "posture": 0.20, "temporal": 0.10}
        fidelity_score = round(
            (anomaly_comp * weights["anomaly"]) +
            (graph_comp * weights["graph"]) +
            (posture_comp * weights["posture"]) +
            (temporal_comp * weights["temporal"]),
            4
        )

        # Confidence Band: 0.50-0.74 = medium, 0.75-0.89 = high, 0.90+ = critical
        if fidelity_score >= 0.90:
            confidence: ConfidenceLevel = "critical"
        elif fidelity_score >= 0.75:
            confidence: ConfidenceLevel = "high"
        elif fidelity_score >= 0.50:
            confidence: ConfidenceLevel = "medium"
        else:
            confidence: ConfidenceLevel = "low"

        # Signal Stability
        # Persisted across consecutive observations or multi-stage progression
        is_stable = stability_count >= 2 or len(incident.timeline) >= 4 or incident.pattern in ("data_exfiltration", "lateral_movement")

        reasoning = {
            "justification": f"Fidelity score {fidelity_score} driven by anomaly ({anomaly_comp}) and graph lateral movement ({graph_comp}).",
            "anomaly_factor": anomaly_comp,
            "lateral_movement": graph_ctx.lateral_movement_detected,
            "subgraph_entities": graph_ctx.subgraph_size,
            "pattern": incident.pattern,
            "stability_windows": stability_count,
        }

        breakdown = ScoreBreakdown(
            anomaly_component=anomaly_comp,
            graph_component=graph_comp,
            posture_component=posture_comp,
            temporal_component=temporal_comp,
            weights=weights
        )

        output = FidelityOutput(
            pipeline_id=incident.pipeline_id,
            incident_id=incident.incident_id,
            evaluated_at=utc_now(),
            fidelity_score=fidelity_score,
            confidence=confidence,
            score_breakdown=breakdown,
            is_stable=is_stable,
            stability_window_count=stability_count,
            signal_trend="rising" if fidelity_score > 0.75 else "stable",
            reasoning=reasoning
        )

        # Store to act_aware_fidelity
        doc = output.model_dump()
        doc["evaluated_at"] = output.evaluated_at.isoformat()
        self.es.store_fidelity(output.fidelity_id, doc)
        logger.info(f"Computed Fidelity for incident {incident.incident_id}: Score={fidelity_score} ({confidence})")

        return output


fidelity_engine = FidelityScoringEngine()
