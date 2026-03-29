# fidelity/scoring_engine.py
# FIXED VERSION
# Fix 1: passes anomaly_score to normalizer.normalize()
# Fix 2: graph component reads centrality_scores correctly
# Fix 3: cold start no longer applies 0.7 penalty at component level

import os
import sys
sys.path.append(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)

from datetime import datetime, timezone
from typing import Optional
from uuid import uuid4
from elasticsearch import Elasticsearch
from dotenv import load_dotenv
from loguru import logger

from fidelity.normalizer import ScoreNormalizer
from fidelity.stability_tracker import StabilityTracker
from fidelity.confidence_bands import (
    get_confidence_label,
    get_permitted_actions,
    is_llm_eligible,
    requires_escalation
)

load_dotenv()


def utc_now():
    return datetime.now(timezone.utc)


class FidelityScoringEngine:
    """
    Combines anomaly scores, graph signals, posture signals,
    and temporal signals into one calibrated fidelity score.

    Weights (banking context):
    anomaly  0.40 — ML model outputs
    graph    0.30 — lateral movement and centrality
    posture  0.20 — privilege misuse, behavioral drift
    temporal 0.10 — after-hours, weekend, velocity
    """

    DEFAULT_WEIGHTS = {
        "anomaly": 0.40,
        "graph": 0.30,
        "posture": 0.20,
        "temporal": 0.10
    }

    def __init__(
        self,
        es_client: Elasticsearch,
        weights: Optional[dict] = None
    ):
        self.es = es_client
        self.weights = weights or self.DEFAULT_WEIGHTS
        self.normalizer = ScoreNormalizer(es_client)
        self.stability = StabilityTracker(es_client)

        total = sum(self.weights.values())
        if abs(total - 1.0) > 0.001:
            raise ValueError(
                f"Weights must sum to 1.0. Got {total:.4f}."
            )

        logger.info(
            f"FidelityScoringEngine initialized with "
            f"weights: {self.weights}"
        )

    def _fetch_incident(
        self, incident_id: str
    ) -> Optional[dict]:
        try:
            result = self.es.get(
                index=os.getenv(
                    'ES_INDEX_INCIDENTS',
                    'act_aware_incidents'
                ),
                id=incident_id
            )
            return result['_source']
        except Exception as e:
            logger.error(
                f"Could not fetch incident {incident_id}: {e}"
            )
            return None

    def _fetch_detections(
        self, incident: dict
    ) -> list:
        detection_ids = incident.get("detection_ids", [])
        if not detection_ids:
            return []

        try:
            result = self.es.search(
                index=os.getenv(
                    'ES_INDEX_DETECTIONS',
                    'act_aware_detections'
                ),
                body={
                    "query": {
                        "ids": {"values": detection_ids}
                    },
                    "size": 50
                }
            )
            return [h['_source'] for h in result['hits']['hits']]
        except Exception as e:
            logger.error(f"Could not fetch detections: {e}")
            return []
    def _compute_anomaly_component(
        self, detections: list
    ) -> dict:
        """
        FIXED: passes anomaly_score to normalizer
        so cold start returns the correct value
        instead of collapsing to zero.
        """

        if not detections:
            return {
                "score": 0.0,
                "detail": [{"message": "no_detections"}]
            }

        weighted_scores = []
        detail = []

        for det in detections:
            # FIXED: pass anomaly_score as fallback
            norm_result = self.normalizer.normalize(
                raw_score=det.get("raw_score", 0.0),
                model=det["model"],
                anomaly_score=det.get("anomaly_score", 0.0)
            )

            normalized = norm_result["normalized_score"]

            # Margin above threshold = confidence in this signal
            margin = det.get("score_margin", 0.0)
            margin_weight = 1.0 + max(0.0, margin)

            weighted_scores.append(normalized * margin_weight)
            detail.append({
                "model": det["model"],
                "normalized": normalized,
                "cold_start": norm_result["cold_start"],
                "margin": round(margin, 3),
                "source": norm_result.get("source")
            })

        total_weight = sum(
            1.0 + max(0.0, d.get("score_margin", 0.0))
            for d in detections
        )

        component_score = (
            sum(weighted_scores) / total_weight
            if total_weight > 0 else 0.0
        )

        return {
            "score": round(min(1.0, component_score), 4),
            "model_count": len(detections),
            "detail": detail
        }

    def _compute_graph_component(
        self, incident: dict
    ) -> dict:
        """
        FIXED: reads centrality_scores as a flat dict correctly.
        Handles both dict and nested object formats from ES.
        """
        graph = incident.get("graph_context", {})

        # centrality_scores is a flat dict: {entity_id: float}
        centrality_scores = graph.get("centrality_scores", {})

        # Handle case where ES returns it differently
        if isinstance(centrality_scores, list):
            # Should not happen but guard against it
            max_centrality = 0.0
        elif isinstance(centrality_scores, dict):
            if centrality_scores:
                max_centrality = max(centrality_scores.values())
            else:
                max_centrality = 0.0
        else:
            max_centrality = 0.0

        # Lateral movement is a strong signal
        lateral = graph.get("lateral_movement_detected", False)
        lateral_bonus = 0.30 if lateral else 0.0

        # Subgraph size — more entities = higher risk
        subgraph_size = graph.get("subgraph_size", 1)
        size_score = min(0.20, (subgraph_size - 1) * 0.025)

        # Pivot entity identified = confirmed attack chain
        pivot_bonus = 0.05 if graph.get("pivot_entity") else 0.0

        raw_score = (
            max_centrality + lateral_bonus +
            size_score + pivot_bonus
        )
        component_score = min(1.0, raw_score)

        return {
            "score": round(component_score, 4),
            "max_centrality": round(max_centrality, 4),
            "lateral_movement": lateral,
            "subgraph_size": subgraph_size,
            "lateral_bonus": lateral_bonus,
            "size_score": round(size_score, 4),
            "pivot_bonus": pivot_bonus
        }

    def _compute_posture_component(
        self,
        detections: list,
        incident: dict
    ) -> dict:
        posture_signals = []

        for det in detections:
            features = det.get("features_used", {})
            top = det.get("top_contributing_features", [])

            if features.get(
                "privilege_escalation_attempts", 0
            ) > 0:
                posture_signals.append(0.8)

            if features.get("admin_action_count", 0) > 10:
                posture_signals.append(0.6)

            if features.get(
                "failed_privilege_actions", 0
            ) > 3:
                posture_signals.append(0.5)

            if features.get(
                "sensitive_resource_access_count", 0
            ) > 2:
                posture_signals.append(0.7)

            posture_features = {
                "privilege_escalation_attempts",
                "admin_action_count",
                "sensitive_resource_access_count",
                "failed_privilege_actions"
            }
            overlap = posture_features.intersection(set(top))
            if overlap:
                posture_signals.append(0.4 * len(overlap))

        pattern = incident.get("pattern", "unknown")
        if pattern in ["insider_threat", "privilege_escalation"]:
            posture_signals.append(0.9)
        elif pattern in [
            "lateral_movement", "data_exfiltration"
        ]:
            posture_signals.append(0.6)
        elif pattern == "brute_force":
            posture_signals.append(0.4)

        if not posture_signals:
            return {"score": 0.1, "signals_found": 0}

        component_score = min(1.0, max(posture_signals))
        return {
            "score": round(component_score, 4),
            "signals_found": len(posture_signals),
            "max_signal": round(max(posture_signals), 4)
        }

    def _compute_temporal_component(
        self,
        detections: list,
        incident: dict
    ) -> dict:
        temporal_signals = []

        for det in detections:
            features = det.get("features_used", {})

            if features.get("after_hours_activity", False):
                temporal_signals.append(0.7)

            if features.get("weekend_activity", False):
                temporal_signals.append(0.6)

            rate = features.get("event_rate_per_minute", 0.0)
            if rate > 10:
                temporal_signals.append(
                    min(0.8, rate / 20)
                )

            velocity = features.get(
                "login_attempt_velocity", 0.0
            )
            if velocity > 5:
                temporal_signals.append(
                    min(0.7, velocity / 10)
                )

        if not temporal_signals:
            return {"score": 0.1, "signals_found": 0}

        return {
            "score": round(
                min(1.0, max(temporal_signals)), 4
            ),
            "signals_found": len(temporal_signals)
        }

    def score_incident(
        self, incident_id: str
    ) -> Optional[dict]:
        logger.info(f"Scoring incident: {incident_id}")

        incident = self._fetch_incident(incident_id)
        if not incident:
            logger.error(f"Incident not found: {incident_id}")
            return None

        detections = self._fetch_detections(incident)
        pipeline_id = incident.get("pipeline_id", str(uuid4()))

        # Compute all four components
        anomaly_comp = self._compute_anomaly_component(
            detections
        )
        graph_comp = self._compute_graph_component(incident)
        posture_comp = self._compute_posture_component(
            detections, incident
        )
        temporal_comp = self._compute_temporal_component(
            detections, incident
        )

        # Weighted combination
        fidelity_score = (
            self.weights["anomaly"] * anomaly_comp["score"] +
            self.weights["graph"] * graph_comp["score"] +
            self.weights["posture"] * posture_comp["score"] +
            self.weights["temporal"] * temporal_comp["score"]
        )
        fidelity_score = round(
            min(1.0, max(0.0, fidelity_score)), 4
        )

        # Stability
        stability = self.stability.get_stability(incident_id)

        # Confidence band
        confidence = get_confidence_label(fidelity_score)
        permitted = get_permitted_actions(fidelity_score)
        llm_eligible = is_llm_eligible(
            fidelity_score, stability["is_stable"]
        )
        escalation = requires_escalation(fidelity_score)

        fidelity_id = str(uuid4())
        fidelity_output = {
            "schema_version": "1.1.0",
            "pipeline_id": pipeline_id,
            "fidelity_id": fidelity_id,
            "incident_id": incident_id,
            "evaluated_at": utc_now().isoformat(),
            "fidelity_score": fidelity_score,
            "confidence": confidence,
            "score_breakdown": {
                "anomaly_component": anomaly_comp["score"],
                "graph_component": graph_comp["score"],
                "posture_component": posture_comp["score"],
                "temporal_component": temporal_comp["score"],
                "weights": self.weights
            },
            "is_stable": stability["is_stable"],
            "stability_window_count": (
                stability["stability_window_count"]
            ),
            "signal_trend": stability["signal_trend"],
            "llm_eligible": llm_eligible,
            "permitted_actions": permitted,
            "requires_escalation": escalation,
            "reasoning": {
                "anomaly_detail": anomaly_comp,
                "graph_detail": graph_comp,
                "posture_detail": posture_comp,
                "temporal_detail": temporal_comp,
                "stability_detail": stability
            }
        }

        # Write to Elasticsearch
        self.es.index(
            index=os.getenv(
                'ES_INDEX_FIDELITY', 'act_aware_fidelity'
            ),
            id=fidelity_id,
            document=fidelity_output,
            refresh=True
        )

        logger.info(
            f"Incident {incident_id} scored: "
            f"{fidelity_score} ({confidence}) "
            f"stable={stability['is_stable']} "
            f"llm_eligible={llm_eligible}"
        )

        return fidelity_output