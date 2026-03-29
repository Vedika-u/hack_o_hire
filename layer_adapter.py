# integration/layer_adapter.py
# Reads real data from upstream layers and normalizes it
# into the exact schema your fidelity engine expects.
#
# WHY THIS EXISTS:
# Each team member built their layer independently.
# Field names will be slightly different.
# Some fields will be missing.
# Timestamps may not be timezone-aware.
# pipeline_id may not have been propagated.
#
# This adapter is the boundary between "what they produce"
# and "what your engine needs."
# Fix it here. Never touch the scoring engine for integration issues.

import os
import sys
sys.path.append(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)

from datetime import datetime, timezone
from typing import Optional, List
from uuid import uuid4
from elasticsearch import Elasticsearch
from loguru import logger
from dotenv import load_dotenv

load_dotenv()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def ensure_timezone(ts: Optional[str]) -> Optional[str]:
    """
    Makes any timestamp string timezone-aware UTC.
    Handles:
    - Already correct: "2026-03-24T19:17:32+00:00"
    - Missing Z: "2026-03-24T19:17:32"
    - With Z: "2026-03-24T19:17:32Z"
    - None: returns current UTC time
    """
    if ts is None:
        return utc_now()
    try:
        # Already has timezone info
        if "+" in ts or ts.endswith("Z"):
            ts_clean = ts.replace("Z", "+00:00")
            datetime.fromisoformat(ts_clean)
            return ts_clean
        # Naive datetime — assume UTC
        dt = datetime.fromisoformat(ts)
        return dt.replace(tzinfo=timezone.utc).isoformat()
    except Exception:
        return utc_now()


def normalize_severity(raw: Optional[str]) -> str:
    """Maps any severity string to your schema's Literal."""
    mapping = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "info": "low",
        "informational": "low",
        "warning": "medium",
        "warn": "medium",
        "severe": "critical",
        "3": "critical",
        "2": "high",
        "1": "medium",
        "0": "low"
    }
    return mapping.get(str(raw).lower(), "low")


def normalize_pattern(raw: Optional[str]) -> str:
    """Maps any attack pattern string to your schema's Literal."""
    valid = {
        "lateral_movement", "brute_force",
        "data_exfiltration", "privilege_escalation",
        "insider_threat", "api_abuse",
        "ransomware", "unknown"
    }
    if raw and raw.lower() in valid:
        return raw.lower()
    # Try to map common variations
    mapping = {
        "lateral": "lateral_movement",
        "brute": "brute_force",
        "exfil": "data_exfiltration",
        "exfiltration": "data_exfiltration",
        "privilege": "privilege_escalation",
        "privesc": "privilege_escalation",
        "insider": "insider_threat",
        "api": "api_abuse",
        "ransom": "ransomware"
    }
    for key, val in mapping.items():
        if raw and key in raw.lower():
            return val
    return "unknown"


def normalize_attack_stage(raw: Optional[str]) -> str:
    """Maps any attack stage to your schema's Literal."""
    valid = {
        "reconnaissance", "initial_access", "execution",
        "persistence", "privilege_escalation",
        "lateral_movement", "collection",
        "exfiltration", "unknown"
    }
    if raw and raw.lower() in valid:
        return raw.lower()
    return "unknown"


class LayerAdapter:
    """
    Reads upstream layer data from Elasticsearch and adapts
    it to the exact format your fidelity engine expects.

    Use this instead of reading directly from ES in your engine
    until all layers are producing perfectly formatted data.
    After full integration is stable, this adapter can be removed.
    """

    def __init__(self, es_client: Elasticsearch):
        self.es = es_client

    def get_incidents_for_scoring(
        self,
        limit: int = 50,
        only_unscored: bool = True
    ) -> List[dict]:
        """
        Fetches incidents from act_aware_incidents that
        have not yet been scored by the fidelity engine.

        Returns a list of normalized incident dicts
        ready for FidelityScoringEngine.score_incident()
        """
        query = {"match_all": {}}

        if only_unscored:
            # Find incidents with no fidelity record yet
            # by checking act_aware_fidelity for incident_ids
            try:
                scored_result = self.es.search(
                    index=os.getenv(
                        'ES_INDEX_FIDELITY',
                        'act_aware_fidelity'
                    ),
                    body={
                        "size": 0,
                        "aggs": {
                            "scored_ids": {
                                "terms": {
                                    "field": "incident_id",
                                    "size": 10000
                                }
                            }
                        }
                    }
                )
                scored_ids = [
                    b['key'] for b in
                    scored_result['aggregations']
                    ['scored_ids']['buckets']
                ]

                if scored_ids:
                    query = {
                        "bool": {
                            "must_not": [
                                {
                                    "ids": {
                                        "values": scored_ids
                                    }
                                }
                            ]
                        }
                    }
            except Exception as e:
                logger.warning(
                    f"Could not filter scored incidents: {e}. "
                    f"Returning all incidents."
                )

        try:
            result = self.es.search(
                index=os.getenv(
                    'ES_INDEX_INCIDENTS',
                    'act_aware_incidents'
                ),
                body={
                    "query": query,
                    "sort": [
                        {"created_at": {"order": "desc"}}
                    ],
                    "size": limit
                }
            )

            incidents = []
            for hit in result['hits']['hits']:
                raw = hit['_source']
                adapted = self._adapt_incident(
                    raw, hit['_id']
                )
                if adapted:
                    incidents.append(adapted)

            logger.info(
                f"LayerAdapter: fetched {len(incidents)} "
                f"unscored incidents"
            )
            return incidents

        except Exception as e:
            logger.error(
                f"LayerAdapter: could not fetch incidents: {e}"
            )
            return []

    def _adapt_incident(
        self,
        raw: dict,
        doc_id: str
    ) -> Optional[dict]:
        """
        Normalizes a raw incident document from any upstream
        format into the CorrelatedIncident schema your engine
        expects.

        Handles missing fields with safe defaults.
        Fixes timestamp formats.
        Ensures pipeline_id exists.
        """
        try:
            # Ensure incident_id
            incident_id = (
                raw.get("incident_id") or
                raw.get("id") or
                raw.get("_id") or
                doc_id
            )

            # Ensure pipeline_id — generate if missing
            pipeline_id = (
                raw.get("pipeline_id") or
                raw.get("pipeline") or
                str(uuid4())
            )

            # Normalize entities
            entities = raw.get("entities", [])
            if isinstance(entities, str):
                entities = [entities]

            entity_types = raw.get("entity_types", {})
            if not entity_types and entities:
                entity_types = {e: "user" for e in entities}

            primary_entity = (
                raw.get("primary_entity") or
                raw.get("source_entity") or
                (entities[0] if entities else "unknown")
            )

            # Normalize detection_ids
            detection_ids = (
                raw.get("detection_ids") or
                raw.get("alert_ids") or
                raw.get("detection_id") or
                []
            )
            if isinstance(detection_ids, str):
                detection_ids = [detection_ids]

            # Normalize timeline
            timeline = raw.get("timeline", [])
            normalized_timeline = []
            for event in timeline:
                normalized_timeline.append({
                    "event_id": (
                        event.get("event_id") or
                        str(uuid4())
                    ),
                    "timestamp": ensure_timezone(
                        event.get("timestamp") or
                        event.get("time")
                    ),
                    "entity_id": (
                        event.get("entity_id") or
                        event.get("user") or
                        primary_entity
                    ),
                    "action": (
                        event.get("action") or
                        event.get("event_type") or
                        "exec"
                    ),
                    "resource": event.get(
                        "resource") or event.get("target"),
                    "severity": normalize_severity(
                        event.get("severity")
                    )
                })

            # Normalize graph_context
            graph = raw.get("graph_context", {})
            if not graph:
                graph = raw.get("graph", {})

            centrality = graph.get("centrality_scores", {})
            if not isinstance(centrality, dict):
                centrality = {}

            normalized_graph = {
                "nodes": graph.get("nodes", []),
                "edges": graph.get("edges", []),
                "centrality_scores": centrality,
                "pivot_entity": graph.get("pivot_entity"),
                "lateral_movement_detected": (
                    graph.get("lateral_movement_detected") or
                    graph.get("lateral_movement") or
                    False
                ),
                "subgraph_size": (
                    graph.get("subgraph_size") or
                    len(entities)
                )
            }

            # Normalize timestamps
            incident_start = ensure_timezone(
                raw.get("incident_start") or
                raw.get("start_time") or
                raw.get("first_seen")
            )
            incident_end = ensure_timezone(
                raw.get("incident_end") or
                raw.get("end_time") or
                raw.get("last_seen")
            )

            # Duration
            duration = raw.get("duration_minutes", 0.0)
            if not duration:
                try:
                    start_dt = datetime.fromisoformat(
                        incident_start.replace("Z", "+00:00")
                    )
                    end_dt = datetime.fromisoformat(
                        incident_end.replace("Z", "+00:00")
                    )
                    duration = (
                        end_dt - start_dt
                    ).total_seconds() / 60
                except Exception:
                    duration = 0.0

            adapted = {
                "schema_version": "1.1.0",
                "pipeline_id": pipeline_id,
                "incident_id": incident_id,
                "created_at": ensure_timezone(
                    raw.get("created_at")
                ),
                "updated_at": ensure_timezone(
                    raw.get("updated_at")
                ),
                "entities": entities,
                "entity_types": entity_types,
                "primary_entity": primary_entity,
                "detection_ids": detection_ids,
                "source_event_ids": raw.get(
                    "source_event_ids", []
                ),
                "incident_start": incident_start,
                "incident_end": incident_end,
                "duration_minutes": round(duration, 2),
                "timeline": normalized_timeline,
                "pattern": normalize_pattern(
                    raw.get("pattern") or
                    raw.get("attack_pattern") or
                    raw.get("type")
                ),
                "attack_stage": normalize_attack_stage(
                    raw.get("attack_stage") or
                    raw.get("stage") or
                    raw.get("mitre_stage")
                ),
                "severity": normalize_severity(
                    raw.get("severity") or
                    raw.get("risk_level")
                ),
                "graph_context": normalized_graph
            }

            return adapted

        except Exception as e:
            logger.error(
                f"LayerAdapter: could not adapt incident "
                f"{doc_id}: {e}"
            )
            return None

    def get_detections_for_incident(
        self,
        incident: dict
    ) -> List[dict]:
        """
        Fetches and normalizes detection records for an incident.
        Handles upstream detection formats that differ from schema.
        """
        detection_ids = incident.get("detection_ids", [])
        if not detection_ids:
            logger.warning(
                f"No detection_ids in incident "
                f"{incident.get('incident_id')}. "
                f"Querying by entity_id instead."
            )
            # Fallback: query by entity_id and time window
            return self._fetch_detections_by_entity(incident)

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
            raw_detections = [
                h['_source']
                for h in result['hits']['hits']
            ]
            return [
                self._adapt_detection(d)
                for d in raw_detections
                if d
            ]

        except Exception as e:
            logger.error(
                f"Could not fetch detections: {e}"
            )
            return []

    def _fetch_detections_by_entity(
        self,
        incident: dict
    ) -> List[dict]:
        """
        Fallback detection fetch when detection_ids are missing.
        Queries by entity_id within the incident time window.
        """
        entity_id = incident.get("primary_entity", "")
        if not entity_id:
            return []

        try:
            result = self.es.search(
                index=os.getenv(
                    'ES_INDEX_DETECTIONS',
                    'act_aware_detections'
                ),
                body={
                    "query": {
                        "bool": {
                            "must": [
                                {
                                    "term": {
                                        "entity_id": entity_id
                                    }
                                },
                                {
                                    "range": {
                                        "detected_at": {
                                            "gte": incident.get(
                                                "incident_start",
                                                "now-1h"
                                            ),
                                            "lte": incident.get(
                                                "incident_end",
                                                "now"
                                            )
                                        }
                                    }
                                }
                            ]
                        }
                    },
                    "size": 20
                }
            )
            raw = [
                h['_source']
                for h in result['hits']['hits']
            ]
            return [self._adapt_detection(d) for d in raw]

        except Exception as e:
            logger.error(
                f"Entity-based detection fallback failed: {e}"
            )
            return []

    def _adapt_detection(self, raw: dict) -> dict:
        """
        Normalizes a raw detection document into the
        DetectionOutput schema your scoring engine expects.
        """
        anomaly_score = float(
            raw.get("anomaly_score") or
            raw.get("score") or
            raw.get("anomaly") or
            0.5
        )
        threshold = float(
            raw.get("threshold_used") or
            raw.get("threshold") or
            0.65
        )
        raw_score = float(
            raw.get("raw_score") or
            raw.get("decision_score") or
            anomaly_score
        )

        # Normalize model name
        model_raw = str(
            raw.get("model") or
            raw.get("algorithm") or
            raw.get("detector") or
            "isolation_forest"
        ).lower()

        if "lof" in model_raw or "local" in model_raw:
            model = "lof"
        elif "hbos" in model_raw or "histogram" in model_raw:
            model = "hbos"
        else:
            model = "isolation_forest"

        # Top features
        top_features = (
            raw.get("top_contributing_features") or
            raw.get("top_features") or
            raw.get("important_features") or
            []
        )
        if isinstance(top_features, str):
            top_features = [top_features]

        # Features used
        features_used = (
            raw.get("features_used") or
            raw.get("features") or
            raw.get("feature_values") or
            {}
        )

        return {
            "schema_version": "1.1.0",
            "pipeline_id": (
                raw.get("pipeline_id") or str(uuid4())
            ),
            "detection_id": (
                raw.get("detection_id") or
                raw.get("id") or
                str(uuid4())
            ),
            "behavior_id": (
                raw.get("behavior_id") or str(uuid4())
            ),
            "entity_id": (
                raw.get("entity_id") or
                raw.get("user") or
                raw.get("source") or
                "unknown"
            ),
            "entity_type": (
                raw.get("entity_type") or "user"
            ),
            "window_start": ensure_timezone(
                raw.get("window_start") or
                raw.get("start_time")
            ),
            "window_end": ensure_timezone(
                raw.get("window_end") or
                raw.get("end_time")
            ),
            "detected_at": ensure_timezone(
                raw.get("detected_at") or
                raw.get("timestamp")
            ),
            "model": model,
            "model_version": raw.get(
                "model_version", "1.0"
            ),
            "anomaly_score": min(1.0, max(0.0, anomaly_score)),
            "raw_score": raw_score,
            "threshold_used": threshold,
            "score_margin": round(
                anomaly_score - threshold, 4
            ),
            "label": (
                "anomaly" if anomaly_score > threshold
                else "normal"
            ),
            "severity": normalize_severity(
                raw.get("severity")
            ),
            "features_used": features_used,
            "top_contributing_features": top_features[:5]
        }

    def check_index_health(self) -> dict:
        """
        Reports what data exists in each upstream index.
        Run this to understand the current integration state.
        """
        health = {}
        indices = {
            "events": os.getenv(
                'ES_INDEX_EVENTS', 'act_aware_events'
            ),
            "behaviors": os.getenv(
                'ES_INDEX_BEHAVIORS', 'act_aware_behaviors'
            ),
            "detections": os.getenv(
                'ES_INDEX_DETECTIONS', 'act_aware_detections'
            ),
            "incidents": os.getenv(
                'ES_INDEX_INCIDENTS', 'act_aware_incidents'
            ),
            "fidelity": os.getenv(
                'ES_INDEX_FIDELITY', 'act_aware_fidelity'
            ),
            "playbooks": os.getenv(
                'ES_INDEX_PLAYBOOKS', 'act_aware_playbooks'
            ),
            "provenance": "act_aware_provenance"
        }

        for name, index in indices.items():
            try:
                result = self.es.count(index=index)
                health[name] = {
                    "index": index,
                    "count": result["count"],
                    "status": "ok"
                }
            except Exception as e:
                health[name] = {
                    "index": index,
                    "count": 0,
                    "status": f"error: {e}"
                }

        return health