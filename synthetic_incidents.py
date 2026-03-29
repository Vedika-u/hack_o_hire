# tests/synthetic_incidents.py
# FIXED VERSION
# Changes:
# - raw_score now matches the model's actual output range
# - anomaly_score is the normalized version (0-1)
# - stability_count pushed into ES so stability tracker finds history

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from datetime import datetime, timezone, timedelta
from uuid import uuid4
from elasticsearch import Elasticsearch
from dotenv import load_dotenv

load_dotenv()


def utc_now():
    return datetime.now(timezone.utc)


def get_client():
    return Elasticsearch(
        f"http://{os.getenv('ES_HOST', 'localhost')}:"
        f"{os.getenv('ES_PORT', '9200')}",
        basic_auth=(
            os.getenv('ES_USERNAME', 'elastic'),
            os.getenv('ES_PASSWORD', 'actaware123')
        )
    )


def make_detection(entity_id, model, anomaly_score,
                   top_features, pipeline_id, behavior_id):
    """
    Creates a DetectionOutput document.
    
    raw_score is now correct per model:
    - isolation_forest: negative, more negative = more anomalous
    - lof: positive > 1, higher = more anomalous  
    - hbos: positive, higher = more anomalous
    
    anomaly_score is already normalized 0-1 (what scoring engine uses).
    """
    threshold = 0.65

    # Correct raw_score per model type
    if model == "isolation_forest":
        # Range typically -0.5 to 0.5
        # More anomalous = more negative
        raw_score = -1 * anomaly_score * 0.4
    elif model == "lof":
        # Range typically 1.0 to 10.0
        # More anomalous = higher
        raw_score = 1.0 + (anomaly_score * 9.0)
    else:  # hbos
        # Range typically 0 to 100
        raw_score = anomaly_score * 80.0

    return {
        "schema_version": "1.1.0",
        "pipeline_id": pipeline_id,
        "detection_id": str(uuid4()),
        "behavior_id": behavior_id,
        "entity_id": entity_id,
        "entity_type": "user",
        "window_start": (
            utc_now() - timedelta(minutes=10)
        ).isoformat(),
        "window_end": utc_now().isoformat(),
        "detected_at": utc_now().isoformat(),
        "model": model,
        "model_version": "1.0",
        "anomaly_score": anomaly_score,
        "raw_score": raw_score,
        "threshold_used": threshold,
        "score_margin": round(anomaly_score - threshold, 4),
        "label": "anomaly" if anomaly_score > threshold else "normal",
        "severity": (
            "critical" if anomaly_score > 0.90 else
            "high" if anomaly_score > 0.75 else
            "medium" if anomaly_score > 0.60 else "low"
        ),
        "features_used": {
            "login_fail_count": anomaly_score * 15,
            "login_attempt_velocity": anomaly_score * 8,
            "login_fail_ratio": anomaly_score * 0.9,
            "unique_hosts_accessed": anomaly_score * 5,
            "privilege_escalation_attempts": (
                int(anomaly_score * 3)
            ),
            "after_hours_activity": float(anomaly_score > 0.7),
            "data_transfer_rate": anomaly_score * 500,
            "db_rows_accessed": int(anomaly_score * 10000),
            "outbound_data_volume": anomaly_score * 1000,
            "suspicious_process_count": int(anomaly_score * 4),
            "sensitive_resource_access_count": int(
                anomaly_score * 5
            ),
            "admin_action_count": int(anomaly_score * 12),
            "event_rate_per_minute": anomaly_score * 20,
            "weekend_activity": float(anomaly_score > 0.85),
            "failed_privilege_actions": int(anomaly_score * 4)
        },
        "top_contributing_features": top_features
    }


def make_incident(entity_id, pattern, attack_stage, severity,
                  detection_ids, pipeline_id,
                  lateral_movement=False, centrality=0.3):
    start = utc_now() - timedelta(minutes=30)
    end = utc_now()

    return {
        "schema_version": "1.1.0",
        "pipeline_id": pipeline_id,
        "incident_id": str(uuid4()),
        "created_at": utc_now().isoformat(),
        "updated_at": utc_now().isoformat(),
        "entities": [entity_id, f"host_{entity_id}"],
        "entity_types": {
            entity_id: "user",
            f"host_{entity_id}": "host"
        },
        "primary_entity": entity_id,
        "detection_ids": detection_ids,
        "source_event_ids": [str(uuid4()) for _ in range(5)],
        "incident_start": start.isoformat(),
        "incident_end": end.isoformat(),
        "duration_minutes": 30.0,
        "timeline": [
            {
                "event_id": str(uuid4()),
                "timestamp": (
                    start + timedelta(minutes=i * 5)
                ).isoformat(),
                "entity_id": entity_id,
                "action": action,
                "resource": resource,
                "severity": severity
            }
            for i, (action, resource) in enumerate([
                ("failure", "/auth/login"),
                ("failure", "/auth/login"),
                ("success", "/auth/login"),
                ("read", "/api/accounts"),
                ("exec", "powershell.exe")
            ])
        ],
        "pattern": pattern,
        "attack_stage": attack_stage,
        "severity": severity,
        "graph_context": {
            "nodes": [
                {
                    "id": entity_id,
                    "type": "user",
                    "label": f"user:{entity_id}",
                    "risk_score": centrality
                },
                {
                    "id": f"host_{entity_id}",
                    "type": "host",
                    "label": f"host:ws-{entity_id}",
                    "risk_score": 0.4
                }
            ],
            "edges": [
                {
                    "source": entity_id,
                    "target": f"host_{entity_id}",
                    "weight": 0.8,
                    "relation": "accessed",
                    "timestamp": utc_now().isoformat(),
                    "event_id": str(uuid4())
                }
            ],
            # THIS IS THE KEY FIX:
            # centrality_scores must be a flat dict
            # entity_id (string) → score (float)
            "centrality_scores": {
                entity_id: centrality,
                f"host_{entity_id}": round(centrality * 0.6, 3)
            },
            "pivot_entity": (
                entity_id if centrality > 0.5 else None
            ),
            "lateral_movement_detected": lateral_movement,
            "subgraph_size": 2
        }
    }


def make_fidelity_history(incident_id, pipeline_id,
                          fidelity_score, window_count):
    """
    Creates fake historical fidelity records so the stability
    tracker sees multiple consecutive windows.
    Without this, every incident is is_stable=False.
    """
    records = []
    for i in range(window_count):
        records.append({
            "schema_version": "1.1.0",
            "pipeline_id": pipeline_id,
            "fidelity_id": str(uuid4()),
            "incident_id": incident_id,
            "evaluated_at": (
                utc_now() - timedelta(minutes=(window_count - i) * 5)
            ).isoformat(),
            "fidelity_score": round(
                fidelity_score - (0.02 * (window_count - i)), 4
            ),
            "confidence": (
                "critical" if fidelity_score > 0.90 else
                "high" if fidelity_score > 0.75 else
                "medium" if fidelity_score > 0.50 else "low"
            ),
            "is_stable": i >= 1,
            "stability_window_count": i + 1,
            "signal_trend": "rising",
            "score_breakdown": {
                "anomaly_component": fidelity_score * 0.9,
                "graph_component": fidelity_score * 0.95,
                "posture_component": fidelity_score * 0.85,
                "temporal_component": fidelity_score * 0.7,
                "weights": {
                    "anomaly": 0.40,
                    "graph": 0.30,
                    "posture": 0.20,
                    "temporal": 0.10
                }
            },
            "reasoning": {}
        })
    return records


ARCHETYPES = [
    {
        "name": "noise_incident",
        "entity_id": "user_noise_001",
        "pattern": "unknown",
        "attack_stage": "unknown",
        "severity": "low",
        "anomaly_scores": [0.35, 0.32, 0.38],
        "lateral_movement": False,
        "centrality": 0.05,
        "top_features": ["login_fail_count", "process_count"],
        "stability_windows": 1,
        "base_fidelity": 0.20,
        "expected_fidelity_range": (0.0, 0.50)
    },
    {
        "name": "brute_force",
        "entity_id": "user_brute_001",
        "pattern": "brute_force",
        "attack_stage": "initial_access",
        "severity": "medium",
        "anomaly_scores": [0.72, 0.68, 0.75],
        "lateral_movement": False,
        "centrality": 0.25,
        "top_features": [
            "login_fail_count",
            "login_attempt_velocity",
            "login_fail_ratio"
        ],
        "stability_windows": 2,
        "base_fidelity": 0.62,
        "expected_fidelity_range": (0.55, 0.75)
    },
    {
        "name": "lateral_movement",
        "entity_id": "user_lateral_001",
        "pattern": "lateral_movement",
        "attack_stage": "lateral_movement",
        "severity": "high",
        "anomaly_scores": [0.84, 0.81, 0.87],
        "lateral_movement": True,
        "centrality": 0.72,
        "top_features": [
            "unique_hosts_accessed",
            "privilege_escalation_attempts",
            "after_hours_activity",
            "suspicious_process_count"
        ],
        "stability_windows": 3,
        "base_fidelity": 0.80,
        "expected_fidelity_range": (0.75, 0.89)
    },
    {
        "name": "data_exfiltration",
        "entity_id": "user_exfil_001",
        "pattern": "data_exfiltration",
        "attack_stage": "exfiltration",
        "severity": "critical",
        "anomaly_scores": [0.93, 0.91, 0.95],
        "lateral_movement": True,
        "centrality": 0.88,
        "top_features": [
            "data_transfer_rate",
            "db_rows_accessed",
            "outbound_data_volume",
            "unique_file_extensions",
            "after_hours_activity"
        ],
        "stability_windows": 4,
        "base_fidelity": 0.92,
        "expected_fidelity_range": (0.90, 1.0)
    }
]


def clear_existing_test_data(client):
    """Removes previous synthetic test data to avoid stale results."""
    test_entities = [a["entity_id"] for a in ARCHETYPES]
    for index in [
        os.getenv('ES_INDEX_DETECTIONS', 'act_aware_detections'),
        os.getenv('ES_INDEX_INCIDENTS', 'act_aware_incidents'),
        os.getenv('ES_INDEX_FIDELITY', 'act_aware_fidelity')
    ]:
        try:
            client.delete_by_query(
                index=index,
                body={
                    "query": {
                        "terms": {
                            "entity_id": test_entities
                        }
                    }
                }
            )
        except Exception:
            pass

def make_events_for_incident(incident_id, entity_id, pattern, count=20):
    """Generate synthetic events for an incident."""
    events = []
    base_time = datetime.now(timezone.utc) - timedelta(hours=1)  # Within 1 hour for aggregation
    
    event_types = {
        "brute_force": ["login", "login", "login", "login"],
        "lateral_movement": ["login", "process", "network", "network"],
        "data_exfiltration": ["network", "file", "file", "database"],
        "noise_incident": ["login", "process", "file", "network"],
    }
    
    actions = {
        "brute_force": ["failure", "failure", "failure", "success"],
        "lateral_movement": ["success", "exec", "connect", "connect"],
        "data_exfiltration": ["read", "read", "connect", "exec"],
        "noise_incident": ["success", "exec", "read", "connect"],
    }
    
    types = event_types.get(pattern, ["login", "process", "network", "file"])
    acts = actions.get(pattern, ["exec", "success", "read", "connect"])
    
    for i in range(count):
        event_type = types[i % len(types)]
        action = acts[i % len(acts)]
        
        # Key fix: ensure timestamps are within same hour for aggregation
        event_time = base_time + timedelta(minutes=i * 2)
        
        event = {
            "schema_version": "1.1.0",
            "pipeline_id": str(uuid4()),
            "event_id": str(uuid4()),
            "timestamp": event_time.isoformat(),
            "ingested_at": datetime.now(timezone.utc).isoformat(),
            "source": "synthetic_test",
            "event_type": event_type,
            "severity": "medium" if pattern == "noise_incident" else "high",
            "user": entity_id,  # This must match the entity_id from archetype
            "host": f"host-{entity_id.split('_')[0]}",
            "ip": f"10.0.{i%255}.{(i*7)%255}",
            "destination_ip": f"192.168.{i%255}.{(i*11)%255}",
            "destination_port": 445 if event_type == "network" else None,
            "action": action,
            "resource": f"/sensitive/data_{i}.db" if pattern == "data_exfiltration" else f"/path/to/resource_{i}",
            "process_name": "mimikatz.exe" if pattern == "lateral_movement" else "cmd.exe",
            "outcome": "success" if action == "success" else "failure",
            "is_valid": True,
            "validation_errors": [],
            "metadata": {
                "original_timestamp": event_time.isoformat(),
                "timestamp_flags": [],
                "raw_message": f"Synthetic {event_type} event for {pattern}",
            }
        }
        events.append(event)
    
    return events
    
def generate_and_push():
    client = get_client()

    print("\nACT AWARE — Generating Synthetic Test Data")
    print("=" * 52)

    # Clear stale data first
    clear_existing_test_data(client)

    generated = []

    for archetype in ARCHETYPES:
        pipeline_id = str(uuid4())
        behavior_id = str(uuid4())

        # Create detections
        detection_ids = []
        for model, score in zip(
            ["isolation_forest", "lof", "hbos"],
            archetype["anomaly_scores"]
        ):
            detection = make_detection(
                entity_id=archetype["entity_id"],
                model=model,
                anomaly_score=score,
                top_features=archetype["top_features"],
                pipeline_id=pipeline_id,
                behavior_id=behavior_id
            )
            client.index(
                index=os.getenv(
                    'ES_INDEX_DETECTIONS',
                    'act_aware_detections'
                ),
                id=detection["detection_id"],
                document=detection,
                refresh=True
            )
            detection_ids.append(detection["detection_id"])

        # Create events for this incident
        events = make_events_for_incident(
            incident_id=str(uuid4()),  # will use actual incident_id after creation
            entity_id=archetype["entity_id"],
            pattern=archetype["pattern"],
            count=archetype["stability_windows"] * 10
        )
        for event in events:
            client.index(
                index=os.getenv('ES_INDEX_EVENTS', 'act_aware_events'),
                id=event["event_id"],
                document=event,
                refresh=False  # We'll refresh all at once at the end
            )    

        # Create incident
        incident = make_incident(
            entity_id=archetype["entity_id"],
            pattern=archetype["pattern"],
            attack_stage=archetype["attack_stage"],
            severity=archetype["severity"],
            detection_ids=detection_ids,
            pipeline_id=pipeline_id,
            lateral_movement=archetype["lateral_movement"],
            centrality=archetype["centrality"]
        )
        client.index(
            index=os.getenv(
                'ES_INDEX_INCIDENTS',
                'act_aware_incidents'
            ),
            id=incident["incident_id"],
            document=incident,
            refresh=True
        )

        # Create fidelity history so stability tracker
        # sees multiple windows
        fidelity_history = make_fidelity_history(
            incident_id=incident["incident_id"],
            pipeline_id=pipeline_id,
            fidelity_score=archetype["base_fidelity"],
            window_count=archetype["stability_windows"]
        )
        for record in fidelity_history:
            client.index(
                index=os.getenv(
                    'ES_INDEX_FIDELITY',
                    'act_aware_fidelity'
                ),
                id=record["fidelity_id"],
                document=record,
                refresh=True
            )

        generated.append({
            "archetype": archetype["name"],
            "pipeline_id": pipeline_id,
            "incident_id": incident["incident_id"],
            "expected_fidelity": archetype["expected_fidelity_range"],
            "stability_windows": archetype["stability_windows"]
        })

        print(f"\n  ✓ {archetype['name']}")
        print(f"    incident_id  : {incident['incident_id']}")
        print(
            f"    expected     : "
            f"{archetype['expected_fidelity_range']}"
        )
        print(
            f"    stab windows : "
            f"{archetype['stability_windows']}"
        )

        print("\n" + "=" * 52)
    print(f"Generated {len(generated)} incidents with history.")
    print("Ready for fidelity scoring.\n")
    
    # Final refresh to ensure all data is immediately searchable
    try:
        client.indices.refresh(
            index=os.getenv('ES_INDEX_DETECTIONS', 'act_aware_detections')
        )
        client.indices.refresh(
            index=os.getenv('ES_INDEX_INCIDENTS', 'act_aware_incidents')
        )
        client.indices.refresh(
            index=os.getenv('ES_INDEX_FIDELITY', 'act_aware_fidelity')
        )
        client.indices.refresh(
            index=os.getenv('ES_INDEX_EVENTS', 'act_aware_events')
        )
    except Exception as e:
        print(f"Warning: Could not refresh indices: {e}")
    
    return generated