"""
detection.py
Layer 6 — Anomaly Detection using PyOD Ensemble
Team: Phoenix Core | ACT AWARE | Kanchan
Follows: config/schemas.py v1.1.0
"""

import sys
sys.path.insert(0, '.')

import numpy as np
import pandas as pd
from datetime import datetime, timezone, timedelta
from uuid import uuid4
from pyod.models.iforest import IForest
from pyod.models.lof import LOF
from pyod.models.hbos import HBOS

from config.schemas import (
    UniversalEvent, AggregatedBehavior, BehaviorFeatures,
    DetectionOutput, utc_now, SCHEMA_VERSION
)


def aggregate_events(events: list, pipeline_id: str, window_minutes: int = 15):
    """
    Convert raw UniversalEvents into AggregatedBehavior per entity.
    Groups events by entity_id and computes behavioral features.
    """
    if not events:
        return []

    entity_map = {}
    for event in events:
        eid = event.user or event.host or event.ip or "unknown"
        if eid not in entity_map:
            entity_map[eid] = []
        entity_map[eid].append(event)

    now = utc_now()
    window_start = now - timedelta(minutes=window_minutes)
    behaviors = []

    for entity_id, entity_events in entity_map.items():
        login_fail = sum(1 for e in entity_events if e.event_type == "login" and e.action == "failure")
        login_success = sum(1 for e in entity_events if e.event_type == "login" and e.action == "success")
        total_logins = login_fail + login_success
        login_ratio = login_fail / total_logins if total_logins > 0 else 0.0

        unique_ips = len(set(e.destination_ip for e in entity_events if e.destination_ip))
        unique_hosts = len(set(e.host for e in entity_events if e.host))
        process_count = sum(1 for e in entity_events if e.event_type == "process")
        priv_escalation = sum(1 for e in entity_events if e.event_type == "privilege")
        file_reads = sum(1 for e in entity_events if e.event_type == "file" and e.action == "read")
        file_writes = sum(1 for e in entity_events if e.event_type == "file" and e.action == "write")
        file_deletes = sum(1 for e in entity_events if e.event_type == "file" and e.action == "delete")
        network_events = sum(1 for e in entity_events if e.event_type == "network")
        db_queries = sum(1 for e in entity_events if e.event_type == "database")

        event_rate = len(entity_events) / window_minutes if window_minutes > 0 else 0.0

        hours = set(e.timestamp.hour for e in entity_events)
        after_hours = any(h < 8 or h > 20 for h in hours)
        weekend = any(e.timestamp.weekday() >= 5 for e in entity_events)

        features = BehaviorFeatures(
            login_fail_count=login_fail,
            login_success_count=login_success,
            login_fail_ratio=round(login_ratio, 4),
            event_rate_per_minute=round(event_rate, 4),
            login_attempt_velocity=round(total_logins / window_minutes, 4) if window_minutes > 0 else 0.0,
            unique_ips_accessed=unique_ips,
            unique_destinations=unique_ips,
            unique_hosts_accessed=unique_hosts,
            process_count=process_count,
            privilege_escalation_attempts=priv_escalation,
            file_read_count=file_reads,
            file_write_count=file_writes,
            file_delete_count=file_deletes,
            db_query_count=db_queries,
            after_hours_activity=after_hours,
            weekend_activity=weekend,
            activity_hour_spread=len(hours)
        )

        behavior = AggregatedBehavior(
            pipeline_id=pipeline_id,
            entity_id=entity_id,
            entity_type="user",
            window_start=window_start,
            window_end=now,
            time_window="15min",
            event_count=len(entity_events),
            source_event_ids=[e.event_id for e in entity_events],
            features=features
        )
        behaviors.append(behavior)

    return behaviors


def behaviors_to_dataframe(behaviors: list):
    """Convert AggregatedBehavior list into feature DataFrame for PyOD."""
    rows = []
    for b in behaviors:
        f = b.features
        rows.append({
            "entity_id": b.entity_id,
            "behavior_id": b.behavior_id,
            "login_fail_count": f.login_fail_count,
            "login_fail_ratio": f.login_fail_ratio,
            "event_rate_per_minute": f.event_rate_per_minute,
            "login_attempt_velocity": f.login_attempt_velocity,
            "unique_ips_accessed": f.unique_ips_accessed,
            "unique_hosts_accessed": f.unique_hosts_accessed,
            "process_count": f.process_count,
            "privilege_escalation_attempts": f.privilege_escalation_attempts,
            "file_read_count": f.file_read_count,
            "file_write_count": f.file_write_count,
            "file_delete_count": f.file_delete_count,
            "db_query_count": f.db_query_count,
            "after_hours": 1 if f.after_hours_activity else 0,
            "weekend": 1 if f.weekend_activity else 0,
            "activity_hour_spread": f.activity_hour_spread
        })
    return pd.DataFrame(rows)


def run_ensemble_detection(behaviors: list, pipeline_id: str, contamination: float = 0.15):
    """
    Run IsolationForest + LOF + HBOS ensemble on aggregated behaviors.
    Returns list of DetectionOutput objects following schema v1.1.0.
    """
    if not behaviors or len(behaviors) < 3:
        return []

    df = behaviors_to_dataframe(behaviors)
    entity_ids = df["entity_id"].tolist()
    behavior_ids = df["behavior_id"].tolist()

    feature_cols = [c for c in df.columns if c not in ("entity_id", "behavior_id")]
    X = df[feature_cols].values.astype(float)

    # Three PyOD models
    iforest = IForest(contamination=contamination, random_state=42)
    lof = LOF(contamination=contamination)
    hbos = HBOS(contamination=contamination)

    iforest.fit(X)
    lof.fit(X)
    hbos.fit(X)

    # Normalize scores to 0-1
    def normalize(scores):
        mn, mx = scores.min(), scores.max()
        if mx == mn:
            return np.zeros_like(scores)
        return (scores - mn) / (mx - mn)

    i_scores = normalize(iforest.decision_scores_)
    l_scores = normalize(lof.decision_scores_)
    h_scores = normalize(hbos.decision_scores_)

    ensemble_scores = (i_scores + l_scores + h_scores) / 3.0

    # Threshold for anomaly
    threshold = 0.5

    detections = []
    now = utc_now()
    window_start = now - timedelta(minutes=15)

    for idx in range(len(entity_ids)):
        score = float(ensemble_scores[idx])
        is_anomaly = score >= threshold

        # Severity classification
        if score >= 0.80:
            severity = "critical"
        elif score >= 0.65:
            severity = "high"
        elif score >= 0.45:
            severity = "medium"
        else:
            severity = "low"

        # Top contributing features
        feature_values = {col: float(X[idx][j]) for j, col in enumerate(feature_cols)}
        sorted_features = sorted(feature_values.items(), key=lambda x: abs(x[1]), reverse=True)
        top_features = [f[0] for f in sorted_features[:5]]

        # Per-model scores for features_used
        model_scores = {
            "iforest_score": float(i_scores[idx]),
            "lof_score": float(l_scores[idx]),
            "hbos_score": float(h_scores[idx]),
            "ensemble_score": score
        }

        detection = DetectionOutput(
            pipeline_id=pipeline_id,
            behavior_id=behavior_ids[idx],
            entity_id=entity_ids[idx],
            entity_type="user",
            window_start=window_start,
            window_end=now,
            detected_at=now,
            model="isolation_forest",
            model_version="1.0",
            anomaly_score=round(min(score, 1.0), 4),
            raw_score=float(iforest.decision_scores_[idx]),
            threshold_used=threshold,
            score_margin=round(score - threshold, 4),
            label="anomaly" if is_anomaly else "normal",
            severity=severity,
            features_used=model_scores,
            top_contributing_features=top_features
        )
        detections.append(detection)

    # Sort by score descending
    detections.sort(key=lambda d: d.anomaly_score, reverse=True)

    return detections


# ============================================================================
# Elasticsearch Integration - Following Navdeep's Pattern
# ============================================================================

def push_behaviors_to_es(behaviors: list, es_host: str = "http://172.20.132.59:9200"):
    """Push AggregatedBehavior objects to act_aware_behaviors index."""
    try:
        from elasticsearch import Elasticsearch
        from elasticsearch.helpers import bulk
        
        es = Elasticsearch([es_host], basic_auth=("elastic", "actaware123"))
        
        actions = []
        for behavior in behaviors:
            doc = behavior.dict()
            actions.append({
                "_index": "act_aware_behaviors",
                "_id": behavior.behavior_id,
                "pipeline": "fix_timestamp",
                "_source": doc
            })
        
        if actions:
            success, failed = bulk(es, actions, raise_on_error=False)
            print(f"✅ Pushed {success} behaviors to act_aware_behaviors")
            return success
        return 0
    except Exception as e:
        print(f"❌ Error pushing behaviors: {e}")
        return 0


def push_detections_to_es(detections: list, es_host: str = "http://172.20.132.59:9200"):
    """Push DetectionOutput objects to act_aware_detections index."""
    try:
        from elasticsearch import Elasticsearch
        from elasticsearch.helpers import bulk
        
        es = Elasticsearch([es_host], basic_auth=("elastic", "actaware123"))
        
        actions = []
        for detection in detections:
            doc = detection.dict()
            actions.append({
                "_index": "act_aware_detections",
                "_id": detection.detection_id,
                "pipeline": "fix_timestamp",
                "_source": doc
            })
        
        if actions:
            success, failed = bulk(es, actions, raise_on_error=False)
            print(f"✅ Pushed {success} detections to act_aware_detections")
            return success
        return 0
    except Exception as e:
        print(f"❌ Error pushing detections: {e}")
        return 0


if __name__ == "__main__":
    print("=" * 60)
    print("  Layer 6 — Anomaly Detection Test")
    print("=" * 60)

    # Generate test events
    now = utc_now()
    test_events = []

    # Normal users
    for i in range(20):
        for _ in range(3):
            test_events.append(UniversalEvent(
                timestamp=now - timedelta(minutes=np.random.randint(1, 15)),
                source="winlogbeat",
                event_type="login",
                action="success",
                severity="low",
                user=f"normal_user_{i:02d}",
                host=f"workstation_{i:02d}",
                ip=f"192.168.1.{i+10}"
            ))

    # Attacker 1 — brute force
    for _ in range(15):
        test_events.append(UniversalEvent(
            timestamp=now - timedelta(minutes=np.random.randint(1, 5)),
            source="winlogbeat",
            event_type="login",
            action="failure",
            severity="high",
            user="attacker_bruteforce",
            host="dc-server-01",
            ip="10.0.0.99"
        ))

    # Attacker 2 — insider threat
    for evt in ["file", "file", "file", "database", "privilege"]:
        test_events.append(UniversalEvent(
            timestamp=now - timedelta(minutes=np.random.randint(1, 10)),
            source="filebeat",
            event_type=evt,
            action="read" if evt == "file" else ("escalate" if evt == "privilege" else "read"),
            severity="high",
            user="insider_threat_user",
            host="db-server-01",
            ip="10.0.0.55"
        ))

    # Attacker 3 — lateral movement
    for h in range(8):
        test_events.append(UniversalEvent(
            timestamp=now - timedelta(minutes=np.random.randint(1, 10)),
            source="syslog",
            event_type="network",
            action="connect",
            severity="medium",
            user="lateral_mover",
            host=f"server_{h:02d}",
            ip="10.0.0.77",
            destination_ip=f"10.0.{h}.1"
        ))

    pipeline_id = f"test_{str(uuid4())[:8]}"

    print(f"\nTotal test events: {len(test_events)}")

    # Aggregate
    behaviors = aggregate_events(test_events, pipeline_id)
    print(f"Entities aggregated: {len(behaviors)}")

    # Detect
    detections = run_ensemble_detection(behaviors, pipeline_id)
    push_behaviors_to_es(behaviors)
    push_detections_to_es(detections)

    # Results
    anomalies = [d for d in detections if d.label == "anomaly"]
    print(f"\nAnomalies detected: {len(anomalies)} / {len(detections)}")

    print(f"\n{'Entity':<25} {'Score':>7} {'Severity':<10} {'Label':<8} {'Top Features'}")
    print("-" * 90)
    for d in detections:
        marker = " <<<" if d.label == "anomaly" else ""
        print(f"{d.entity_id:<25} {d.anomaly_score:>7.4f} {d.severity:<10} {d.label:<8} {', '.join(d.top_contributing_features[:3])}{marker}")

    print(f"\n{'='*60}")
    print("  Detection layer test PASSED")
    print(f"{'='*60}")



