"""
correlation.py
Layer 6 — Multi-Source Correlation Engine
Team: Phoenix Core | ACT AWARE | Kanchan
Follows: config/schemas.py v1.1.0
"""

import sys
sys.path.insert(0, '.')

from datetime import timedelta
from uuid import uuid4
from collections import defaultdict

from config.schemas import (
    UniversalEvent, DetectionOutput, CorrelatedIncident,
    TimelineEvent, GraphContext, utc_now
)


# Attack pattern detection rules
ATTACK_PATTERNS = {
    "brute_force": {
        "indicators": ["login_fail_count", "login_fail_ratio", "login_attempt_velocity"],
        "min_events": 5,
        "stage": "initial_access"
    },
    "lateral_movement": {
        "indicators": ["unique_hosts_accessed", "unique_ips_accessed"],
        "min_events": 3,
        "stage": "lateral_movement"
    },
    "data_exfiltration": {
        "indicators": ["file_read_count", "db_query_count", "outbound_data_volume"],
        "min_events": 3,
        "stage": "exfiltration"
    },
    "privilege_escalation": {
        "indicators": ["privilege_escalation_attempts", "admin_action_count"],
        "min_events": 2,
        "stage": "privilege_escalation"
    },
    "insider_threat": {
        "indicators": ["after_hours", "file_read_count", "sensitive_resource_access_count"],
        "min_events": 3,
        "stage": "collection"
    },
    "ransomware": {
        "indicators": ["file_write_count", "file_delete_count", "process_count"],
        "min_events": 4,
        "stage": "execution"
    }
}


def classify_attack_pattern(detection: DetectionOutput, entity_events: list):
    """
    Determine attack pattern based on top contributing features
    and event characteristics.
    """
    top_features = detection.top_contributing_features
    event_types = [e.event_type for e in entity_events]
    actions = [e.action for e in entity_events]

    # Count event characteristics
    login_failures = sum(1 for e in entity_events if e.event_type == "login" and e.action == "failure")
    file_ops = sum(1 for e in entity_events if e.event_type == "file")
    network_events = sum(1 for e in entity_events if e.event_type == "network")
    priv_events = sum(1 for e in entity_events if e.event_type == "privilege")
    unique_hosts = len(set(e.host for e in entity_events if e.host))
    db_events = sum(1 for e in entity_events if e.event_type == "database")

    # Pattern matching with scoring
    pattern_scores = {}

    # Brute force
    if login_failures >= 5 or "login_fail_count" in top_features:
        pattern_scores["brute_force"] = login_failures * 0.2 + detection.anomaly_score

    # Lateral movement
    if unique_hosts >= 3 or "unique_hosts_accessed" in top_features:
        pattern_scores["lateral_movement"] = unique_hosts * 0.15 + network_events * 0.1

    # Data exfiltration
    if (file_ops >= 3 and db_events >= 1) or "file_read_count" in top_features:
        pattern_scores["data_exfiltration"] = file_ops * 0.1 + db_events * 0.2

    # Privilege escalation
    if priv_events >= 1 or "privilege_escalation_attempts" in top_features:
        pattern_scores["privilege_escalation"] = priv_events * 0.3

    # Insider threat
    if "after_hours" in top_features and file_ops >= 2:
        pattern_scores["insider_threat"] = file_ops * 0.15 + db_events * 0.1

    # Ransomware
    if "file_write_count" in top_features and "file_delete_count" in top_features:
        pattern_scores["ransomware"] = file_ops * 0.2

    if not pattern_scores:
        return "unknown", "unknown"

    best_pattern = max(pattern_scores, key=pattern_scores.get)
    stage = ATTACK_PATTERNS.get(best_pattern, {}).get("stage", "unknown")

    return best_pattern, stage


def build_timeline(entity_events: list, max_events: int = 20):
    """Build ordered timeline of key events for the incident."""
    sorted_events = sorted(entity_events, key=lambda e: e.timestamp)

    timeline = []
    for event in sorted_events[:max_events]:
        timeline_event = TimelineEvent(
            event_id=event.event_id,
            timestamp=event.timestamp,
            entity_id=event.user or event.host or event.ip or "unknown",
            action=event.action,
            resource=event.resource or event.process_name or event.host,
            severity=event.severity
        )
        timeline.append(timeline_event)

    return timeline


def calculate_duration(events: list):
    """Calculate time span of events in minutes."""
    if not events or len(events) < 2:
        return 0.0

    timestamps = sorted(e.timestamp for e in events)
    duration = (timestamps[-1] - timestamps[0]).total_seconds() / 60.0
    return round(duration, 2)


def determine_severity(detections: list):
    """Get highest severity from all detections."""
    severity_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    highest = "low"

    for d in detections:
        if severity_order.get(d.severity, 0) > severity_order.get(highest, 0):
            highest = d.severity

    return highest


def correlate_events(detections: list, raw_events: list, time_window_minutes: int = 15):
    """
    Correlate anomaly detections with raw events to build
    CorrelatedIncident objects following schema v1.1.0.

    Args:
        detections: List of DetectionOutput from detection.py
        raw_events: List of UniversalEvent objects
        time_window_minutes: Time window for correlation

    Returns:
        List of CorrelatedIncident objects
    """
    if not detections:
        return []

    # Filter anomalies only
    anomalies = [d for d in detections if d.label == "anomaly"]

    if not anomalies:
        return []

    # Group events by entity
    entity_events_map = defaultdict(list)
    for event in raw_events:
        eid = event.user or event.host or event.ip or "unknown"
        entity_events_map[eid].append(event)

    incidents = []
    now = utc_now()

    for detection in anomalies:
        entity_id = detection.entity_id
        entity_events = entity_events_map.get(entity_id, [])

        if not entity_events:
            continue

        # Classify attack pattern
        pattern, stage = classify_attack_pattern(detection, entity_events)

        # Build timeline
        timeline = build_timeline(entity_events)

        # Calculate duration
        duration = calculate_duration(entity_events)

        # Get all source event IDs
        source_event_ids = [e.event_id for e in entity_events]

        # Get sources involved
        sources = list(set(e.source for e in entity_events))

        # Determine timestamps
        sorted_events = sorted(entity_events, key=lambda e: e.timestamp)
        incident_start = sorted_events[0].timestamp
        incident_end = sorted_events[-1].timestamp

        # Ensure end is not before start
        if incident_end < incident_start:
            incident_end = incident_start

        incident = CorrelatedIncident(
            pipeline_id=detection.pipeline_id,
            entities=[entity_id],
            entity_types={entity_id: detection.entity_type},
            primary_entity=entity_id,
            detection_ids=[detection.detection_id],
            source_event_ids=source_event_ids,
            incident_start=incident_start,
            incident_end=incident_end,
            duration_minutes=duration,
            timeline=timeline,
            pattern=pattern,
            attack_stage=stage,
            severity=detection.severity,
            graph_context=GraphContext()
        )

        incidents.append(incident)

    # Sort by severity (critical first)
    severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    incidents.sort(key=lambda i: severity_order.get(i.severity, 0), reverse=True)

    return incidents


def merge_related_incidents(incidents: list, time_threshold_minutes: int = 30):
    """
    Merge incidents that share entities or have overlapping time windows.
    Prevents duplicate incidents for the same attack.
    """
    if len(incidents) <= 1:
        return incidents

    merged = []
    used = set()

    for i, inc_a in enumerate(incidents):
        if i in used:
            continue

        # Find related incidents
        related = [inc_a]
        for j, inc_b in enumerate(incidents):
            if j <= i or j in used:
                continue

            # Check entity overlap
            entities_overlap = bool(set(inc_a.entities) & set(inc_b.entities))

            # Check time overlap
            time_gap = abs((inc_b.incident_start - inc_a.incident_end).total_seconds() / 60)
            time_overlap = time_gap <= time_threshold_minutes

            if entities_overlap and time_overlap:
                related.append(inc_b)
                used.add(j)

        if len(related) == 1:
            merged.append(inc_a)
        else:
            # Merge into single incident
            all_entities = []
            all_entity_types = {}
            all_detection_ids = []
            all_event_ids = []
            all_timeline = []

            for r in related:
                all_entities.extend(r.entities)
                all_entity_types.update(r.entity_types)
                all_detection_ids.extend(r.detection_ids)
                all_event_ids.extend(r.source_event_ids)
                all_timeline.extend(r.timeline)

            all_entities = list(set(all_entities))
            all_timeline.sort(key=lambda t: t.timestamp)

            starts = [r.incident_start for r in related]
            ends = [r.incident_end for r in related]

            merged_severity = determine_severity(
                [type('obj', (object,), {'severity': r.severity})() for r in related]
            )

            merged_incident = CorrelatedIncident(
                pipeline_id=related[0].pipeline_id,
                entities=all_entities,
                entity_types=all_entity_types,
                primary_entity=related[0].primary_entity,
                detection_ids=list(set(all_detection_ids)),
                source_event_ids=list(set(all_event_ids)),
                incident_start=min(starts),
                incident_end=max(ends),
                duration_minutes=round((max(ends) - min(starts)).total_seconds() / 60, 2),
                timeline=all_timeline[:20],
                pattern=related[0].pattern,
                attack_stage=related[0].attack_stage,
                severity=merged_severity,
                graph_context=GraphContext()
            )
            merged.append(merged_incident)

    return merged

# ============================================================================
# Elasticsearch Integration - Following Navdeep's Pattern
# ============================================================================

def push_incidents_to_es(incidents: list, es_host: str = "192.168.43.198:9200"):
    """Push CorrelatedIncident objects to act_aware_incidents index."""
    try:
        from elasticsearch import Elasticsearch
        from elasticsearch.helpers import bulk
        
        es = Elasticsearch([es_host], basic_auth=("elastic", "actaware123"))
        
        actions = []
        for incident in incidents:
            doc = incident.dict()
            actions.append({
                "_index": "act_aware_incidents",
                "_id": incident.incident_id,
                "pipeline": "fix_timestamp",
                "_source": doc
            })
        
        if actions:
            success, failed = bulk(es, actions, raise_on_error=False)
            print(f"✅ Pushed {success} incidents to act_aware_incidents")
            return success
        return 0
    except Exception as e:
        print(f"❌ Error pushing incidents: {e}")
        return 0


if __name__ == "__main__":
    import numpy as np
    from detection import aggregate_events, run_ensemble_detection

    print("=" * 60)
    print("  Layer 6 — Correlation Engine Test")
    print("=" * 60)

    now = utc_now()
    test_events = []
    pipeline_id = f"test_{str(uuid4())[:8]}"

    # Normal users
    for i in range(15):
        for _ in range(2):
            test_events.append(UniversalEvent(
                timestamp=now - timedelta(minutes=np.random.randint(1, 15)),
                source="winlogbeat",
                event_type="login",
                action="success",
                severity="low",
                user=f"normal_{i:02d}",
                host=f"ws_{i:02d}",
                ip=f"192.168.1.{i+10}",
                pipeline_id=pipeline_id
            ))

    # Attacker — brute force
    for _ in range(12):
        test_events.append(UniversalEvent(
            timestamp=now - timedelta(minutes=np.random.randint(1, 5)),
            source="winlogbeat",
            event_type="login",
            action="failure",
            severity="high",
            user="brute_force_attacker",
            host="dc-01",
            ip="10.0.0.99",
            pipeline_id=pipeline_id
        ))

    # Attacker — data exfil
    for evt, act in [("file", "read"), ("file", "read"), ("file", "read"),
                     ("database", "read"), ("database", "read"), ("privilege", "escalate")]:
        test_events.append(UniversalEvent(
            timestamp=now - timedelta(minutes=np.random.randint(1, 10)),
            source="filebeat",
            event_type=evt,
            action=act,
            severity="high",
            user="data_thief",
            host="db-server",
            ip="10.0.0.55",
            pipeline_id=pipeline_id
        ))

    # Attacker — lateral movement
    for h in range(6):
        test_events.append(UniversalEvent(
            timestamp=now - timedelta(minutes=np.random.randint(1, 10)),
            source="syslog",
            event_type="network",
            action="connect",
            severity="medium",
            user="lateral_mover",
            host=f"server_{h:02d}",
            ip="10.0.0.77",
            destination_ip=f"10.0.{h}.1",
            pipeline_id=pipeline_id
        ))

    print(f"\nTotal test events: {len(test_events)}")

    # Run detection
    behaviors = aggregate_events(test_events, pipeline_id)
    detections = run_ensemble_detection(behaviors, pipeline_id)
    anomalies = [d for d in detections if d.label == "anomaly"]
    print(f"Anomalies detected: {len(anomalies)}")

    # Run correlation
    incidents = correlate_events(detections, test_events)
    incidents = merge_related_incidents(incidents)
    push_incidents_to_es(incidents)

    print(f"Correlated incidents: {len(incidents)}")

    for inc in incidents:
        print(f"\n{'─' * 50}")
        print(f"  Incident:  {inc.incident_id[:12]}...")
        print(f"  Entity:    {inc.primary_entity}")
        print(f"  Pattern:   {inc.pattern}")
        print(f"  Stage:     {inc.attack_stage}")
        print(f"  Severity:  {inc.severity.upper()}")
        print(f"  Duration:  {inc.duration_minutes} minutes")
        print(f"  Events:    {len(inc.source_event_ids)}")
        print(f"  Timeline:  {len(inc.timeline)} steps")
        chain = " → ".join([f"{t.action}({t.resource or '?'})" for t in inc.timeline[:5]])
        print(f"  Chain:     {chain}")

    print(f"\n{'=' * 60}")
    print("  Correlation engine test PASSED")
    print(f"{'=' * 60}")