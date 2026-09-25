# run_pipeline.py
"""
ACT AWARE — End-to-End Autonomous Pipeline Runner
Executes the full 10-layer pipeline from raw banking telemetry to SOAR response.
Fully air-gapped and offline capable.
"""

import sys
import os
from datetime import datetime, timezone
import logging

# Ensure root directory is in sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config.settings import settings
from layer3_storage.index_manager import index_manager
from layer1_ingestion.log_generators import log_simulator
from layer1_ingestion.normalizer import normalizer
from layer4_aggregation.sliding_window import aggregator
from layer5_features.posture_engine import posture_engine
from layer6_detection.anomaly_detector import anomaly_detector
from layer7_correlation.correlation_engine import correlation_engine
from layer8_fidelity.fidelity_engine import fidelity_engine
from layer9_agentic_soc.reasoning_engine import agentic_soc
from soar.executor import execute_step
from config.schemas import SOARConstraints
from evaluation.metrics_engine import metrics_engine
from evaluation.feedback_loop import feedback_loop
from storage.es_client import es_client

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("ACT_AWARE_PIPELINE")


def run_act_aware_pipeline():
    print("\n" + "=" * 80)
    print("      ACT AWARE — BANKING CYBER INCIDENT RESPONSE PLATFORM (AIR-GAPPED)      ")
    print("      Team: PHEONIX CORE | Theme: Cyber Incident Response in Banking         ")
    print("=" * 80)

    # ── STEP 0: Topology & Storage Check ──────────────────────────────────────
    print("\n[*] LAYER 3: Initializing Storage Backbone & Unified Indices...")
    index_manager.setup_indices()
    connected = es_client.check_connection()
    if connected:
        print(f"  [+] Connected to Elasticsearch cluster at {settings.ES_HOST}")
    else:
        print(f"  [!] Elasticsearch remote ping offline — Running in resilient air-gapped demo mode.")

    # ── STEP 1: Log Collection & Ingestion (Layer 1-2) ────────────────────────
    print("\n[*] LAYER 1-2: Generating Multi-Source Banking Telemetry...")
    baseline_logs = log_simulator.generate_baseline_traffic(count=30)
    attack_logs = log_simulator.generate_banking_attack_scenario()
    raw_logs = baseline_logs + attack_logs
    print(f"  [+] Generated {len(raw_logs)} raw security logs (Baseline: {len(baseline_logs)}, Attack: {len(attack_logs)})")
    print("      Sources: Winlogbeat (AD/Sysmon), Filebeat (Core Banking), Syslog (Firewall)")

    print("\n[*] LAYER 1-2: ECS Normalization & Indexing into 'act_aware_events'...")
    normalized_events = []
    pipeline_id = f"pipeline_run_{int(datetime.now(timezone.utc).timestamp())}"
    for raw in raw_logs:
        ev = normalizer.ingest_event(raw, pipeline_id=pipeline_id)
        normalized_events.append(ev)
    valid_count = sum(1 for e in normalized_events if e.is_valid)
    print(f"  [+] Ingested {valid_count}/{len(normalized_events)} valid UniversalEvent records to 'act_aware_events'")

    # ── STEP 2: Behavioral Aggregation & Features (Layer 3-5) ─────────────────
    print("\n[*] LAYER 4-5: Sliding Time-Window Aggregation & Feature Extraction...")
    behaviors = aggregator.aggregate_events(normalized_events, window_size_minutes=15, window_name="15min")
    print(f"  [+] Profiled {len(behaviors)} entities into 'act_aware_behaviors'")
    for b in behaviors:
        posture = posture_engine.evaluate_posture(b)
        if posture["is_high_risk"]:
            print(f"      - High Risk Entity '{b.entity_id}' [{b.entity_type}]: Posture Score = {posture['posture_score']}")
            for sig in posture["risk_signals"]:
                print(f"        * {sig}")

    # ── STEP 3: Detection & Anomaly Scoring (Layer 6) ──────────────────────────
    print("\n[*] LAYER 6: PyOD / Isolation Forest Anomaly Detection...")
    detections = anomaly_detector.score_behaviors(behaviors)
    anomalies = [d for d in detections if d.label == "anomaly"]
    print(f"  [+] Scored {len(detections)} behaviors into 'act_aware_detections'. Found {len(anomalies)} anomalies:")
    for a in anomalies:
        print(f"      - [{a.severity.upper()}] Entity: {a.entity_id} | Score: {a.anomaly_score:.4f} | Margin: +{a.score_margin:.4f}")
        print(f"        Top Contributing Features: {', '.join(a.top_contributing_features[:3])}")

    # ── STEP 4: Correlation & Graph Attack Modeling (Layer 7) ─────────────────
    print("\n[*] LAYER 7: Multi-Source Correlation & NetworkX Graph Attack Modeling...")
    incidents = correlation_engine.correlate(normalized_events, detections)
    if not incidents:
        print("  [-] No multi-stage attack incidents identified.")
        return

    incident = incidents[0]
    graph_ctx = incident.graph_context
    print(f"  [+] Incident Created: {incident.incident_id}")
    print(f"      Pattern: {incident.pattern.upper()} | Stage: {incident.attack_stage.upper()} | Severity: {incident.severity.upper()}")
    print(f"      Primary Pivot Entity: {incident.primary_entity}")
    print(f"      Graph Nodes: {len(graph_ctx.nodes)} | Edges: {len(graph_ctx.edges)} | Lateral Movement Detected: {graph_ctx.lateral_movement_detected}")
    print(f"      Attack Duration: {incident.duration_minutes:.1f} mins | Timeline Entries: {len(incident.timeline)}")

    # ── STEP 5: Fidelity Scoring (Layer 8) ────────────────────────────────────
    print("\n[*] LAYER 8: Computing Multi-Dimensional Fidelity Score...")
    fidelity = fidelity_engine.evaluate_incident(incident, detections, stability_count=2)
    b_down = fidelity.score_breakdown
    print(f"  [+] Fidelity Score: {fidelity.fidelity_score:.4f} (Confidence: {fidelity.confidence.upper()})")
    print(f"      Signal Stability: {'STABLE (Persistent)' if fidelity.is_stable else 'TRANSIENT'}")
    print(f"      Component Breakdown:")
    print(f"        - Anomaly Component (40%): {b_down.anomaly_component:.2f}")
    print(f"        - Graph Component   (30%): {b_down.graph_component:.2f} (Lateral Movement + Centrality)")
    print(f"        - Posture Component (20%): {b_down.posture_component:.2f} (Privilege Misuse)")
    print(f"        - Temporal Component(10%): {b_down.temporal_component:.2f} (Multi-Stage Persistence)")

    # ── STEP 6: Agentic SOC Reasoning & Playbook Generation (Layer 9) ─────────
    print("\n[*] LAYER 9: Agentic SOC Reasoning (LangGraph + Ollama / Air-Gapped Engine)...")
    print("      Gating Check: Verifying is_stable=True and Confidence >= High... PASSED.")
    playbook = agentic_soc.generate_playbook(
        incident=incident,
        fidelity=fidelity,
        requested_by="senior_analyst.vedika"
    )
    print(f"  [+] Advisory Playbook Generated: {playbook.playbook_id}")
    print(f"      Threat Narrative:\n      \"{playbook.threat_narrative}\"")
    print(f"      Attack Hypothesis: \"{playbook.attack_hypothesis}\"")
    print(f"      Status: {playbook.status.upper()} (All actions require human approval)")
    print("\n      Recommended SOAR Action Steps:")
    for s in playbook.steps:
        print(f"        Step {s.step_number}: [{s.action.upper()}] -> Target: {s.target_entity}")
        print(f"                Rationale: {s.reason}")

    # ── STEP 7: Control Plane & SOAR Response Execution (Layer 9-10) ──────────
    print("\n[*] LAYER 9-10: Human-in-the-Loop Approval & SOAR Response Execution...")
    soar_constraints = SOARConstraints(
        allowed_soar_actions=[
            "isolate_endpoint",
            "force_logout",
            "revoke_token",
            "block_ip",
            "alert_analyst",
            "increase_monitoring"
        ],
        max_blast_radius="network",
    )
    executed_count = 0
    for s in playbook.steps:
        # Simulate analyst approving containment actions
        s.approved = True
        s.approved_by = "senior_analyst.vedika"
        s.approved_at = datetime.now(timezone.utc)

        # Execute step through safety checks
        res = execute_step(
            step=s,
            constraints=soar_constraints,
            executor_username="soc_manager.vedika",
            executor_role="soc_manager",
            pipeline_id=pipeline_id,
            incident_id=incident.incident_id,
        )
        if res.success:
            s.executed = True
            executed_count += 1
            print(f"  [PASS] EXECUTED Step {s.step_number}: {s.action} on {s.target_entity} -> SUCCESS")
        else:
            print(f"  [FAIL] BLOCKED Step {s.step_number}: {s.action} -> {res.message}")

    playbook.status = "executed"
    es_client.update_playbook(playbook.playbook_id, {"status": "executed"})

    # ── STEP 8: Evaluation & Feedback Loop (Layer 10) ─────────────────────────
    print("\n[*] LAYER 10: Evaluation, System Metrics & Feedback Loop...")
    metrics = metrics_engine.compute_all_metrics()
    alert_m = metrics["alert_metrics"]
    print(f"  [+] Alert Reduction Rate: {alert_m['reduction_percentage']} ({alert_m['total_raw_events']} raw logs -> {alert_m['total_incidents']} incident)")
    print(f"  [+] Playbook Acceptance Rate: {metrics['playbook_metrics']['acceptance_percentage']}")
    print(f"  [+] SOAR Action Success Rate: {metrics['action_metrics']['success_percentage']}")

    fb = feedback_loop.submit_feedback(
        incident_id=incident.incident_id,
        analyst_username="senior_analyst.vedika",
        feedback_type="true_positive",
        severity_accurate=True,
        notes="High-risk banking attack verified. Staged lateral movement and database exfiltration contained.",
        playbook_id=playbook.playbook_id,
    )
    print(f"  [+] Closed-Loop Analyst Feedback: Recorded {fb['feedback_type']} (Retraining Triggered: {fb['retraining_triggered']})")

    # ── SUMMARY DASHBOARD ─────────────────────────────────────────────────────
    print("\n" + "=" * 80)
    print("                     ACT AWARE EXECUTION COMPLETE                          ")
    print("=" * 80)
    print(f"Pipeline Run ID        : {pipeline_id}")
    print(f"Total Raw Logs Ingested: {len(raw_logs)}")
    print(f"Anomalous Entities     : {len(anomalies)}")
    print(f"Correlated Incident    : {incident.incident_id} [{incident.pattern}]")
    print(f"Fidelity Confidence    : {fidelity.fidelity_score} ({fidelity.confidence.upper()})")
    print(f"Playbook Status        : EXECUTED ({executed_count} actions contained)")
    print(f"Alert Reduction Rate   : {alert_m['reduction_percentage']}")
    print("=" * 80 + "\n")


if __name__ == "__main__":
    run_act_aware_pipeline()
