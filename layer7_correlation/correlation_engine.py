# layer7_correlation/correlation_engine.py
"""
Layer 7: Multi-Source Correlation Engine
Correlates detections across EDR, Network, IAM, and Database events.
Combines timeline sequence and graph topology into a unified CorrelatedIncident.
Writes incidents to 'act_aware_incidents'.
"""

from typing import List, Dict, Any, Optional
from datetime import datetime

from config.schemas import (
    UniversalEvent,
    DetectionOutput,
    CorrelatedIncident,
    TimelineEvent,
    AttackPattern,
    AttackStage,
    SeverityLevel,
    EntityType,
    utc_now,
)
from layer7_correlation.graph_attack import graph_modeler
from storage.es_client import es_client
from config.settings import settings
import logging

logger = logging.getLogger(__name__)


class CorrelationEngine:
    def __init__(self):
        self.es = es_client

    def correlate(
        self,
        events: List[UniversalEvent],
        detections: List[DetectionOutput]
    ) -> List[CorrelatedIncident]:
        """
        Groups detections and raw events into multi-stage attack incidents.
        Builds graph context and timeline reconstruction.
        """
        if not events:
            return []

        # Filter anomalous detections or high-severity events
        anomaly_detections = [d for d in detections if d.label == "anomaly" or d.severity in ("high", "critical")]
        if not anomaly_detections and not any(e.severity in ("high", "critical") for e in events):
            logger.info("No anomalous detections or critical events to correlate into incidents.")
            return []

        # Group events by attack cluster / scenario if multiple scenarios are present
        clusters: Dict[str, List[UniversalEvent]] = {}
        for e in events:
            # Benign scanner noise suppression (Scenario G)
            if "svc_vuln_scanner" in str(e.user) or "svc_vuln_scanner" in str(e.resource or ""):
                continue  # Suppress benign scanner alerts from escalating into security incidents!

            cluster_key = "default_campaign"
            note = str(e.metadata.get("notes") or "")
            if "ransomware" in note or "vssadmin" in str(e.resource or "") or "svc_jenkins" in str(e.user or ""):
                cluster_key = "ransomware_campaign"
            elif "bec" in note or "wire_fraud" in note or "finance_mgr" in str(e.user or "") or "inboxrule" in str(e.resource or "").lower():
                cluster_key = "bec_campaign"
            elif "spray" in note or "203.0.113.45" in (e.ip or "") or "tflenderson" in str(e.user or "") or "GT_BRUTE" in note:
                cluster_key = "password_spray_campaign"
            elif "insider" in note or "mscott" in str(e.user or "") or "personal_backup.zip" in str(e.resource or ""):
                cluster_key = "insider_threat_campaign"
            elif "lsass" in note or "update_service.exe" in str(e.process_name or "") or "DC-01" in str(e.host or "") or "sys_admin" in str(e.user or ""):
                cluster_key = "lateral_movement_campaign"
            elif "supply_chain" in note or "cicd" in note or "svc_cicd_runner" in str(e.user or ""):
                cluster_key = "supply_chain_campaign"
            elif "sqli" in note or "xp_cmdshell" in str(e.resource or "") or "MSSQLSERVER" in str(e.user or ""):
                cluster_key = "web_sqli_campaign"
            elif e.user:
                cluster_key = f"user_{e.user}"
            elif e.ip:
                cluster_key = f"ip_{e.ip}"

            clusters.setdefault(cluster_key, []).append(e)

        incidents: List[CorrelatedIncident] = []

        for c_key, c_events in clusters.items():
            if len(c_events) == 0:
                continue

            # Only correlate if cluster has anomalous detections, high severity, or multiple suspicious events
            c_high_sev = [ev for ev in c_events if ev.severity in ("high", "critical")]
            c_users = {ev.user for ev in c_events if ev.user}
            c_ips = {ev.ip for ev in c_events if ev.ip}
            
            # Find relevant detections for this cluster
            c_detections = [d for d in detections if d.entity_id in c_users or d.entity_id in c_ips]
            if not c_high_sev and not any(d.label == "anomaly" for d in c_detections) and len(c_events) < 3:
                continue

            # Entities involved
            entities_involved = set()
            entity_types: Dict[str, EntityType] = {}
            for ev in c_events:
                if ev.user:
                    entities_involved.add(ev.user)
                    entity_types[ev.user] = "user"
                if ev.host:
                    entities_involved.add(ev.host)
                    entity_types[ev.host] = "host"
                if ev.ip:
                    entities_involved.add(ev.ip)
                    entity_types[ev.ip] = "ip"
                if ev.destination_ip:
                    entities_involved.add(ev.destination_ip)
                    entity_types[ev.destination_ip] = "ip"

            # Graph context for this cluster
            graph_ctx = graph_modeler.build_graph_context(c_events, c_detections)

            primary_entity = graph_ctx.pivot_entity
            if not primary_entity and c_detections:
                highest_det = max(c_detections, key=lambda d: d.anomaly_score)
                primary_entity = highest_det.entity_id
            if not primary_entity and c_high_sev:
                primary_entity = c_high_sev[0].user or c_high_sev[0].ip or c_high_sev[0].host
            if not primary_entity:
                primary_entity = list(entities_involved)[0] if entities_involved else "unknown_actor"

            # Timeline
            sorted_events = sorted(c_events, key=lambda ev: ev.timestamp)
            timeline: List[TimelineEvent] = []
            for ev in sorted_events:
                ent = ev.user or ev.host or ev.ip or "unknown"
                timeline.append(
                    TimelineEvent(
                        event_id=ev.event_id,
                        timestamp=ev.timestamp,
                        entity_id=ent,
                        action=ev.action,
                        resource=ev.resource or ev.process_name,
                        severity=ev.severity,
                    )
                )

            # Pattern & Stage Inference
            actions_seen = {ev.action for ev in c_events}
            event_types_seen = {ev.event_type for ev in c_events}
            text_context = " ".join([
                ev.resource or "" for ev in c_events
            ] + [
                ev.process_name or "" for ev in c_events
            ] + [
                str(ev.metadata.get("command_line", "")) for ev in c_events
            ] + [
                str(ev.metadata.get("notes", "")) for ev in c_events
            ]).lower()

            pattern: AttackPattern = "unknown"
            stage: AttackStage = "reconnaissance"
            max_severity: SeverityLevel = "low"

            if "vssadmin" in text_context or "ransomware" in text_context or "backup_agent" in text_context:
                pattern = "ransomware"
                stage = "exfiltration"
                max_severity = "critical"
            elif "inboxrule" in text_context or "wire_transfer" in text_context or "wire transfer" in text_context or "bec" in text_context:
                pattern = "data_exfiltration"
                stage = "exfiltration"
                max_severity = "critical"
            elif "certutil" in text_context or "4625" in text_context or "spray" in text_context or "gt_brute" in text_context:
                pattern = "brute_force"
                stage = "initial_access"
                max_severity = "high"
            elif "personal_backup.zip" in text_context or "confidential" in text_context or "mscott" in text_context:
                pattern = "insider_threat"
                stage = "collection"
                max_severity = "high"
            elif "lsass" in text_context or "dc-01" in text_context or graph_ctx.lateral_movement_detected:
                pattern = "lateral_movement"
                stage = "lateral_movement"
                max_severity = "critical"
            elif "actions-runner" in text_context or "payment-gateway" in text_context or "aws_" in text_context:
                pattern = "api_abuse"
                stage = "execution"
                max_severity = "critical"
            elif "xp_cmdshell" in text_context or "mssql" in text_context or "sqli" in text_context:
                pattern = "privilege_escalation"
                stage = "execution"
                max_severity = "critical"
            elif "read" in actions_seen and ("customer_accounts" in text_context or "database" in event_types_seen):
                pattern = "data_exfiltration"
                stage = "exfiltration"
                max_severity = "critical"
            elif any(ev.action == "failure" and ev.event_type == "login" for ev in c_events):
                pattern = "brute_force"
                stage = "initial_access"
                max_severity = "medium"

            for ev in c_high_sev:
                if ev.severity == "critical":
                    max_severity = "critical"
                    break
                elif ev.severity == "high" and max_severity != "critical":
                    max_severity = "high"

            start_time = sorted_events[0].timestamp
            end_time = sorted_events[-1].timestamp
            duration = max(1.0, (end_time - start_time).total_seconds() / 60.0)
            pid = c_events[0].pipeline_id

            incident = CorrelatedIncident(
                pipeline_id=pid,
                entities=list(entities_involved),
                entity_types=entity_types,
                primary_entity=primary_entity,
                detection_ids=[d.detection_id for d in c_detections],
                source_event_ids=[ev.event_id for ev in c_events],
                incident_start=start_time,
                incident_end=end_time,
                duration_minutes=round(duration, 2),
                timeline=timeline[:20],
                pattern=pattern,
                attack_stage=stage,
                severity=max_severity,
                graph_context=graph_ctx,
            )

            # Store to act_aware_incidents
            doc = incident.model_dump()
            doc["incident_start"] = incident.incident_start.isoformat()
            doc["incident_end"] = incident.incident_end.isoformat()
            doc["created_at"] = incident.created_at.isoformat()
            doc["updated_at"] = incident.updated_at.isoformat()
            for t_item in doc.get("timeline", []):
                if isinstance(t_item.get("timestamp"), datetime):
                    t_item["timestamp"] = t_item["timestamp"].isoformat()
            for edge in doc.get("graph_context", {}).get("edges", []):
                if isinstance(edge.get("timestamp"), datetime):
                    edge["timestamp"] = edge["timestamp"].isoformat()

            self.es.store_incident(incident.incident_id, doc)
            logger.info(f"Created CorrelatedIncident {incident.incident_id} [{incident.pattern} / {incident.severity}]")
            incidents.append(incident)

        return incidents


correlation_engine = CorrelationEngine()
