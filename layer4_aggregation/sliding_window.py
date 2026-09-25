# layer4_aggregation/sliding_window.py
"""
Layer 4: Behavioral Aggregation Engine
Reads normalized logs from 'act_aware_events' (or in-memory stream).
Aggregates events into per-entity sliding time-window behavioral states.
Writes AggregatedBehavior records conforming to Frozen Data Contract v1.1.0
to 'act_aware_behaviors'.
"""

from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta, timezone
from collections import defaultdict
import math

from config.schemas import (
    UniversalEvent,
    AggregatedBehavior,
    BehaviorFeatures,
    EntityType,
    TimeWindow,
    utc_now,
)
from storage.es_client import es_client
from config.settings import settings
import logging

logger = logging.getLogger(__name__)

SUSPICIOUS_PROCESSES = {
    "mimikatz.exe", "psexec.exe", "wscript.exe", "certutil.exe",
    "powershell.exe", "cscript.exe", "vssadmin.exe", "net.exe"
}

SENSITIVE_RESOURCES = {
    "sam", "/etc/passwd", "/etc/shadow", "customer_accounts",
    "swift_financial_gateway", "sedebugprivilege", "admin$", "ipc$"
}


class SlidingWindowAggregator:
    def __init__(self):
        self.es = es_client

    def aggregate_events(
        self,
        events: List[UniversalEvent],
        window_size_minutes: int = 15,
        window_name: TimeWindow = "15min",
    ) -> List[AggregatedBehavior]:
        """
        Groups events by entity (user, host, IP) over sliding time windows
        and computes rich behavioral feature vectors.
        """
        if not events:
            return []

        # Sort events by timestamp
        sorted_events = sorted(events, key=lambda e: e.timestamp)
        earliest_time = sorted_events[0].timestamp
        latest_time = sorted_events[-1].timestamp

        # Define time window bounds
        window_start = earliest_time
        window_end = latest_time if latest_time > earliest_time else (earliest_time + timedelta(minutes=window_size_minutes))
        duration_minutes = max(1.0, (window_end - window_start).total_seconds() / 60.0)

        # Bucket events by entity: (entity_type, entity_id) -> list of events
        entity_buckets = defaultdict(list)
        for e in sorted_events:
            if not e.is_valid:
                continue

            if e.user:
                entity_buckets[("user", e.user)].append(e)
            if e.host:
                entity_buckets[("host", e.host)].append(e)
            if e.ip:
                entity_buckets[("ip", e.ip)].append(e)

        aggregated_records: List[AggregatedBehavior] = []

        for (entity_type, entity_id), ev_list in entity_buckets.items():
            features = self._calculate_features(ev_list, duration_minutes)
            pid = ev_list[0].pipeline_id

            behavior = AggregatedBehavior(
                pipeline_id=pid,
                entity_id=entity_id,
                entity_type=entity_type,
                window_start=window_start,
                window_end=window_end,
                time_window=window_name,
                event_count=len(ev_list),
                source_event_ids=[e.event_id for e in ev_list],
                features=features,
            )

            # Store to act_aware_behaviors index
            doc = behavior.model_dump()
            doc["window_start"] = behavior.window_start.isoformat()
            doc["window_end"] = behavior.window_end.isoformat()
            self.es.store_behavior(behavior.behavior_id, doc)
            aggregated_records.append(behavior)

        logger.info(
            f"Aggregated {len(sorted_events)} events into {len(aggregated_records)} behavioral entities "
            f"in index {settings.ES_INDEX_BEHAVIORS}"
        )
        return aggregated_records

    def _calculate_features(
        self, events: List[UniversalEvent], duration_minutes: float
    ) -> BehaviorFeatures:
        feat = BehaviorFeatures()

        login_fails = 0
        login_success = 0
        unique_ips = set()
        unique_dests = set()
        unique_ports = set()
        processes = set()
        suspicious_proc_count = 0
        unique_hosts = set()
        unique_resources = set()
        sensitive_res_count = 0
        priv_esc = 0
        admin_actions = 0
        failed_priv = 0
        hours_active = set()
        after_hours = False
        weekend = False
        db_queries = 0
        db_rows = 0
        db_fails = 0
        outbound_bytes = 0.0
        inbound_bytes = 0.0

        for e in events:
            # Login tracking
            if e.event_type == "login":
                if e.action == "failure" or e.outcome == "failure":
                    login_fails += 1
                elif e.action in ("success", "login") or e.outcome == "success":
                    login_success += 1

            # Network
            if e.ip:
                unique_ips.add(e.ip)
            if e.destination_ip:
                unique_dests.add(e.destination_ip)
            if e.destination_port:
                unique_ports.add(e.destination_port)

            bytes_sent = e.metadata.get("bytes_sent") or e.metadata.get("data_volume_bytes", 0)
            if bytes_sent:
                outbound_bytes += float(bytes_sent)

            # Process
            if e.process_name:
                processes.add(e.process_name.lower())
                if e.process_name.lower() in SUSPICIOUS_PROCESSES or e.metadata.get("suspicious"):
                    suspicious_proc_count += 1

            # Resources & Hosts
            if e.host:
                unique_hosts.add(e.host)
            if e.resource:
                res_low = e.resource.lower()
                unique_resources.add(res_low)
                if any(sens in res_low for sens in SENSITIVE_RESOURCES):
                    sensitive_res_count += 1

            # Privilege
            if e.action == "escalate" or e.event_type == "privilege":
                priv_esc += 1
            if e.user_privilege_level == "admin" or e.action == "escalate":
                admin_actions += 1
            if e.outcome == "failure" and e.user_privilege_level == "admin":
                failed_priv += 1

            # Temporal
            hour = e.timestamp.hour
            hours_active.add(hour)
            if hour < 8 or hour > 20:
                after_hours = True
            if e.timestamp.weekday() >= 5:
                weekend = True

            # Database
            if e.event_type == "database":
                db_queries += 1
                db_rows += int(e.metadata.get("rows_returned", 0))
                if e.outcome == "failure":
                    db_fails += 1

        # Calculate ratios and velocities
        total_logins = login_fails + login_success
        feat.login_fail_count = login_fails
        feat.login_success_count = login_success
        feat.login_fail_ratio = (login_fails / total_logins) if total_logins > 0 else 0.0

        feat.event_rate_per_minute = len(events) / duration_minutes
        feat.login_attempt_velocity = total_logins / duration_minutes
        feat.data_transfer_rate = outbound_bytes / duration_minutes
        feat.process_spawn_rate = len(processes) / duration_minutes

        feat.unique_ips_accessed = len(unique_ips)
        feat.unique_destinations = len(unique_dests)
        feat.unique_ports_used = len(unique_ports)
        feat.outbound_data_volume = outbound_bytes
        feat.inbound_data_volume = inbound_bytes

        feat.process_count = len(events)
        feat.unique_process_names = len(processes)
        feat.suspicious_process_count = suspicious_proc_count

        feat.unique_hosts_accessed = len(unique_hosts)
        feat.unique_resources_accessed = len(unique_resources)
        feat.sensitive_resource_access_count = sensitive_res_count

        feat.privilege_escalation_attempts = priv_esc
        feat.admin_action_count = admin_actions
        feat.failed_privilege_actions = failed_priv

        feat.after_hours_activity = after_hours
        feat.weekend_activity = weekend
        feat.activity_hour_spread = len(hours_active)

        feat.db_query_count = db_queries
        feat.db_failed_query_count = db_fails
        feat.db_rows_accessed = db_rows

        return feat


aggregator = SlidingWindowAggregator()
