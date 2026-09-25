# layer1_ingestion/normalizer.py
"""
Layer 1-2: Normalization & ECS Mapping Engine
Normalizes raw heterogeneous logs from Winlogbeat, Filebeat, Syslog, and DB
into the UniversalEvent schema (ECS compliant).
Populates both 'timestamp' and '@timestamp' for Elasticsearch compatibility.
"""

from typing import Dict, Any, Tuple, Optional
from datetime import datetime, timezone
from config.schemas import UniversalEvent, utc_now
from storage.es_client import es_client
from config.settings import settings
import logging

logger = logging.getLogger(__name__)


class LogNormalizer:
    def __init__(self, pipeline_id: Optional[str] = None):
        self.pipeline_id = pipeline_id

    def normalize(self, raw_log: Dict[str, Any], pipeline_id: Optional[str] = None) -> UniversalEvent:
        pid = pipeline_id or self.pipeline_id or str(utc_now().timestamp())
        errors = []

        # Parse or ensure timezone-aware timestamp
        ts = raw_log.get("timestamp") or raw_log.get("@timestamp")
        if isinstance(ts, str):
            try:
                # Replace trailing 'Z' if present for ISO parsing
                if ts.endswith("Z"):
                    ts = ts[:-1] + "+00:00"
                parsed_ts = datetime.fromisoformat(ts)
                if parsed_ts.tzinfo is None:
                    parsed_ts = parsed_ts.replace(tzinfo=timezone.utc)
            except Exception as e:
                errors.append(f"Invalid timestamp format: {e}")
                parsed_ts = utc_now()
        elif isinstance(ts, datetime):
            parsed_ts = ts if ts.tzinfo is not None else ts.replace(tzinfo=timezone.utc)
        else:
            errors.append("Missing timestamp field")
            parsed_ts = utc_now()

        # Port validation
        dest_port = raw_log.get("destination_port")
        if dest_port is not None:
            try:
                dest_port = int(dest_port)
                if not (0 <= dest_port <= 65535):
                    errors.append(f"Port {dest_port} out of range (0-65535)")
                    dest_port = None
            except Exception:
                errors.append(f"Invalid port value: {dest_port}")
                dest_port = None

        source = raw_log.get("source", "custom")
        event_type = raw_log.get("event_type", "login")
        action = raw_log.get("action", "success")
        severity = raw_log.get("severity", "low")

        is_valid = len(errors) == 0

        event_data = {
            "pipeline_id": pid,
            "timestamp": parsed_ts,
            "ingested_at": utc_now(),
            "source": source,
            "source_file": raw_log.get("source_file"),
            "event_type": event_type,
            "severity": severity,
            "user": raw_log.get("user"),
            "user_domain": raw_log.get("user_domain", "CORP"),
            "user_privilege_level": raw_log.get("user_privilege_level", "standard"),
            "host": raw_log.get("host"),
            "host_os": raw_log.get("host_os", "windows"),
            "ip": raw_log.get("ip"),
            "destination_ip": raw_log.get("destination_ip"),
            "destination_port": dest_port,
            "geo_country": raw_log.get("geo_country"),
            "action": action,
            "resource": raw_log.get("resource"),
            "process_name": raw_log.get("process_name"),
            "process_id": raw_log.get("process_id"),
            "parent_process": raw_log.get("parent_process"),
            "outcome": raw_log.get("outcome", "success" if action == "success" else "unknown"),
            "error_code": raw_log.get("error_code"),
            "is_valid": is_valid,
            "validation_errors": errors,
            "metadata": raw_log.get("metadata", {}),
        }

        # Build UniversalEvent model
        event = UniversalEvent(**event_data)
        return event

    def ingest_event(self, raw_log: Dict[str, Any], pipeline_id: Optional[str] = None) -> UniversalEvent:
        event = self.normalize(raw_log, pipeline_id=pipeline_id)
        doc = event.model_dump()
        doc["timestamp"] = event.timestamp.isoformat()
        doc["ingested_at"] = event.ingested_at.isoformat()
        doc["@timestamp"] = event.timestamp.isoformat()  # ECS standard index field

        if event.is_valid:
            es_client.store_event(event.event_id, doc)
        else:
            es_client.index_document("soc-dead-letter", event.event_id, doc)
            logger.warning(f"Event {event.event_id} flagged invalid and routed to soc-dead-letter")

        return event


normalizer = LogNormalizer()
