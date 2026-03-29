# pipeline/full_pipeline.py
# Complete single-machine pipeline.
# Takes any dataset file or directory.
# Runs all layers sequentially on localhost.
# Produces fidelity scores and playbooks.
#
# Usage:
#   python pipeline/full_pipeline.py --data /path/to/dataset
#   python pipeline/full_pipeline.py --data /path/to/file.csv
#   python pipeline/full_pipeline.py --synthetic  (uses generated data)

import os
import sys
import json
import csv
import re
import argparse
import time
import hashlib
import pickle
import numpy as np
import pandas as pd
import networkx as nx

sys.path.append(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)

from datetime import datetime, timezone, timedelta
from uuid import uuid4
from pathlib import Path
from elasticsearch import Elasticsearch
from loguru import logger
from dotenv import load_dotenv

load_dotenv()

# ── GLOBALS ───────────────────────────────────────────────────

ES = Elasticsearch(
    f"http://{os.getenv('ES_HOST','localhost')}:"
    f"{os.getenv('ES_PORT','9200')}",
    basic_auth=(
        os.getenv('ES_USERNAME','elastic'),
        os.getenv('ES_PASSWORD','actaware123')
    )
)

PIPELINE_ID = str(uuid4())

def utc_now():
    return datetime.now(timezone.utc)

def utc_str():
    return utc_now().isoformat()

def ensure_indices_exist():
    """Creates all required ES indices if they don't exist."""
    indices = {
        "act_aware_events": {
            "mappings": {
                "properties": {
                    "timestamp": {"type": "date"},
                    "event_type": {"type": "keyword"},
                    "source_ip": {"type": "ip"},
                    "dest_ip": {"type": "ip"},
                    "user": {"type": "keyword"},
                    "incident_id": {"type": "keyword"},
                    "severity": {"type": "keyword"},
                    "host": {"type": "keyword"},
                    "action": {"type": "keyword"},
                }
            }
        },
        "act_aware_behaviors": {},
        "act_aware_detections": {},
        "act_aware_incidents": {},
        "act_aware_fidelity": {},
        "act_aware_playbooks": {},
        "act_aware_provenance": {},
    }
    
    for index_name, settings in indices.items():
        try:
            if not ES.indices.exists(index=index_name):
                ES.indices.create(index=index_name, body=settings)
                logger.info(f"Created index: {index_name}")
        except Exception as e:
            logger.warning(f"Could not create {index_name}: {e}")
# ════════════════════════════════════════════════════════════
# LAYER 1-2: INGESTION
# Handles JSON, CSV, syslog, kv, tsv, xml, free text
# Deduplicates, normalizes timestamps, maps field aliases
# ════════════════════════════════════════════════════════════

FIELD_ALIASES = {
    "timestamp":      ["ts","time","datetime","event_time",
                       "log_time","@timestamp","date",
                       "TimeCreated","time_generated",
                       "occurred_at","created_at","eventtime"],
    "source":         ["src","source_system","log_source",
                       "collector","agent","provider",
                       "SourceName","channel"],
    "event_type":     ["type","category","event_category",
                       "log_type","alert_type","EventID",
                       "event_id","evtid","action_type"],
    "user":           ["username","user_name","userid",
                       "user_id","account","actor",
                       "SubjectUserName","TargetUserName",
                       "initiator","principal"],
    "host":           ["hostname","host_name","machine",
                       "computer","device","node",
                       "ComputerName","workstation","endpoint"],
    "ip":             ["src_ip","source_ip","ip_address",
                       "client_ip","IpAddress","remote_addr",
                       "source_address","srcip"],
    "destination_ip": ["dst_ip","dest_ip","target_ip",
                       "remote_ip","DestinationIp","dstip"],
    "action":         ["event_action","activity","operation",
                       "verb","method","EventType","task"],
    "resource":       ["object","target","file","path",
                       "ObjectName","url","endpoint","service"],
    "severity":       ["level","priority","risk_level",
                       "alert_level","EventLevel","importance"],
    "outcome":        ["result","status","EventResult",
                       "SubStatus","disposition"],
    "destination_port":["dst_port","dport","dest_port","port"],
    "process_name":   ["proc","process","image","ImagePath",
                       "NewProcessName","app"],
}

ALIAS_LOOKUP = {}
for canon, aliases in FIELD_ALIASES.items():
    for a in aliases:
        ALIAS_LOOKUP[a.lower()] = canon
    ALIAS_LOOKUP[canon.lower()] = canon

SEVERITY_MAP = {
    "0":"low","1":"low","2":"medium","3":"medium",
    "4":"high","5":"critical","information":"low",
    "informational":"low","warning":"medium","warn":"medium",
    "error":"high","critical":"critical","audit failure":"high",
    "audit success":"low","debug":"low","info":"low",
    "notice":"low","err":"high","alert":"critical",
    "emerg":"critical","low":"low","medium":"medium",
    "high":"high","severe":"critical","none":"low",
}

EVENT_TYPE_MAP = {
    "4624":"login","4625":"login","4634":"login",
    "4648":"login","4672":"privilege","4688":"process",
    "4689":"process","4663":"file","4660":"file",
    "3":"network","5156":"network","logon":"login",
    "authentication":"login","login":"login","logout":"login",
    "process_create":"process","exec":"process",
    "network_connect":"network","connection":"network",
    "firewall":"network","dns":"dns","file_create":"file",
    "file_delete":"file","file_read":"file",
    "privilege_use":"privilege","escalation":"privilege",
    "audit_table":"database","db_query":"database",
    "sql":"database","database":"database","api":"api_call",
}

ACTION_MAP = {
    "success":"success","succeeded":"success","allowed":"success",
    "failure":"failure","failed":"failure","denied":"failure",
    "blocked":"failure","drop":"failure","reject":"failure",
    "exec":"exec","execute":"exec","run":"exec",
    "read":"read","open":"read","get":"read",
    "write":"write","modify":"write","put":"write",
    "delete":"delete","remove":"delete",
    "escalate":"escalate","elevate":"escalate",
    "connect":"connect","established":"connect",
    "disconnect":"disconnect","closed":"disconnect",
    "4624":"success","4625":"failure","4688":"exec",
    "4663":"read","4672":"escalate",
}

_seen_hashes = set()

def _hash_event(d: dict) -> str:
    parts = [
        str(d.get(f,"")).lower().strip()
        for f in ["user","host","ip","action",
                  "resource","event_type"]
    ]
    ts = str(d.get("timestamp",""))[:16]
    parts.append(ts)
    return hashlib.sha256("|".join(parts).encode()).hexdigest()

def _fix_ts(raw_ts):
    now = utc_now()
    if not raw_ts:
        return utc_str(), ["missing_timestamp"]

    formats = [
        "%Y-%m-%dT%H:%M:%S.%fZ","%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S%z","%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S","%Y-%m-%d %H:%M:%S.%f",
        "%b %d %H:%M:%S","%b  %d %H:%M:%S",
        "%d/%b/%Y:%H:%M:%S %z","%m/%d/%Y %H:%M:%S",
        "%m/%d/%Y %I:%M:%S %p",
    ]

    parsed = None
    for fmt in formats:
        try:
            parsed = datetime.strptime(str(raw_ts).strip(), fmt)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            break
        except ValueError:
            continue

    if parsed is None:
        try:
            f = float(raw_ts)
            if f > 1e12:
                f /= 1000
            parsed = datetime.fromtimestamp(f, tz=timezone.utc)
        except Exception:
            return utc_str(), ["unparseable_timestamp"]

    flags = []
    if parsed > now + timedelta(seconds=300):
        flags.append("future_timestamp")
        parsed = now
    elif parsed < now - timedelta(days=30):
        flags.append("old_timestamp")

    return parsed.isoformat(), flags

def _normalize_raw(raw: dict) -> dict:
    out = {}
    for k, v in raw.items():
        canon = ALIAS_LOOKUP.get(k.lower(), k)
        out[canon] = v

    if "severity" in out:
        out["severity"] = SEVERITY_MAP.get(
            str(out["severity"]).lower().strip(), "low"
        )
    if "event_type" in out:
        et = str(out["event_type"]).lower()
        out["event_type"] = EVENT_TYPE_MAP.get(
            et, et if et in [
                "login","process","network","file",
                "dns","privilege","api_call","database"
            ] else "login"
        )
    elif "event_id" in out:
        out["event_type"] = EVENT_TYPE_MAP.get(
            str(out.get("event_id","")), "login"
        )

    if "action" not in out:
        eid = str(out.get("event_id",""))
        if eid in ACTION_MAP:
            out["action"] = ACTION_MAP[eid]
        else:
            outcome = str(out.get("outcome","")).lower()
            out["action"] = ACTION_MAP.get(outcome, "exec")
    else:
        out["action"] = ACTION_MAP.get(
            str(out["action"]).lower(), "exec"
        )

    return out

def parse_line(raw: str, source_hint: str = "unknown") -> dict:
    raw = raw.strip()
    if not raw:
        return None

    # Try JSON
    if raw.startswith("{"):
        try:
            d = json.loads(raw)
        except Exception:
            try:
                d = json.loads(
                    re.sub(r",\s*([}\]])", r"\1", raw)
                )
            except Exception:
                d = {"message": raw}
    # Try syslog
    elif re.match(r"^<\d+>", raw):
        m = re.match(
            r"<(\d+)>(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(.*)",
            raw
        )
        if m:
            d = {
                "timestamp": m.group(2),
                "host": m.group(3),
                "message": m.group(4),
                "source": "syslog"
            }
            # Extract user from message
            um = re.search(
                r"for (\S+) from (\S+)", m.group(4)
            )
            if um:
                d["user"] = um.group(1)
                d["ip"] = um.group(2)
                d["action"] = "failure"
                d["event_type"] = "login"
        else:
            d = {"message": raw, "source": "syslog"}
    # Try key=value
    elif raw.count("=") >= 3:
        d = {}
        for m in re.finditer(
            r'(\w+)=(?:"([^"]*)"|([\S]*))', raw
        ):
            d[m.group(1)] = m.group(2) or m.group(3)
        if not d:
            d = {"message": raw}
    # Try CSV
    elif raw.count(",") >= 2 or raw.count("\t") >= 2:
        delim = "\t" if raw.count("\t") >= raw.count(",") \
                else ","
        parts = [p.strip().strip('"') for p in raw.split(delim)]
        if len(parts) >= 3:
            # Check if it's a header row
            if all(
                re.match(r'^[a-zA-Z_][a-zA-Z0-9_\s]*$', p)
                for p in parts
            ):
                return None  # Skip header
            d = {
                "timestamp": parts[0] if len(parts) > 0 else None,
                "host":      parts[1] if len(parts) > 1 else None,
                "user":      parts[2] if len(parts) > 2 else None,
                "action":    parts[3] if len(parts) > 3 else None,
                "resource":  parts[4] if len(parts) > 4 else None,
            }
        else:
            d = {"message": raw}
    # Windows XML
    elif "<Event" in raw or "<EventID" in raw:
        d = {}
        for field, pattern in [
            ("event_id", r"<EventID[^>]*>(\d+)</EventID>"),
            ("timestamp", r"SystemTime='([^']+)'"),
            ("host", r"<Computer>([^<]+)</Computer>"),
            ("user", r"Name='SubjectUserName'>([^<]+)<"),
            ("process_name", r"Name='NewProcessName'>([^<]+)<"),
            ("source", r"<Provider Name='([^']+)'"),
        ]:
            m = re.search(pattern, raw)
            if m:
                d[field] = m.group(1)
    # Free text
    else:
        d = {"message": raw, "source": source_hint}
        ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", raw)
        if ips:
            d["ip"] = ips[0]
            if len(ips) > 1:
                d["destination_ip"] = ips[1]
        m = re.search(
            r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}", raw
        )
        if m:
            d["timestamp"] = m.group(0)
        for kw in ["failed","denied","blocked",
                   "success","allowed","exec"]:
            if kw in raw.lower():
                d["action"] = ACTION_MAP.get(kw, "exec")
                break
        for kw in ["login","logon","auth","process",
                   "network","file","dns"]:
            if kw in raw.lower():
                d["event_type"] = EVENT_TYPE_MAP.get(
                    kw, "login"
                )
                break

    normalized = _normalize_raw(d)

    # Dedup
    h = _hash_event(normalized)
    if h in _seen_hashes:
        return None
    _seen_hashes.add(h)

    # Fix timestamp
    raw_ts = normalized.get("timestamp")
    ts, flags = _fix_ts(raw_ts)
    normalized["timestamp"] = ts

    validation_errors = []
    if not normalized.get("event_type"):
        validation_errors.append("missing_event_type")
        normalized["event_type"] = "login"
    if not normalized.get("action"):
        validation_errors.append("missing_action")
        normalized["action"] = "exec"

    event = {
        "schema_version": "1.1.0",
        "pipeline_id": PIPELINE_ID,
        "event_id": str(uuid4()),
        "timestamp": ts,
        "ingested_at": utc_str(),
        "source": normalized.get("source") or source_hint,
        "event_type": normalized.get("event_type","login"),
        "severity": normalized.get("severity","low"),
        "user": normalized.get("user"),
        "host": normalized.get("host"),
        "ip": normalized.get("ip"),
        "destination_ip": normalized.get("destination_ip"),
        "destination_port": (
            int(normalized["destination_port"])
            if normalized.get("destination_port") else None
        ),
        "action": normalized.get("action","exec"),
        "resource": normalized.get("resource"),
        "process_name": normalized.get("process_name"),
        "outcome": normalized.get("outcome"),
        "is_valid": len(validation_errors) == 0,
        "validation_errors": validation_errors,
        "metadata": {
            "original_timestamp": str(raw_ts),
            "timestamp_flags": flags,
            "raw_message": normalized.get("message",""),
        }
    }

    return event

def ingest_file(filepath: str) -> list:
    """Ingests any file format and returns list of events."""
    events = []
    path = Path(filepath)
    source_hint = path.suffix.lstrip(".") or "unknown"

    try:
        with open(filepath, "r", encoding="utf-8",
                  errors="replace") as f:
            content = f.read()
    except Exception as e:
        logger.error(f"Cannot read {filepath}: {e}")
        return []

    # Try JSON array
    if content.strip().startswith("["):
        try:
            records = json.loads(content)
            for r in records:
                raw = json.dumps(r)
                event = parse_line(raw, source_hint)
                if event:
                    events.append(event)
            return events
        except Exception:
            pass

    # Try CSV with header detection
    if filepath.endswith(".csv") or "," in content.split("\n")[0]:
        lines = content.split("\n")
        if lines:
            first = lines[0].strip()
            # Detect header
            has_header = all(
                re.match(r'^[a-zA-Z_\s][a-zA-Z0-9_\s]*$', p.strip())
                for p in first.split(",")
                if p.strip()
            )
            if has_header:
                # Parse with DictReader
                try:
                    reader = csv.DictReader(
                        content.splitlines()
                    )
                    for row in reader:
                        raw = json.dumps(dict(row))
                        event = parse_line(raw, source_hint)
                        if event:
                            events.append(event)
                    return events
                except Exception:
                    pass

    # Line by line for everything else
    for line in content.split("\n"):
        if not line.strip():
            continue
        event = parse_line(line.strip(), source_hint)
        if event:
            events.append(event)

    return events

def ingest_directory(dirpath: str) -> list:
    """Ingests all files in a directory."""
    all_events = []
    extensions = {
        ".json",".csv",".log",".txt",".syslog",
        ".tsv",".xml",""
    }

    for root, dirs, files in os.walk(dirpath):
        for fname in files:
            fpath = os.path.join(root, fname)
            ext = Path(fname).suffix.lower()
            if ext in extensions or not ext:
                logger.info(f"Ingesting: {fpath}")
                events = ingest_file(fpath)
                all_events.extend(events)
                logger.info(
                    f"  → {len(events)} events from {fname}"
                )

    # Sort by timestamp after ingesting all files
    all_events.sort(key=lambda e: e.get("timestamp",""))
    return all_events

def push_events_to_es(events: list) -> int:
    """Pushes events to Elasticsearch in bulk."""
    pushed = 0
    batch = []

    for event in events:
        batch.append({
            "index": {
                "_index": os.getenv(
                    "ES_INDEX_EVENTS","act_aware_events"
                ),
                "_id": event["event_id"]
            }
        })
        batch.append(event)

        if len(batch) >= 200:
            try:
                ES.bulk(operations=batch, refresh=False)
                pushed += len(batch) // 2
            except Exception as e:
                logger.error(f"Bulk push error: {e}")
            batch = []

    if batch:
        try:
            ES.bulk(operations=batch, refresh=True)
            pushed += len(batch) // 2
        except Exception as e:
            logger.error(f"Final bulk push error: {e}")

    return pushed


# ════════════════════════════════════════════════════════════
# LAYER 3-5: AGGREGATION + FEATURE ENGINEERING
# Aggregates events per entity into behavioral windows
# Extracts features for anomaly detection
# ════════════════════════════════════════════════════════════

def aggregate_behaviors() -> list:
    """
    Reads events from ES, aggregates per entity
    into 1-hour behavioral windows.
    Returns list of AggregatedBehavior dicts.
    """
    # Fetch all valid events
    result = ES.search(
        index=os.getenv("ES_INDEX_EVENTS","act_aware_events"),
        body={
            "query": {"term": {"is_valid": True}},
            "size": 10000,
            "sort": [{"timestamp": {"order": "asc"}}]
        }
    )

    events = [h["_source"] for h in result["hits"]["hits"]]
    if not events:
        logger.warning("No valid events to aggregate")
        return []

    # Group by entity (user or host) and 1-hour window
    entity_windows = {}

    for event in events:
        entity = (
            event.get("user") or
            event.get("host") or
            event.get("ip") or
            "unknown"
        )
        if entity == "unknown":
            continue

        # Get hour window
        try:
            ts = datetime.fromisoformat(
                event["timestamp"].replace("Z","+00:00")
            )
            window_start = ts.replace(
                minute=0, second=0, microsecond=0
            )
            window_end = window_start + timedelta(hours=1)
        except Exception:
            continue

        key = f"{entity}|{window_start.isoformat()}"
        if key not in entity_windows:
            entity_windows[key] = {
                "entity": entity,
                "entity_type": (
                    "user" if event.get("user") == entity
                    else "host"
                ),
                "window_start": window_start,
                "window_end": window_end,
                "events": []
            }
        entity_windows[key]["events"].append(event)

    # Compute features for each window
    behaviors = []
    for key, window in entity_windows.items():
        evts = window["events"]
        behavior = _compute_features(window, evts)
        behaviors.append(behavior)

    # Push to ES
    for b in behaviors:
        try:
            ES.index(
                index=os.getenv(
                    "ES_INDEX_BEHAVIORS","act_aware_behaviors"
                ),
                id=b["behavior_id"],
                document=b,
                refresh=False
            )
        except Exception as e:
            logger.error(f"Behavior push error: {e}")

    ES.indices.refresh(index=os.getenv(
        "ES_INDEX_BEHAVIORS","act_aware_behaviors"
    ))

    logger.info(
        f"Aggregated {len(behaviors)} behavioral windows "
        f"from {len(events)} events"
    )
    return behaviors

def _compute_features(window: dict, evts: list) -> dict:
    """Computes behavioral features for one entity window."""
    logins = [e for e in evts if e.get("event_type") == "login"]
    processes = [
        e for e in evts if e.get("event_type") == "process"
    ]
    network = [
        e for e in evts if e.get("event_type") == "network"
    ]
    files = [e for e in evts if e.get("event_type") == "file"]
    db = [e for e in evts if e.get("event_type") == "database"]
    priv = [
        e for e in evts if e.get("event_type") == "privilege"
    ]

    failures = [
        e for e in evts if e.get("action") == "failure"
    ]
    successes = [
        e for e in evts if e.get("action") == "success"
    ]

    total = len(evts)
    duration_minutes = 60.0

    # Detect after-hours (before 8am or after 8pm)
    ws = window["window_start"]
    after_hours = ws.hour < 8 or ws.hour >= 20
    weekend = ws.weekday() >= 5

    # Unique IPs and hosts
    unique_ips = len(set(
        e.get("destination_ip","") or e.get("ip","")
        for e in network if e.get("destination_ip")
    ))
    unique_hosts = len(set(
        e.get("host","") for e in evts if e.get("host")
    ))
    unique_resources = len(set(
        e.get("resource","")
        for e in evts if e.get("resource")
    ))

    # Suspicious processes
    suspicious_procs = {
        "mimikatz","psexec","wscript","cscript",
        "powershell","cmd","net.exe","whoami",
        "certutil","bitsadmin","regsvr32",
        "mshta","rundll32","nc","ncat","netcat"
    }
    susp_count = sum(
        1 for e in processes
        if any(s in (e.get("process_name","") or "").lower()
               for s in suspicious_procs)
    )

    login_fails = len([
        e for e in logins if e.get("action") == "failure"
    ])
    login_success = len([
        e for e in logins if e.get("action") == "success"
    ])
    total_logins = login_fails + login_success
    fail_ratio = (
        login_fails / total_logins if total_logins > 0 else 0.0
    )

    priv_escalations = len([
        e for e in evts
        if e.get("action") == "escalate" or
           e.get("event_type") == "privilege"
    ])

    sensitive_resources = {
        "/etc/passwd","/etc/shadow","sam","ntds",
        "lsass","id_rsa","credentials","password",
        "secret","token","key","payroll","finance",
        "transaction","account","customer"
    }
    sensitive_count = sum(
        1 for e in evts
        if any(s in (e.get("resource","") or "").lower()
               for s in sensitive_resources)
    )

    # Outbound data volume (rough estimate from network events)
    outbound = len([
        e for e in network
        if e.get("action") == "connect"
    ]) * 100.0  # 100 bytes per connection as estimate

    return {
        "schema_version": "1.1.0",
        "pipeline_id": PIPELINE_ID,
        "behavior_id": str(uuid4()),
        "entity_id": window["entity"],
        "entity_type": window["entity_type"],
        "window_start": window["window_start"].isoformat(),
        "window_end": window["window_end"].isoformat(),
        "time_window": "1hr",
        "event_count": total,
        "source_event_ids": [
            e["event_id"] for e in evts
        ],
        "features": {
            "login_fail_count": login_fails,
            "login_success_count": login_success,
            "login_fail_ratio": round(fail_ratio, 4),
            "event_rate_per_minute": round(
                total / duration_minutes, 4
            ),
            "login_attempt_velocity": round(
                total_logins / duration_minutes, 4
            ),
            "data_transfer_rate": round(
                outbound / duration_minutes, 4
            ),
            "process_spawn_rate": round(
                len(processes) / duration_minutes, 4
            ),
            "unique_ips_accessed": unique_ips,
            "unique_destinations": unique_ips,
            "outbound_data_volume": outbound,
            "unique_ports_used": len(set(
                str(e.get("destination_port",""))
                for e in network
                if e.get("destination_port")
            )),
            "process_count": len(processes),
            "unique_process_names": len(set(
                e.get("process_name","")
                for e in processes
                if e.get("process_name")
            )),
            "suspicious_process_count": susp_count,
            "unique_hosts_accessed": unique_hosts,
            "unique_resources_accessed": unique_resources,
            "sensitive_resource_access_count": sensitive_count,
            "privilege_escalation_attempts": priv_escalations,
            "admin_action_count": len(priv),
            "failed_privilege_actions": len([
                e for e in priv
                if e.get("action") == "failure"
            ]),
            "after_hours_activity": after_hours,
            "weekend_activity": weekend,
            "activity_hour_spread": 1,
            "file_read_count": len([
                e for e in files
                if e.get("action") == "read"
            ]),
            "file_write_count": len([
                e for e in files
                if e.get("action") == "write"
            ]),
            "file_delete_count": len([
                e for e in files
                if e.get("action") == "delete"
            ]),
            "unique_file_extensions": len(set(
                Path(e.get("resource","")).suffix
                for e in files
                if e.get("resource")
            )),
            "db_query_count": len(db),
            "db_failed_query_count": len([
                e for e in db
                if e.get("action") == "failure"
            ]),
            "db_rows_accessed": len(db) * 10,
            "dns_query_count": len([
                e for e in evts
                if e.get("event_type") == "dns"
            ]),
            "unique_dns_domains": 0,
            "suspicious_dns_count": 0,
        }
    }


# ════════════════════════════════════════════════════════════
# LAYER 6-7: DETECTION + CORRELATION + GRAPH
# Runs PyOD on behavioral features
# Correlates anomalous entities into incidents
# Builds networkx attack graph
# ════════════════════════════════════════════════════════════

FEATURE_COLS = [
    "login_fail_count","login_success_count",
    "login_fail_ratio","event_rate_per_minute",
    "login_attempt_velocity","data_transfer_rate",
    "process_spawn_rate","unique_ips_accessed",
    "unique_destinations","outbound_data_volume",
    "unique_ports_used","process_count",
    "unique_process_names","suspicious_process_count",
    "unique_hosts_accessed","unique_resources_accessed",
    "sensitive_resource_access_count",
    "privilege_escalation_attempts","admin_action_count",
    "failed_privilege_actions","activity_hour_spread",
    "file_read_count","file_write_count",
    "file_delete_count","db_query_count",
    "db_rows_accessed","dns_query_count",
]

def run_detection(behaviors: list) -> list:
    """
    Runs PyOD anomaly detection on behavioral features.
    Returns list of DetectionOutput dicts.
    """
    if len(behaviors) < 2:
        logger.warning(
            "Not enough behaviors for ML detection. "
            "Need at least 2."
        )
        return _rule_based_detection(behaviors)

    # Build feature matrix
    rows = []
    for b in behaviors:
        feats = b.get("features", {})
        row = []
        for col in FEATURE_COLS:
            val = feats.get(col, 0)
            if isinstance(val, bool):
                val = int(val)
            row.append(float(val) if val else 0.0)
        rows.append(row)

    X = np.array(rows, dtype=np.float64)

    # Replace NaN/inf
    X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)

    detections = []

    models_to_run = {}

    # Try loading pre-trained models, else fit on the fly
    model_dir = Path("detection/models")
    for model_name in ["isolation_forest","lof","hbos"]:
        model_path = model_dir / f"{model_name}.pkl"
        if model_path.exists():
            try:
                with open(model_path,"rb") as f:
                    models_to_run[model_name] = pickle.load(f)
                logger.info(f"Loaded pre-trained {model_name}")
            except Exception:
                models_to_run[model_name] = None
        else:
            models_to_run[model_name] = None

    # Import PyOD
    try:
        from pyod.models.iforest import IForest
        from pyod.models.lof import LOF
        from pyod.models.hbos import HBOS
        pyod_available = True
    except ImportError:
        pyod_available = False
        logger.warning(
            "PyOD not available. Using rule-based detection."
        )

    if not pyod_available:
        return _rule_based_detection(behaviors)

    model_classes = {
        "isolation_forest": IForest(
            n_estimators=100, contamination=0.1,
            random_state=42
        ),
        "lof": LOF(n_neighbors=min(5, len(behaviors)-1),
                   contamination=0.1),
        "hbos": HBOS(n_bins=5, contamination=0.1),
    }

    for model_name, pretrained in models_to_run.items():
        model = pretrained or model_classes[model_name]

        try:
            if pretrained is None:
                model.fit(X)

            # Get scores
            if pretrained:
                scores = model.decision_function(X)
            else:
                scores = model.decision_scores_
                labels = model.labels_

            # Normalize scores to 0-1
            s_min, s_max = scores.min(), scores.max()
            if s_max > s_min:
                norm_scores = (scores - s_min) / (s_max - s_min)
            else:
                norm_scores = np.zeros_like(scores)

            threshold = 0.65

            for i, b in enumerate(behaviors):
                score = float(norm_scores[i])
                raw_score = float(scores[i])
                margin = score - threshold
                label = "anomaly" if score > threshold \
                    else "normal"

                severity = (
                    "critical" if score > 0.90 else
                    "high" if score > 0.75 else
                    "medium" if score > 0.60 else "low"
                )

                # Top contributing features
                feature_vals = np.array([
                    b["features"].get(c,0)
                    for c in FEATURE_COLS
                ], dtype=float)
                top_idx = np.argsort(feature_vals)[::-1][:5]
                top_features = [
                    FEATURE_COLS[j] for j in top_idx
                    if feature_vals[j] > 0
                ]

                det = {
                    "schema_version": "1.1.0",
                    "pipeline_id": PIPELINE_ID,
                    "detection_id": str(uuid4()),
                    "behavior_id": b["behavior_id"],
                    "entity_id": b["entity_id"],
                    "entity_type": b["entity_type"],
                    "window_start": b["window_start"],
                    "window_end": b["window_end"],
                    "detected_at": utc_str(),
                    "model": model_name,
                    "model_version": "1.0",
                    "anomaly_score": round(score, 4),
                    "raw_score": round(raw_score, 4),
                    "threshold_used": threshold,
                    "score_margin": round(margin, 4),
                    "label": label,
                    "severity": severity,
                    "features_used": {
                        c: b["features"].get(c,0)
                        for c in FEATURE_COLS
                    },
                    "top_contributing_features": top_features,
                }

                detections.append(det)

                ES.index(
                    index=os.getenv(
                        "ES_INDEX_DETECTIONS",
                        "act_aware_detections"
                    ),
                    id=det["detection_id"],
                    document=det,
                    refresh=False
                )

        except Exception as e:
            logger.error(
                f"Detection error for {model_name}: {e}"
            )
            continue

    ES.indices.refresh(index=os.getenv(
        "ES_INDEX_DETECTIONS","act_aware_detections"
    ))

    logger.info(
        f"Detection: {len(detections)} scores from "
        f"{len(behaviors)} behaviors"
    )
    return detections

def _rule_based_detection(behaviors: list) -> list:
    """
    Fallback when PyOD unavailable.
    Uses threshold rules on key features.
    Still produces valid DetectionOutput.
    """
    detections = []
    for b in behaviors:
        f = b.get("features", {})

        # Compute rule-based score
        score = 0.0
        score += min(0.3, f.get("login_fail_count",0) / 20)
        score += min(0.2, f.get("login_fail_ratio",0))
        score += min(0.2, f.get("privilege_escalation_attempts",0) * 0.1)
        score += min(0.15, f.get("sensitive_resource_access_count",0) * 0.05)
        score += min(0.1, f.get("suspicious_process_count",0) * 0.05)
        if f.get("after_hours_activity"):
            score += 0.05

        score = min(1.0, score)
        threshold = 0.30
        label = "anomaly" if score > threshold else "normal"

        top_features = sorted(
            FEATURE_COLS,
            key=lambda c: float(f.get(c,0)),
            reverse=True
        )[:5]

        det = {
            "schema_version": "1.1.0",
            "pipeline_id": PIPELINE_ID,
            "detection_id": str(uuid4()),
            "behavior_id": b["behavior_id"],
            "entity_id": b["entity_id"],
            "entity_type": b["entity_type"],
            "window_start": b["window_start"],
            "window_end": b["window_end"],
            "detected_at": utc_str(),
            "model": "rule_based",
            "model_version": "1.0",
            "anomaly_score": round(score, 4),
            "raw_score": round(score, 4),
            "threshold_used": threshold,
            "score_margin": round(score - threshold, 4),
            "label": label,
            "severity": (
                "critical" if score > 0.80 else
                "high" if score > 0.60 else
                "medium" if score > 0.40 else "low"
            ),
            "features_used": f,
            "top_contributing_features": top_features,
        }

        detections.append(det)
        ES.index(
            index=os.getenv(
                "ES_INDEX_DETECTIONS","act_aware_detections"
            ),
            id=det["detection_id"],
            document=det,
            refresh=False
        )

    ES.indices.refresh(index=os.getenv(
        "ES_INDEX_DETECTIONS","act_aware_detections"
    ))
    return detections

def correlate_incidents(
    detections: list,
    behaviors: list
) -> list:
    """
    Groups related anomalous detections into incidents.
    Builds networkx attack graph.
    Returns list of CorrelatedIncident dicts.
    """
    # Group anomalous detections by entity
    anomalies = {}
    for d in detections:
        if d["label"] != "anomaly":
            continue
        eid = d["entity_id"]
        if eid not in anomalies:
            anomalies[eid] = []
        anomalies[eid].append(d)

    if not anomalies:
        logger.info("No anomalous detections to correlate")
        return []

    # Build behavior lookup
    behavior_map = {b["behavior_id"]: b for b in behaviors}

    # Build entity relationship graph
    G = nx.DiGraph()

    # Add nodes for each anomalous entity
    for entity_id, dets in anomalies.items():
        max_score = max(d["anomaly_score"] for d in dets)
        G.add_node(entity_id, score=max_score)

    # Add edges based on shared events
    # (entities that accessed same resource or same host)
    all_events_result = ES.search(
        index=os.getenv("ES_INDEX_EVENTS","act_aware_events"),
        body={"query":{"match_all":{}},"size":10000}
    )
    all_events = [
        h["_source"]
        for h in all_events_result["hits"]["hits"]
    ]

    # Build resource-entity mapping
    resource_entities = {}
    for event in all_events:
        resource = event.get("resource","") or \
                   event.get("host","")
        entity = event.get("user","") or event.get("host","")
        if resource and entity and entity in anomalies:
            if resource not in resource_entities:
                resource_entities[resource] = set()
            resource_entities[resource].add(entity)

    # Connect entities that share resources
    for resource, entities in resource_entities.items():
        entity_list = list(entities)
        for i in range(len(entity_list)):
            for j in range(i+1, len(entity_list)):
                e1, e2 = entity_list[i], entity_list[j]
                if G.has_node(e1) and G.has_node(e2):
                    G.add_edge(
                        e1, e2,
                        weight=1.0,
                        relation="shared_resource",
                        resource=resource,
                        timestamp=utc_str(),
                        event_id=str(uuid4())
                    )

    # Compute centrality
    try:
        centrality = nx.betweenness_centrality(G)
    except Exception:
        centrality = {n: 0.0 for n in G.nodes()}

    # Find connected components — each is one incident
    undirected = G.to_undirected()
    components = list(
        nx.connected_components(undirected)
    )

    # Also create solo incidents for isolated anomalies
    in_component = set()
    for comp in components:
        in_component.update(comp)

    for entity in anomalies:
        if entity not in in_component:
            components.append({entity})

    incidents = []

    for component in components:
        entities = list(component)
        if not entities:
            continue

        # Gather all detections for this component
        component_dets = []
        for entity in entities:
            component_dets.extend(anomalies.get(entity,[]))

        if not component_dets:
            continue

        # Determine severity and pattern
        max_score = max(
            d["anomaly_score"] for d in component_dets
        )
        all_features = {}
        for d in component_dets:
            for k, v in d.get("features_used",{}).items():
                all_features[k] = max(
                    all_features.get(k,0), float(v or 0)
                )

        pattern = _infer_pattern(all_features, component_dets)
        stage = _infer_stage(pattern, all_features)
        severity = (
            "critical" if max_score > 0.85 else
            "high" if max_score > 0.70 else
            "medium" if max_score > 0.50 else "low"
        )

        # Pivot entity = highest centrality in component
        pivot = max(
            entities,
            key=lambda e: centrality.get(e, 0)
        )

        # Lateral movement = component has multiple entities
        # AND at least one edge
        lateral = (
            len(entities) > 1 and
            G.number_of_edges() > 0
        )

        # Build timeline from events
        entity_events = [
            e for e in all_events
            if (e.get("user","") in entities or
                e.get("host","") in entities)
        ]
        entity_events.sort(key=lambda e: e.get("timestamp",""))

        timeline = [
            {
                "event_id": e.get("event_id",""),
                "timestamp": e.get("timestamp",""),
                "entity_id": (
                    e.get("user") or
                    e.get("host") or
                    "unknown"
                ),
                "action": e.get("action","exec"),
                "resource": e.get("resource"),
                "severity": e.get("severity","low")
            }
            for e in entity_events[-10:]
        ]

        # Get timestamps
        timestamps = [
            e.get("timestamp","") for e in entity_events
            if e.get("timestamp")
        ]
        inc_start = min(timestamps) if timestamps else utc_str()
        inc_end = max(timestamps) if timestamps else utc_str()

        try:
            start_dt = datetime.fromisoformat(
                inc_start.replace("Z","+00:00")
            )
            end_dt = datetime.fromisoformat(
                inc_end.replace("Z","+00:00")
            )
            duration = (
                end_dt - start_dt
            ).total_seconds() / 60
        except Exception:
            duration = 0.0

        # Build graph context
        nodes = [
            {
                "id": e,
                "type": "user" if any(
                    ev.get("user")==e for ev in all_events
                ) else "host",
                "label": e,
                "risk_score": centrality.get(e,0.0)
            }
            for e in entities
        ]

        edges = [
            {
                "source": u,
                "target": v,
                "weight": G[u][v].get("weight",1.0),
                "relation": G[u][v].get("relation",""),
                "timestamp": G[u][v].get("timestamp",utc_str()),
                "event_id": G[u][v].get("event_id","")
            }
            for u, v in G.edges()
            if u in component and v in component
        ]

        incident = {
            "schema_version": "1.1.0",
            "pipeline_id": PIPELINE_ID,
            "incident_id": str(uuid4()),
            "created_at": utc_str(),
            "updated_at": utc_str(),
            "entities": entities,
            "entity_types": {
                e: "user" if any(
                    ev.get("user")==e for ev in all_events
                ) else "host"
                for e in entities
            },
            "primary_entity": pivot,
            "detection_ids": [
                d["detection_id"] for d in component_dets
            ],
            "source_event_ids": [
                e.get("event_id","") for e in entity_events
            ],
            "incident_start": inc_start,
            "incident_end": inc_end,
            "duration_minutes": round(duration, 2),
            "timeline": timeline,
            "pattern": pattern,
            "attack_stage": stage,
            "severity": severity,
            "graph_context": {
                "nodes": nodes,
                "edges": edges,
                "centrality_scores": {
                    e: round(centrality.get(e,0.0),4)
                    for e in entities
                },
                "pivot_entity": pivot,
                "lateral_movement_detected": lateral,
                "subgraph_size": len(entities)
            }
        }

        incidents.append(incident)

        ES.index(
            index=os.getenv(
                "ES_INDEX_INCIDENTS","act_aware_incidents"
            ),
            id=incident["incident_id"],
            document=incident,
            refresh=False
        )

    ES.indices.refresh(index=os.getenv(
        "ES_INDEX_INCIDENTS","act_aware_incidents"
    ))

    logger.info(
        f"Correlation: {len(incidents)} incidents from "
        f"{len(anomalies)} anomalous entities"
    )
    return incidents

def _infer_pattern(features: dict, dets: list) -> str:
    """Infers attack pattern from features."""
    if features.get("login_fail_count",0) > 5 and \
       features.get("login_fail_ratio",0) > 0.5:
        return "brute_force"
    if features.get("privilege_escalation_attempts",0) > 0:
        return "privilege_escalation"
    if features.get("unique_hosts_accessed",0) > 2:
        return "lateral_movement"
    if features.get("db_rows_accessed",0) > 500 or \
       features.get("outbound_data_volume",0) > 1000:
        return "data_exfiltration"
    if features.get("suspicious_process_count",0) > 0:
        return "lateral_movement"
    if features.get("sensitive_resource_access_count",0) > 2:
        return "insider_threat"
    return "unknown"

def _infer_stage(pattern: str, features: dict) -> str:
    """Infers MITRE ATT&CK stage from pattern."""
    stage_map = {
        "brute_force": "initial_access",
        "privilege_escalation": "privilege_escalation",
        "lateral_movement": "lateral_movement",
        "data_exfiltration": "exfiltration",
        "insider_threat": "collection",
        "unknown": "unknown"
    }
    return stage_map.get(pattern, "unknown")


# ════════════════════════════════════════════════════════════
# MAIN PIPELINE RUNNER
# ════════════════════════════════════════════════════════════

def run_full_pipeline(data_path: str = None,
                      synthetic: bool = False):
    """
    Runs the complete pipeline end to end.
    """
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich import box

    console = Console()

    console.print(Panel(
        "[bold cyan]ACT AWARE — Full Pipeline[/bold cyan]\n"
        f"Pipeline ID: [dim]{PIPELINE_ID}[/dim]",
        box=box.DOUBLE
    ))

    start_time = time.time()
    ensure_indices_exist()
    # ── STEP 1: INGEST ────────────────────────────────────────
    console.print(
        "\n[bold yellow]STEP 1 — Log Ingestion[/bold yellow]"
    )

    events = []
    if synthetic or data_path is None:
        console.print(
            "  [dim]No data path provided. "
            "Generating synthetic data...[/dim]"
        )
        from tests.synthetic_incidents import generate_and_push
        generate_and_push()
        console.print(
            "  [green]✓ Synthetic data generated[/green]"
        )
        # Fetch what was generated
        r = ES.search(
            index=os.getenv(
                "ES_INDEX_EVENTS","act_aware_events"
            ),
            body={"query":{"match_all":{}},"size":1}
        )
        event_count = r["hits"]["total"]["value"]
        console.print(
            f"  [green]✓ {event_count} events in ES[/green]"
        )
    else:
        path = Path(data_path)
        if path.is_dir():
            console.print(
                f"  Ingesting directory: {data_path}"
            )
            events = ingest_directory(data_path)
        elif path.is_file():
            console.print(f"  Ingesting file: {data_path}")
            events = ingest_file(data_path)
        else:
            console.print(
                f"  [red]Path not found: {data_path}[/red]"
            )
            return

        if not events:
            console.print(
                "  [red]No events parsed from dataset. "
                "Check file format.[/red]"
            )
            return

        pushed = push_events_to_es(events)
        console.print(
            f"  [green]✓ {len(events)} events parsed, "
            f"{pushed} pushed to ES[/green]"
        )

        # Show format breakdown
        formats = {}
        for e in events:
            fmt = e.get("source","unknown")
            formats[fmt] = formats.get(fmt,0) + 1
        for fmt, count in sorted(
            formats.items(), key=lambda x: -x[1]
        ):
            console.print(
                f"    {fmt}: {count} events"
            )

    # ── STEP 2: AGGREGATE ────────────────────────────────────
    console.print(
        "\n[bold yellow]STEP 2 — Behavioral Aggregation"
        "[/bold yellow]"
    )
    behaviors = aggregate_behaviors()
    console.print(
        f"  [green]✓ {len(behaviors)} behavioral windows"
        f"[/green]"
    )

    if not behaviors:
        console.print(
            "  [red]No behaviors to analyze. "
            "Check event data.[/red]"
        )
        return

    # ── STEP 3: DETECT ───────────────────────────────────────
    console.print(
        "\n[bold yellow]STEP 3 — Anomaly Detection"
        "[/bold yellow]"
    )
    detections = run_detection(behaviors)
    anomaly_count = sum(
        1 for d in detections if d["label"] == "anomaly"
    )
    console.print(
        f"  [green]✓ {len(detections)} detections, "
        f"{anomaly_count} anomalies[/green]"
    )

    # ── STEP 4: CORRELATE ────────────────────────────────────
    console.print(
        "\n[bold yellow]STEP 4 — Incident Correlation"
        "[/bold yellow]"
    )
    incidents = correlate_incidents(detections, behaviors)
    console.print(
        f"  [green]✓ {len(incidents)} incidents[/green]"
    )

    if not incidents:
        console.print(
            "  [yellow]No incidents correlated. "
            "No anomalies detected.[/yellow]"
        )
        _print_summary(console, 0, 0, 0, time.time()-start_time)
        return

    # ── STEP 5: FIDELITY SCORING ─────────────────────────────
    console.print(
        "\n[bold yellow]STEP 5 — Fidelity Scoring "
        "(Layer 8)[/bold yellow]"
    )
    from fidelity.scoring_engine import FidelityScoringEngine
    engine = FidelityScoringEngine(ES)
    scored = []

    for inc in incidents:
        result = engine.score_incident(inc["incident_id"])
        if result:
            scored.append({
                **inc,
                "fidelity_score": result["fidelity_score"],
                "confidence": result["confidence"],
                "is_stable": result["is_stable"],
                "llm_eligible": result["llm_eligible"],
                "fidelity_id": result["fidelity_id"],
                "permitted_actions": result.get(
                    "permitted_actions",[]
                ),
                "pipeline_id_fid": result["pipeline_id"]
            })

    # Print scoring table
    table = Table(
        title="Incident Fidelity Scores",
        box=box.SIMPLE
    )
    table.add_column("Entity", style="cyan")
    table.add_column("Pattern")
    table.add_column("Severity")
    table.add_column("Score", style="bold")
    table.add_column("Confidence")
    table.add_column("Stable")
    table.add_column("LLM Eligible")

    high_count = 0
    for s in sorted(
        scored, key=lambda x: -x["fidelity_score"]
    ):
        score = s["fidelity_score"]
        color = (
            "red" if score >= 0.90 else
            "yellow" if score >= 0.75 else
            "green" if score >= 0.50 else "dim"
        )
        if score >= 0.75:
            high_count += 1

        table.add_row(
            str(s.get("primary_entity",""))[:20],
            str(s.get("pattern","")),
            str(s.get("severity","")),
            f"[{color}]{score:.4f}[/{color}]",
            str(s.get("confidence","")),
            "✓" if s["is_stable"] else "✗",
            "✓" if s["llm_eligible"] else "✗"
        )

    console.print(table)

    # ── STEP 6: PLAYBOOK GENERATION ──────────────────────────
    console.print(
        "\n[bold yellow]STEP 6 — AI Playbook Generation "
        "(Layer 9)[/bold yellow]"
    )

    eligible = [s for s in scored if s["llm_eligible"]]
    console.print(
        f"  {len(eligible)} incident(s) eligible for "
        f"AI reasoning (score ≥ 0.75 + stable)"
    )

    playbooks_generated = 0
    if eligible:
        from reasoning.agent import SOCReasoningAgent
        agent = SOCReasoningAgent()

        for s in eligible[:3]:  # Max 3 playbooks
            console.print(
                f"\n  [cyan]Generating playbook for "
                f"{s.get('primary_entity','')} "
                f"({s['pattern']}, score={s['fidelity_score']})"
                f"[/cyan]"
            )

            result = agent.run(
                incident_id=s["incident_id"],
                fidelity_id=s["fidelity_id"],
                requested_by="hackathon_analyst"
            )

            if result["success"]:
                playbooks_generated += 1
                console.print(
                    f"  [green]✓ Playbook: "
                    f"{result['playbook_id'][:20]}...[/green]"
                )
                console.print(
                    f"    Steps: {result['steps_count']} | "
                    f"Status: pending_review"
                )
                if result.get("threat_narrative"):
                    console.print(
                        f"    [dim]{result['threat_narrative'][:100]}..."
                        f"[/dim]"
                    )
            else:
                reason = (
                    result.get("termination_reason") or
                    result.get("llm_error") or
                    result.get("error","Unknown error")
                )
                console.print(
                    f"  [yellow]⚠ {reason}[/yellow]"
                )
    else:
        console.print(
            "  [yellow]No eligible incidents. "
            "All below 0.75 threshold or unstable.[/yellow]"
        )

    total_time = time.time() - start_time
    _print_summary(
        console,
        len(incidents),
        high_count,
        playbooks_generated,
        total_time
    )

    # ── EXPORT RESULTS ───────────────────────────────────────
    _export_results(scored)


def _print_summary(
    console, incidents, high_risk, playbooks, elapsed
):
    from rich.panel import Panel
    from rich import box

    # Final counts from ES
    def count(idx):
        try:
            return ES.count(index=os.getenv(idx,idx))["count"]
        except Exception:
            return 0

    console.print(Panel(
        f"Events ingested    : "
        f"{count('ES_INDEX_EVENTS')}\n"
        f"Behaviors computed : "
        f"{count('ES_INDEX_BEHAVIORS')}\n"
        f"Detections scored  : "
        f"{count('ES_INDEX_DETECTIONS')}\n"
        f"Incidents created  : "
        f"{count('ES_INDEX_INCIDENTS')}\n"
        f"High-risk (≥0.75)  : {high_risk}\n"
        f"Fidelity records   : "
        f"{count('ES_INDEX_FIDELITY')}\n"
        f"Playbooks generated: {playbooks}\n"
        f"Provenance records : "
        f"{count('act_aware_provenance')}\n\n"
        f"Total runtime      : {elapsed:.1f}s\n\n"
        "[dim]All playbooks in pending_review status.\n"
        "Human approval required before execution.[/dim]",
        title="[bold green]Pipeline Complete[/bold green]",
        box=box.SIMPLE
    ))


def _export_results(scored: list):
    """
    Exports results to a JSON file for the judges.
    This is your final output.
    """
    output = {
        "pipeline_id": PIPELINE_ID,
        "generated_at": utc_str(),
        "system": "ACT AWARE",
        "incidents": []
    }

    for s in sorted(
        scored, key=lambda x: -x["fidelity_score"]
    ):
        # Get playbook if exists
        try:
            pb_result = ES.search(
                index=os.getenv(
                    "ES_INDEX_PLAYBOOKS","act_aware_playbooks"
                ),
                body={
                    "query": {
                        "term": {
                            "incident_id": s["incident_id"]
                        }
                    },
                    "size": 1
                }
            )
            pb = (
                pb_result["hits"]["hits"][0]["_source"]
                if pb_result["hits"]["hits"] else None
            )
        except Exception:
            pb = None

        entry = {
            "incident_id": s["incident_id"],
            "primary_entity": s.get("primary_entity"),
            "pattern": s.get("pattern"),
            "attack_stage": s.get("attack_stage"),
            "severity": s.get("severity"),
            "fidelity_score": s["fidelity_score"],
            "confidence": s["confidence"],
            "is_stable": s["is_stable"],
            "llm_eligible": s["llm_eligible"],
            "entities_involved": s.get("entities",[]),
            "lateral_movement": s.get(
                "graph_context",{}
            ).get("lateral_movement_detected",False),
            "playbook": {
                "generated": pb is not None,
                "playbook_id": pb.get("playbook_id") if pb else None,
                "threat_narrative": pb.get("threat_narrative") if pb else None,
                "steps": pb.get("steps",[]) if pb else [],
                "status": pb.get("status") if pb else None,
            } if pb else {"generated": False}
        }
        output["incidents"].append(entry)

    # Save to file
    output_path = "output/results.json"
    os.makedirs("output", exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2, default=str)

    print(f"\nResults exported to: {output_path}")
    print(
        f"Total incidents: {len(output['incidents'])}"
    )
    print(
        f"High-risk (≥0.75): "
        f"{sum(1 for i in output['incidents'] if i['fidelity_score'] >= 0.75)}"
    )
    print(
        f"Playbooks generated: "
        f"{sum(1 for i in output['incidents'] if i['playbook']['generated'])}"
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="ACT AWARE Full Pipeline"
    )
    parser.add_argument(
        "--data",
        help="Path to dataset file or directory",
        default=None
    )
    parser.add_argument(
        "--synthetic",
        action="store_true",
        help="Use synthetic data instead of real dataset"
    )
    args = parser.parse_args()

    run_full_pipeline(
        data_path=args.data,
        synthetic=args.synthetic or args.data is None
    )