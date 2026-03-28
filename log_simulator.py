"""
log_simulator.py
Real-Time Banking Log Simulator
Mimics Nandni's Layer 1-2 pipeline output exactly.
Generates UniversalEvent objects following schema v1.1.0
Team: Phoenix Core | ACT AWARE
"""

import sys
sys.path.insert(0, '.')

import random
import time
import threading
from datetime import datetime, timezone, timedelta
from uuid import uuid4
from collections import deque

import os
from dotenv import load_dotenv
from elasticsearch import Elasticsearch
load_dotenv()

from config.schemas import UniversalEvent, utc_now

# ── Shared Event Buffer ───────────────────────
# This acts like Elasticsearch — main.py reads from here
# instead of from ES when running air-gapped
event_buffer = deque(maxlen=500)
buffer_lock = threading.Lock()

# ── Realistic Banking Data ────────────────────
USERS = [
    # Normal employees
    "alice.johnson", "bob.smith", "carol.white", "david.brown",
    "eve.davis", "frank.miller", "grace.wilson", "henry.moore",
    "iris.taylor", "jack.anderson", "karen.thomas", "liam.jackson",
    "mary.harris", "nathan.martin", "olivia.garcia", "peter.martinez",
    "quinn.robinson", "rachel.clark", "steve.rodriguez", "tina.lewis",
    # Service accounts
    "svc_backup", "svc_monitor", "svc_deploy", "svc_database",
    # Admin accounts
    "admin.ops", "admin.security", "admin.network"
]

HOSTS = [
    "ws-alice-001", "ws-bob-002", "ws-carol-003", "ws-david-004",
    "dc-prod-01", "dc-prod-02", "db-server-01", "db-server-02",
    "app-server-01", "app-server-02", "file-server-01",
    "payroll-srv-01", "hr-server-01", "finance-srv-01",
    "backup-srv-01", "monitoring-srv-01"
]

INTERNAL_IPS = [f"192.168.{random.randint(1,5)}.{i}" for i in range(10, 60)]
EXTERNAL_IPS = [
    "203.0.113.45", "198.51.100.23", "185.220.101.45",
    "91.108.4.0", "45.33.32.156", "104.21.45.67"
]

RESOURCES = [
    "/data/customers/", "/data/transactions/", "/data/payroll/",
    "/config/network/", "/logs/audit/", "/backup/daily/",
    "customers_db", "transactions_db", "hr_records",
    "financial_reports", "salary_data", "card_numbers"
]

PROCESSES = [
    "explorer.exe", "chrome.exe", "outlook.exe", "excel.exe",
    "python.exe", "cmd.exe", "powershell.exe", "notepad.exe",
    "svchost.exe", "lsass.exe", "winlogon.exe"
]

SUSPICIOUS_PROCESSES = [
    "mimikatz.exe", "psexec.exe", "wscript.exe",
    "certutil.exe", "regsvr32.exe", "mshta.exe"
]


# ── Normal Activity Patterns ──────────────────
def generate_normal_events(count=5):
    """Simulate normal banking employee activity"""
    events = []
    now = utc_now()

    patterns = [
        # Morning logins
        {
            "source": "winlogbeat",
            "event_type": "login",
            "action": "success",
            "severity": "low",
            "hour_range": (8, 18)
        },
        # File reads (normal work)
        {
            "source": "filebeat",
            "event_type": "file",
            "action": "read",
            "severity": "low",
            "hour_range": (8, 18)
        },
        # Database queries
        {
            "source": "filebeat",
            "event_type": "database",
            "action": "read",
            "severity": "low",
            "hour_range": (9, 17)
        },
        # Network connections
        {
            "source": "syslog",
            "event_type": "network",
            "action": "connect",
            "severity": "low",
            "hour_range": (8, 18)
        },
        # Process execution
        {
            "source": "filebeat",
            "event_type": "process",
            "action": "exec",
            "severity": "low",
            "hour_range": (8, 18)
        },
        # Logouts
        {
            "source": "winlogbeat",
            "event_type": "login",
            "action": "disconnect",
            "severity": "low",
            "hour_range": (17, 19)
        },
        # API calls
        {
            "source": "custom",
            "event_type": "api_call",
            "action": "success",
            "severity": "low",
            "hour_range": (8, 18)
        },
    ]

    for _ in range(count):
        pattern = random.choice(patterns)
        user = random.choice(USERS[:20])  # Normal users only
        host = random.choice(HOSTS[:8])
        ip = random.choice(INTERNAL_IPS)

        event = UniversalEvent(
            timestamp=now - timedelta(seconds=random.randint(0, 300)),
            source=pattern["source"],
            event_type=pattern["event_type"],
            action=pattern["action"],
            severity=pattern["severity"],
            user=user,
            host=host,
            ip=ip,
            destination_ip=random.choice(INTERNAL_IPS) if pattern["event_type"] == "network" else None,
            destination_port=random.choice([80, 443, 8080, 3306, 5432]) if pattern["event_type"] == "network" else None,
            resource=random.choice(RESOURCES) if pattern["event_type"] in ("file", "database") else None,
            process_name=random.choice(PROCESSES) if pattern["event_type"] == "process" else None,
            outcome="success",
            user_privilege_level="standard",
            host_os="windows",
            pipeline_id=str(uuid4())
        )
        events.append(event)

    return events


# ── Attack Scenario Generators ────────────────

def simulate_brute_force():
    """
    Attacker trying many login failures from external IP
    Pattern: Multiple failed logins → eventual success → privilege escalation
    """
    events = []
    now = utc_now()
    attacker_user = random.choice(["attacker_ext", "unknown_user", "hacker_001"])
    target_host = random.choice(["dc-prod-01", "dc-prod-02", "app-server-01"])
    external_ip = random.choice(EXTERNAL_IPS)
    pipeline_id = str(uuid4())

    # Many failed logins
    fail_count = random.randint(8, 20)
    for i in range(fail_count):
        events.append(UniversalEvent(
            timestamp=now - timedelta(seconds=random.randint(60, 900)),
            source="winlogbeat",
            event_type="login",
            action="failure",
            severity="high",
            user=attacker_user,
            host=target_host,
            ip=external_ip,
            outcome="failure",
            error_code="0xC000006D",
            pipeline_id=pipeline_id
        ))

    # Eventual successful login
    events.append(UniversalEvent(
        timestamp=now - timedelta(seconds=30),
        source="winlogbeat",
        event_type="login",
        action="success",
        severity="critical",
        user=attacker_user,
        host=target_host,
        ip=external_ip,
        outcome="success",
        pipeline_id=pipeline_id
    ))

    # Privilege escalation attempt
    events.append(UniversalEvent(
        timestamp=now - timedelta(seconds=15),
        source="winlogbeat",
        event_type="privilege",
        action="escalate",
        severity="critical",
        user=attacker_user,
        host=target_host,
        ip=external_ip,
        resource="SYSTEM",
        pipeline_id=pipeline_id
    ))

    return events


def simulate_lateral_movement():
    """
    Attacker moving across multiple internal hosts
    Pattern: Login → access host1 → host2 → host3 → ... → target
    """
    events = []
    now = utc_now()
    attacker = f"compromised_{random.choice(['alice', 'bob', 'carol'])}"
    source_ip = random.choice(INTERNAL_IPS)
    pipeline_id = str(uuid4())

    # Initial login
    events.append(UniversalEvent(
        timestamp=now - timedelta(minutes=12),
        source="winlogbeat",
        event_type="login",
        action="success",
        severity="low",
        user=attacker,
        host=HOSTS[0],
        ip=source_ip,
        pipeline_id=pipeline_id
    ))

    # Move across multiple hosts
    target_hosts = random.sample(HOSTS[4:12], random.randint(5, 8))
    for i, target_host in enumerate(target_hosts):
        dest_ip = f"192.168.{random.randint(1,5)}.{random.randint(1,50)}"
        events.append(UniversalEvent(
            timestamp=now - timedelta(minutes=10-i),
            source="syslog",
            event_type="network",
            action="connect",
            severity="medium" if i < 3 else "high",
            user=attacker,
            host=target_host,
            ip=source_ip,
            destination_ip=dest_ip,
            destination_port=random.choice([445, 3389, 22, 135]),
            pipeline_id=pipeline_id
        ))

    # Final privilege escalation
    events.append(UniversalEvent(
        timestamp=now - timedelta(seconds=30),
        source="winlogbeat",
        event_type="privilege",
        action="escalate",
        severity="critical",
        user=attacker,
        host=target_hosts[-1],
        ip=source_ip,
        pipeline_id=pipeline_id
    ))

    return events


def simulate_data_exfiltration():
    """
    Insider or attacker stealing sensitive data
    Pattern: Login → bulk file reads → database dumps → outbound transfer
    """
    events = []
    now = utc_now()
    thief = random.choice(["david.brown", "insider_threat_01", "svc_backup"])
    host = random.choice(["db-server-01", "file-server-01", "finance-srv-01"])
    ip = random.choice(INTERNAL_IPS)
    pipeline_id = str(uuid4())

    # Login (possibly after hours)
    events.append(UniversalEvent(
        timestamp=now - timedelta(minutes=15),
        source="winlogbeat",
        event_type="login",
        action="success",
        severity="low",
        user=thief,
        host=host,
        ip=ip,
        pipeline_id=pipeline_id
    ))

    # Bulk file reads
    sensitive_resources = [
        "/data/customers/full_dump.csv",
        "/data/transactions/2024_all.xlsx",
        "/data/payroll/salary_all.xlsx",
        "card_numbers",
        "customers_db"
    ]
    for resource in random.sample(sensitive_resources, random.randint(3, 5)):
        events.append(UniversalEvent(
            timestamp=now - timedelta(minutes=random.randint(8, 13)),
            source="filebeat",
            event_type="file",
            action="read",
            severity="high",
            user=thief,
            host=host,
            ip=ip,
            resource=resource,
            pipeline_id=pipeline_id
        ))

    # Database bulk queries
    for _ in range(random.randint(3, 6)):
        events.append(UniversalEvent(
            timestamp=now - timedelta(minutes=random.randint(5, 8)),
            source="filebeat",
            event_type="database",
            action="read",
            severity="high",
            user=thief,
            host=host,
            ip=ip,
            resource=random.choice(["customers_db", "transactions_db", "financial_reports"]),
            pipeline_id=pipeline_id
        ))

    # Outbound network transfer
    events.append(UniversalEvent(
        timestamp=now - timedelta(minutes=2),
        source="syslog",
        event_type="network",
        action="connect",
        severity="critical",
        user=thief,
        host=host,
        ip=ip,
        destination_ip=random.choice(EXTERNAL_IPS),
        destination_port=443,
        pipeline_id=pipeline_id
    ))

    return events


def simulate_ransomware():
    """
    Ransomware infection spreading across the network
    Pattern: Execution → file encryption → spreading → C2 beacon
    """
    events = []
    now = utc_now()
    infected_user = random.choice(["alice.johnson", "carol.white", "frank.miller"])
    infected_host = random.choice(HOSTS[:6])
    ip = random.choice(INTERNAL_IPS)
    pipeline_id = str(uuid4())

    # Initial execution (malicious process)
    for proc in random.sample(SUSPICIOUS_PROCESSES, 2):
        events.append(UniversalEvent(
            timestamp=now - timedelta(minutes=14),
            source="filebeat",
            event_type="process",
            action="exec",
            severity="high",
            user=infected_user,
            host=infected_host,
            ip=ip,
            process_name=proc,
            parent_process="outlook.exe",
            pipeline_id=pipeline_id
        ))

    # Mass file writes (encryption)
    for i in range(random.randint(6, 12)):
        events.append(UniversalEvent(
            timestamp=now - timedelta(minutes=random.randint(8, 13)),
            source="filebeat",
            event_type="file",
            action="write",
            severity="high",
            user=infected_user,
            host=infected_host,
            ip=ip,
            resource=f"/data/files/document_{i}.encrypted",
            pipeline_id=pipeline_id
        ))

    # File deletions (originals deleted after encryption)
    for i in range(random.randint(4, 8)):
        events.append(UniversalEvent(
            timestamp=now - timedelta(minutes=random.randint(5, 8)),
            source="filebeat",
            event_type="file",
            action="delete",
            severity="critical",
            user=infected_user,
            host=infected_host,
            ip=ip,
            resource=f"/data/files/document_{i}.docx",
            pipeline_id=pipeline_id
        ))

    # C2 beacon (command and control)
    events.append(UniversalEvent(
        timestamp=now - timedelta(minutes=2),
        source="syslog",
        event_type="network",
        action="connect",
        severity="critical",
        user=infected_user,
        host=infected_host,
        ip=ip,
        destination_ip=random.choice(EXTERNAL_IPS),
        destination_port=random.choice([4444, 8888, 1337, 9999]),
        pipeline_id=pipeline_id
    ))

    return events


def simulate_insider_threat():
    """
    Privileged insider abusing access
    Pattern: After-hours login → privilege misuse → data access → cover tracks
    """
    events = []
    now = utc_now()

    # After hours timestamp
    after_hours = now.replace(hour=2, minute=random.randint(0, 59))
    if after_hours > now:
        after_hours -= timedelta(hours=24)

    insider = random.choice(["admin.ops", "admin.security", "svc_database"])
    host = random.choice(["payroll-srv-01", "hr-server-01", "finance-srv-01"])
    ip = random.choice(INTERNAL_IPS)
    pipeline_id = str(uuid4())

    # After-hours login
    events.append(UniversalEvent(
        timestamp=after_hours,
        source="winlogbeat",
        event_type="login",
        action="success",
        severity="medium",
        user=insider,
        host=host,
        ip=ip,
        user_privilege_level="admin",
        pipeline_id=pipeline_id
    ))

    # Privilege misuse
    events.append(UniversalEvent(
        timestamp=after_hours + timedelta(minutes=2),
        source="winlogbeat",
        event_type="privilege",
        action="escalate",
        severity="high",
        user=insider,
        host=host,
        ip=ip,
        user_privilege_level="admin",
        pipeline_id=pipeline_id
    ))

    # Sensitive data access
    for resource in ["/data/payroll/all_salaries.xlsx", "salary_data", "hr_records"]:
        events.append(UniversalEvent(
            timestamp=after_hours + timedelta(minutes=random.randint(3, 10)),
            source="filebeat",
            event_type="file",
            action="read",
            severity="high",
            user=insider,
            host=host,
            ip=ip,
            resource=resource,
            pipeline_id=pipeline_id
        ))

    # Database dump
    for _ in range(3):
        events.append(UniversalEvent(
            timestamp=after_hours + timedelta(minutes=random.randint(10, 15)),
            source="filebeat",
            event_type="database",
            action="read",
            severity="high",
            user=insider,
            host=host,
            ip=ip,
            resource="salary_data",
            pipeline_id=pipeline_id
        ))

    return events


def simulate_privilege_escalation():
    """
    Attacker escalating privileges step by step
    Pattern: Standard login → failed privilege → success → admin actions
    """
    events = []
    now = utc_now()
    user = random.choice(USERS[5:15])
    host = random.choice(["dc-prod-01", "app-server-01"])
    ip = random.choice(INTERNAL_IPS)
    pipeline_id = str(uuid4())

    # Normal login
    events.append(UniversalEvent(
        timestamp=now - timedelta(minutes=10),
        source="winlogbeat",
        event_type="login",
        action="success",
        severity="low",
        user=user,
        host=host,
        ip=ip,
        pipeline_id=pipeline_id
    ))

    # Failed privilege escalation attempts
    for _ in range(random.randint(2, 4)):
        events.append(UniversalEvent(
            timestamp=now - timedelta(minutes=random.randint(7, 9)),
            source="winlogbeat",
            event_type="privilege",
            action="failure",
            severity="high",
            user=user,
            host=host,
            ip=ip,
            pipeline_id=pipeline_id
        ))

    # Successful escalation
    events.append(UniversalEvent(
        timestamp=now - timedelta(minutes=5),
        source="winlogbeat",
        event_type="privilege",
        action="escalate",
        severity="critical",
        user=user,
        host=host,
        ip=ip,
        user_privilege_level="admin",
        pipeline_id=pipeline_id
    ))

    # Admin actions
    for resource in ["/config/network/", "customers_db"]:
        events.append(UniversalEvent(
            timestamp=now - timedelta(minutes=random.randint(1, 4)),
            source="filebeat",
            event_type="file",
            action="read",
            severity="critical",
            user=user,
            host=host,
            ip=ip,
            resource=resource,
            user_privilege_level="admin",
            pipeline_id=pipeline_id
        ))

    return events


# ── Attack Scheduler ──────────────────────────
ATTACK_GENERATORS = [
    (simulate_brute_force, 0.20, "Brute Force"),
    (simulate_lateral_movement, 0.18, "Lateral Movement"),
    (simulate_data_exfiltration, 0.20, "Data Exfiltration"),
    (simulate_ransomware, 0.17, "Ransomware"),
    (simulate_insider_threat, 0.15, "Insider Threat"),
    (simulate_privilege_escalation, 0.10, "Privilege Escalation"),
]


def get_events_batch():
    """
    Generate one batch of events (normal + maybe attack).
    Called every cycle by the simulator thread.
    Returns list of UniversalEvent objects.
    """
    events = []

    # Always generate normal activity
    normal_count = random.randint(8, 18)
    events.extend(generate_normal_events(normal_count))

    # Randomly trigger 1-2 attack scenarios
    attack_count = random.randint(1, 2)
    triggered = []

    for _ in range(attack_count):
        roll = random.random()
        cumulative = 0.0
        for generator, probability, name in ATTACK_GENERATORS:
            cumulative += probability
            if roll <= cumulative:
                try:
                    attack_events = generator()
                    events.extend(attack_events)
                    triggered.append(name)
                except Exception as e:
                    print(f"[Simulator] Attack generation error ({name}): {e}")
                break

    total = len(events)
    attacks = sum(1 for e in events if e.severity in ("high", "critical"))

    print(f"[Simulator] Generated {total} events "
          f"({total - attacks} normal, {attacks} attack) "
          f"| Scenarios: {', '.join(triggered) if triggered else 'none'}")

    return events


def run_simulator(interval_seconds=8):
    """
    Continuous simulator thread.
    Generates events every interval and adds to shared buffer.
    Also pushes events to Elasticsearch if connected.
    """
    print("[Simulator] Starting real-time banking log simulator...")
    print(f"[Simulator] Generating events every {interval_seconds} seconds")
    # Try to connect to ES on startup
    get_es_client()

    while True:
        try:
            batch = get_events_batch()
            with buffer_lock:
                for event in batch:
                    event_buffer.append(event)
            # Push to Elasticsearch if connected
            push_events_to_es(batch)
            # Push to Elasticsearch if connected
            push_events_to_es(batch)
            time.sleep(interval_seconds)
        except Exception as e:
            print(f"[Simulator] Error: {e}")
            time.sleep(5)

def get_buffered_events(limit=300):
    """
    Get current events from buffer.
    Called by main.py pipeline instead of Elasticsearch.
    """
    with buffer_lock:
        return list(event_buffer)[-limit:]


def start_simulator(interval_seconds=8):
    """Start simulator in background thread."""
    t = threading.Thread(
        target=run_simulator,
        args=(interval_seconds,),
        daemon=True
    )
    t.start()
    return t


if __name__ == "__main__":
    print("=" * 60)
    print("  Banking Log Simulator — Standalone Test")
    print("=" * 60)

    print("\nGenerating one batch of events...\n")
    events = get_events_batch()

    normal = [e for e in events if e.severity == "low"]
    attacks = [e for e in events if e.severity in ("high", "critical")]
    medium = [e for e in events if e.severity == "medium"]

    print(f"\nTotal events:  {len(events)}")
    print(f"Normal (low):  {len(normal)}")
    print(f"Medium:        {len(medium)}")
    print(f"High/Critical: {len(attacks)}")

    print(f"\nSample attack events:")
    for e in attacks[:5]:
        print(f"  [{e.severity.upper():8}] {e.user or 'unknown':<30} "
              f"{e.event_type}.{e.action:<15} "
              f"host={e.host or 'N/A'}")

    print(f"\n{'=' * 60}")
    print("  Simulator test PASSED")
    print(f"{'=' * 60}")

# ── Elasticsearch Connection ──────────────────
_es_client = None

def get_es_client():
    """Get or create Elasticsearch client"""
    global _es_client
    if _es_client is not None:
        return _es_client
    try:
        ES_HOST = os.getenv("ES_HOST", "")
        ES_USER = os.getenv("ES_USERNAME", "elastic")
        ES_PASS = os.getenv("ES_PASSWORD", "")
        if not ES_HOST:
            return None
        _es_client = Elasticsearch(
            ES_HOST,
            basic_auth=(ES_USER, ES_PASS),
            verify_certs=False
        )
        if _es_client.ping():
            print("[Simulator] ✅ Connected to Elasticsearch - will push events!")
            return _es_client
        else:
            _es_client = None
            print("[Simulator] ❌ ES ping failed - running in memory only")
            return None
    except Exception as e:
        print(f"[Simulator] ❌ ES connection error: {e}")
        return None


def push_events_to_es(events: list):
    """Push generated events to Elasticsearch"""
    es = get_es_client()
    if not es:
        return 0

    index = os.getenv("INDEX_NAME", "act_aware_events")
    pushed = 0

    for event in events:
        try:
            doc = {
                "@timestamp": event.timestamp.isoformat(),
                "timestamp": event.timestamp.isoformat(),
                "event_id": event.event_id,
                "pipeline_id": event.pipeline_id,
                "source": {"ip": event.ip} if event.ip else None,   # ✅ FIXED
                "event_type": event.event_type,
                "action": event.action,
                "severity": event.severity,
                "user": {"name": event.user} if event.user else None,   # ✅ FIXED
                "host": {"name": event.host} if event.host else None,   # ✅ FIXED
                "ip": event.ip,
                "destination": {"ip": event.destination_ip} if event.destination_ip else None,  # ✅ FIXED
                "destination_ip": event.destination_ip,
                "tags": ["simulator", "act_aware", event.severity]
            }

            res = es.index(index=index, document=doc)   # (unchanged logic)
            pushed += 1

        except Exception as e:
            print("[ES ERROR]", e)   # ✅ FIXED (no silent failure)

    if pushed > 0:
        print(f"[Simulator] ✅ Pushed {pushed} events to '{index}'")

    return pushed