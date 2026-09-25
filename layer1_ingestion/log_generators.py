# layer1_ingestion/log_generators.py
"""
Layer 1-2: Security Telemetry & Banking Cyber Attack Scenario Simulator
Generates synthetic heterogeneous logs:
  - Winlogbeat: Windows/AD authentication, Sysmon process executions
  - Filebeat: Core banking application and API logs
  - Syslog: Network perimeter, firewall, and connection logs
  - DB logs: Financial database access, SQL queries, transaction logs
"""

from typing import List, Dict, Any
from datetime import datetime, timedelta, timezone
from config.schemas import utc_now
import uuid
import random


class LogSimulator:
    def __init__(self, base_time: datetime = None):
        self.base_time = base_time or (utc_now() - timedelta(minutes=45))

    def generate_baseline_traffic(self, count: int = 50) -> List[Dict[str, Any]]:
        """Normal corporate banking daily activity."""
        logs = []
        users = ["alice.teller", "bob.cashier", "clara.manager", "david.compliance"]
        hosts = ["host:branch-01", "host:branch-02", "host:mgmt-01", "host:app-srv-01"]
        apps = ["/api/v1/balance", "/api/v1/transfer_status", "/portal/dashboard", "/reports/daily"]

        for i in range(count):
            t = self.base_time + timedelta(seconds=i * 20 + random.randint(1, 10))
            user = random.choice(users)
            host = random.choice(hosts)
            
            # Normal successful login or app interaction
            event = {
                "timestamp": t.isoformat(),
                "source": "winlogbeat" if i % 2 == 0 else "filebeat",
                "event_type": "login" if i % 3 == 0 else "api_call",
                "severity": "low",
                "user": user,
                "user_domain": "CORP_BANK",
                "user_privilege_level": "standard",
                "host": host,
                "host_os": "windows",
                "ip": f"10.10.1.{random.randint(10, 50)}",
                "destination_ip": "10.10.0.10",
                "destination_port": 443,
                "action": "success" if i % 3 == 0 else "read",
                "resource": random.choice(apps),
                "outcome": "success",
                "metadata": {"session_id": str(uuid.uuid4())[:8], "department": "retail_banking"}
            }
            logs.append(event)
        return logs

    def generate_banking_attack_scenario(self) -> List[Dict[str, Any]]:
        """
        Multi-Stage Banking Cyberattack Scenario:
          Stage 1: Brute Force Password Spray on 'sarah.analyst'
          Stage 2: Privilege Escalation via credential harvesting (mimikatz)
          Stage 3: Lateral Movement to Core Banking Server ('host:swift-core-srv')
          Stage 4: Bulk Database Exfiltration (50,000 credit records to foreign C2)
        """
        logs = []
        t = self.base_time + timedelta(minutes=15)
        attacker_ip = "198.51.100.42"
        target_user = "sarah.analyst"
        staging_host = "host:workstation-088"
        dc_host = "host:dc-prod-01"
        swift_host = "host:swift-core-srv"
        c2_ip = "203.0.113.88"

        # ── STAGE 1: Brute Force Attack ──────────────────────────────
        for i in range(12):
            t += timedelta(seconds=15)
            logs.append({
                "timestamp": t.isoformat(),
                "source": "winlogbeat",
                "event_type": "login",
                "severity": "medium",
                "user": target_user,
                "user_domain": "CORP_BANK",
                "user_privilege_level": "standard",
                "host": staging_host,
                "host_os": "windows",
                "ip": attacker_ip,
                "destination_ip": "10.10.1.88",
                "destination_port": 3389,
                "action": "failure",
                "resource": "logon_attempt",
                "outcome": "failure",
                "error_code": "STATUS_LOGON_FAILURE_0xC000006D",
                "metadata": {"attempt_num": i + 1, "protocol": "RDP"}
            })

        # Compromise: 13th attempt succeeds
        t += timedelta(seconds=10)
        logs.append({
            "timestamp": t.isoformat(),
            "source": "winlogbeat",
            "event_type": "login",
            "severity": "high",
            "user": target_user,
            "user_domain": "CORP_BANK",
            "user_privilege_level": "standard",
            "host": staging_host,
            "host_os": "windows",
            "ip": attacker_ip,
            "destination_ip": "10.10.1.88",
            "destination_port": 3389,
            "action": "success",
            "resource": "rdp_session",
            "outcome": "success",
            "metadata": {"auth_package": "Negotiate", "elevated": False}
        })

        # ── STAGE 2: Privilege Escalation & Credential Harvesting ─────
        t += timedelta(minutes=1)
        logs.append({
            "timestamp": t.isoformat(),
            "source": "winlogbeat",
            "event_type": "process",
            "severity": "high",
            "user": target_user,
            "user_domain": "CORP_BANK",
            "user_privilege_level": "admin",
            "host": staging_host,
            "host_os": "windows",
            "ip": "10.10.1.88",
            "action": "exec",
            "resource": "C:\\Windows\\System32\\cmd.exe",
            "process_name": "mimikatz.exe",
            "process_id": 4812,
            "parent_process": "powershell.exe",
            "outcome": "success",
            "metadata": {"command_line": "sekurlsa::logonpasswords", "suspicious": True}
        })

        t += timedelta(seconds=20)
        logs.append({
            "timestamp": t.isoformat(),
            "source": "winlogbeat",
            "event_type": "privilege",
            "severity": "critical",
            "user": target_user,
            "user_domain": "CORP_BANK",
            "user_privilege_level": "admin",
            "host": staging_host,
            "host_os": "windows",
            "ip": "10.10.1.88",
            "action": "escalate",
            "resource": "SeDebugPrivilege / SAM Database",
            "outcome": "success",
            "metadata": {"elevation_token": "token_admin_domain"}
        })

        # ── STAGE 3: Lateral Movement ────────────────────────────────
        t += timedelta(minutes=2)
        # Attacker pivots to Domain Controller via SMB 445
        logs.append({
            "timestamp": t.isoformat(),
            "source": "syslog",
            "event_type": "network",
            "severity": "high",
            "user": target_user,
            "host": staging_host,
            "ip": "10.10.1.88",
            "destination_ip": "10.10.0.5",  # DC
            "destination_port": 445,
            "action": "connect",
            "resource": "IPC$ / ADMIN$",
            "outcome": "success",
            "metadata": {"protocol": "SMBv2", "lateral_probe": True}
        })

        t += timedelta(seconds=15)
        logs.append({
            "timestamp": t.isoformat(),
            "source": "winlogbeat",
            "event_type": "process",
            "severity": "critical",
            "user": "admin.domain",
            "host": dc_host,
            "ip": "10.10.1.88",
            "action": "exec",
            "process_name": "psexec.exe",
            "process_id": 9920,
            "parent_process": "services.exe",
            "resource": "psexec_remote_service",
            "outcome": "success",
            "metadata": {"target": swift_host}
        })

        t += timedelta(seconds=30)
        # Attacker pivots from DC to SWIFT core server
        logs.append({
            "timestamp": t.isoformat(),
            "source": "winlogbeat",
            "event_type": "login",
            "severity": "critical",
            "user": "admin.domain",
            "host": swift_host,
            "ip": "10.10.0.5",
            "destination_port": 445,
            "action": "connect",
            "resource": "swift_financial_gateway",
            "outcome": "success",
            "metadata": {"session_type": "remote_admin"}
        })

        # ── STAGE 4: Database Bulk Access & Exfiltration ─────────────
        t += timedelta(minutes=2)
        logs.append({
            "timestamp": t.isoformat(),
            "source": "filebeat",
            "event_type": "database",
            "severity": "critical",
            "user": "admin.domain",
            "host": swift_host,
            "ip": "10.10.0.20",
            "destination_port": 5432,
            "action": "read",
            "resource": "core_banking.customer_accounts",
            "outcome": "success",
            "metadata": {
                "query": "SELECT * FROM customer_accounts, swift_transfers",
                "rows_returned": 52400,
                "data_volume_bytes": 157286400  # ~150 MB
            }
        })

        t += timedelta(seconds=45)
        logs.append({
            "timestamp": t.isoformat(),
            "source": "syslog",
            "event_type": "network",
            "severity": "critical",
            "user": "admin.domain",
            "host": swift_host,
            "ip": "10.10.0.20",
            "destination_ip": c2_ip,
            "destination_port": 8443,
            "action": "connect",
            "resource": "outbound_ssl_stream",
            "outcome": "success",
            "metadata": {
                "bytes_sent": 164000000,
                "protocol": "HTTPS_TUNNEL",
                "c2_exfiltration": True
            }
        })

        return logs


log_simulator = LogSimulator()
