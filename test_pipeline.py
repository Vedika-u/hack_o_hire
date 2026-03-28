"""
test_pipeline.py — SOC Pipeline Layer 1-2 Validation
======================================================
Tests the full pipeline end-to-end:
  1. Normalizer  — all log types produce valid UniversalEvent
  2. Elasticsearch — connection + index exists + doc count
  3. Firewall fields — ip, source_port, destination_port, protocol, direction

Usage:
    cd C:\\Users\\nandn\\OneDrive\\Desktop\\soc_ingestion
    venv\\Scripts\\activate
    python test_pipeline.py
"""

import sys
import json
import ssl
import urllib.request
import urllib.error
import base64
from datetime import datetime, timezone
from app.normalizer import normalize_to_universal_event

# ── Config ────────────────────────────────────────────────────────────────────
ES_HOST  = "https://localhost:9200"
ES_USER  = "elastic"
ES_PASS  = "381EAB8luuUzmdzan_P+"
INDEX    = "soc-logs"

PASS = "✅"
FAIL = "❌"
WARN = "⚠️ "

results = []


# ── ES HTTP helper ────────────────────────────────────────────────────────────
def _auth():
    return "Basic " + base64.b64encode(f"{ES_USER}:{ES_PASS}".encode()).decode()

_SSL = ssl.create_default_context()
_SSL.check_hostname = False
_SSL.verify_mode    = ssl.CERT_NONE

def _req(method, path, body=None):
    data    = json.dumps(body).encode() if body else None
    headers = {"Authorization": _auth(), "Content-Type": "application/json"}
    req     = urllib.request.Request(f"{ES_HOST}{path}", data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, context=_SSL, timeout=10) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def check(name, passed, detail=""):
    icon = PASS if passed else FAIL
    results.append(passed)
    print(f"  {icon}  {name}" + (f"  →  {detail}" if detail else ""))


# ── Test 1: Normalizer — Winlogbeat login event ───────────────────────────────
def test_winlogbeat():
    print("\n── Test 1: Winlogbeat login event ──")
    raw = {
        "source":     "winlogbeat",
        "event_type": "login",
        "action":     "success",
        "user":       "testuser",
        "host":       "LAPTOP-ABC123",
        "timestamp":  datetime.now(timezone.utc).isoformat(),
        "winlog":     {"event_id": "4624", "event_data": {"SubjectUserName": "testuser"}},
    }
    ev = normalize_to_universal_event(raw, topic="winlogbeat-raw")
    check("is_valid",    ev.get("is_valid"),           ev.get("validation_errors"))
    check("event_type",  ev.get("event_type") == "login",   ev.get("event_type"))
    check("action",      ev.get("action") == "success",     ev.get("action"))
    check("host_os",     ev.get("host_os") is not None,     ev.get("host_os"))
    check("user",        ev.get("user") == "testuser",      ev.get("user"))


# ── Test 2: Normalizer — EDR process event ───────────────────────────────────
def test_edr():
    print("\n── Test 2: EDR process event ──")
    raw = {
        "source":       "custom",
        "event_type":   "process",
        "action":       "exec",
        "process_name": "cmd.exe",
        "process_id":   1234,
        "user":         "SYSTEM",
        "host":         "DESKTOP-XYZ",
        "host_os":      "windows",
        "timestamp":    datetime.now(timezone.utc).isoformat(),
    }
    ev = normalize_to_universal_event(raw, topic="edr-raw")
    check("is_valid",      ev.get("is_valid"),                       ev.get("validation_errors"))
    check("process_name",  ev.get("process_name") == "cmd.exe",      ev.get("process_name"))
    check("process_id",    ev.get("process_id") == 1234,             ev.get("process_id"))
    check("host_os",       ev.get("host_os") == "windows",           ev.get("host_os"))
    check("privilege",     ev.get("user_privilege_level") is not None, ev.get("user_privilege_level"))


# ── Test 3: Normalizer — Firewall iptables event ─────────────────────────────
def test_firewall_iptables():
    print("\n── Test 3: Firewall iptables log ──")
    raw = {
        "source":  "syslog",
        "message": (
            "Jan 15 12:00:00 fw01 kernel: "
            "IN=eth0 OUT= MAC=aa:bb:cc SRC=192.168.1.50 DST=10.0.0.1 "
            "LEN=60 PROTO=TCP SPT=54321 DPT=443 ACCEPT"
        ),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    ev = normalize_to_universal_event(raw, topic="firewall-raw")
    check("is_valid",          ev.get("is_valid"),                            ev.get("validation_errors"))
    check("event_type",        ev.get("event_type") == "network",             ev.get("event_type"))
    check("ip",                ev.get("ip") == "192.168.1.50",                ev.get("ip"))
    check("destination_ip",    ev.get("destination_ip") == "10.0.0.1",        ev.get("destination_ip"))
    check("source_port",       ev.get("source_port") == 54321,                ev.get("source_port"))
    check("destination_port",  ev.get("destination_port") == 443,             ev.get("destination_port"))
    check("network_protocol",  ev.get("network_protocol") == "tcp",           ev.get("network_protocol"))
    check("network_direction", ev.get("network_direction") == "inbound",      ev.get("network_direction"))
    check("action",            ev.get("action") in ("allow","deny","drop"),   ev.get("action"))


# ── Test 4: Normalizer — CEF firewall event ───────────────────────────────────
def test_firewall_cef():
    print("\n── Test 4: Firewall CEF log ──")
    raw = {
        "source":  "syslog",
        "message": (
            "CEF:0|Palo Alto|PAN-OS|9.0|rule-001|Allow HTTPS|7|"
            "src=172.16.0.5 spt=12345 dst=8.8.8.8 dpt=443 proto=TCP act=allow"
        ),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    ev = normalize_to_universal_event(raw, topic="firewall-raw")
    check("is_valid",         ev.get("is_valid"),                          ev.get("validation_errors"))
    check("ip",               ev.get("ip") == "172.16.0.5",               ev.get("ip"))
    check("destination_ip",   ev.get("destination_ip") == "8.8.8.8",      ev.get("destination_ip"))
    check("destination_port", ev.get("destination_port") == 443,           ev.get("destination_port"))
    check("source_port",      ev.get("source_port") == 12345,              ev.get("source_port"))
    check("rule_id",          ev.get("rule_id") is not None,               ev.get("rule_id"))
    check("severity",         ev.get("severity") in ("low","medium","high","critical"), ev.get("severity"))


# ── Test 5: Elasticsearch connectivity ───────────────────────────────────────
def test_elasticsearch():
    print("\n── Test 5: Elasticsearch ──")
    status, resp = _req("GET", "/_cluster/health")
    check("reachable",     status == 200,                        f"status={status}")
    check("cluster green/yellow", resp.get("status") in ("green","yellow"), resp.get("status"))

    status, resp = _req("GET", f"/{INDEX}")
    check("soc-logs index exists", status == 200,                f"status={status}")

    status, resp = _req("GET", f"/{INDEX}/_count")
    count = resp.get("count", 0)
    check("has documents", count > 0,                            f"count={count}")

    # Verify ip field is mapped as 'ip' type (not text)
    status, resp = _req("GET", f"/{INDEX}/_mapping")
    props    = resp.get(INDEX, {}).get("mappings", {}).get("properties", {})
    ip_type  = props.get("ip", {}).get("type")
    ts_type  = props.get("timestamp", {}).get("type")
    check("ip field type=ip",        ip_type == "ip",   f"type={ip_type}")
    check("timestamp field type=date", ts_type == "date", f"type={ts_type}")


# ── Test 6: Dead-letter index exists ─────────────────────────────────────────
def test_dead_letter():
    print("\n── Test 6: Dead-letter index ──")
    status, _ = _req("GET", "/soc-dead-letter")
    check("soc-dead-letter index exists", status == 200, f"status={status}")


# ── Summary ───────────────────────────────────────────────────────────────────
def summary():
    total  = len(results)
    passed = sum(results)
    failed = total - passed
    print("\n" + "=" * 50)
    print(f"  RESULTS:  {passed}/{total} passed  |  {failed} failed")
    print("=" * 50)
    if failed:
        print("  Pipeline has issues — check failures above.")
        sys.exit(1)
    else:
        print("  ✅ All checks passed — pipeline is healthy.")


if __name__ == "__main__":
    print("=" * 50)
    print("  SOC Pipeline — Layer 1-2 Validation")
    print("=" * 50)

    test_winlogbeat()
    test_edr()
    test_firewall_iptables()
    test_firewall_cef()
    test_elasticsearch()
    test_dead_letter()
    summary()