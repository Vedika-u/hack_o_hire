"""
apply_mapping.py
================
Run this ONCE before starting the consumer.
Deletes old soc-logs index and recreates it with correct field types.

Usage:
  python apply_mapping.py

If your ES password is different, change ES_PASSWORD below.
"""

import json
import urllib.request
import urllib.error
import ssl
import base64
import sys

# ─────────────────────────────────────────────────────────────
# CONFIG — change password if needed
# ─────────────────────────────────────────────────────────────
ES_HOST    = "https://localhost:9200"
ES_USER    = "elastic"
ES_PASS    = "381EAB8luuUzmdzan_P+"   # ← your password

MAIN_INDEX        = "soc-logs"
DEAD_LETTER_INDEX = "soc-dead-letter"

# ─────────────────────────────────────────────────────────────
# Full mapping — all 30+ fields with correct ES types
# ─────────────────────────────────────────────────────────────
MAIN_MAPPING = {
    "settings": {
        "number_of_shards":   1,
        "number_of_replicas": 0,
        "refresh_interval":   "5s"
    },
    "mappings": {
        "dynamic": "false",   # unknown fields accepted but not indexed
        "properties": {
            # ── Meta ───────────────────────────────────────
            "schema_version": {"type": "keyword"},
            "pipeline_id":    {"type": "keyword"},
            "event_id":       {"type": "keyword"},

            # ── Timing ─────────────────────────────────────
            "timestamp":      {"type": "date"},
            "ingested_at":    {"type": "date"},

            # ── ECS event.* ────────────────────────────────
            "event_kind":     {"type": "keyword"},
            "event_category": {"type": "keyword"},
            "event_type":     {"type": "keyword"},
            "action":         {"type": "keyword"},
            "outcome":        {"type": "keyword"},
            "severity":       {"type": "keyword"},
            "error_code":     {"type": "keyword"},

            # ── Source ─────────────────────────────────────
            "source":         {"type": "keyword"},
            "source_file":    {"type": "keyword"},

            # ── User ───────────────────────────────────────
            "user":                  {"type": "keyword"},
            "user_domain":           {"type": "keyword"},
            "user_privilege_level":  {"type": "keyword"},

            # ── Host ───────────────────────────────────────
            "host":    {"type": "keyword"},
            "host_os": {"type": "keyword"},

            # ── Network — ip type enables CIDR queries ──────
            "ip":                {"type": "ip"},
            "source_port":       {"type": "integer"},
            "destination_ip":    {"type": "ip"},
            "destination_port":  {"type": "integer"},
            "network_protocol":  {"type": "keyword"},
            "network_direction": {"type": "keyword"},
            "geo_country":       {"type": "keyword"},

            # ── Rule (firewall / IDS) ───────────────────────
            "rule_name": {"type": "keyword"},
            "rule_id":   {"type": "keyword"},

            # ── Process ────────────────────────────────────
            "process_name":   {"type": "keyword"},
            "process_id":     {"type": "integer"},
            "parent_process": {"type": "keyword"},

            # ── Resource (searchable + exact) ──────────────
            "resource": {
                "type": "text",
                "fields": {
                    "keyword": {"type": "keyword", "ignore_above": 512}
                }
            },

            # ── Pipeline quality ───────────────────────────
            "is_valid":          {"type": "boolean"},
            "validation_errors": {"type": "keyword"},

            # ── Catch-all (open object) ─────────────────────
            "metadata": {
                "type":    "object",
                "dynamic": True
            }
        }
    }
}

DEAD_LETTER_MAPPING = {
    "settings": {"number_of_shards": 1, "number_of_replicas": 0},
    "mappings": {
        "dynamic": True,
        "properties": {
            "dead_letter_reason": {"type": "text"},
            "original_topic":     {"type": "keyword"},
            "ingested_at":        {"type": "date"}
        }
    }
}


# ─────────────────────────────────────────────────────────────
# HTTP helper (no requests lib needed)
# ─────────────────────────────────────────────────────────────
def _auth_header() -> str:
    token = base64.b64encode(f"{ES_USER}:{ES_PASS}".encode()).decode()
    return f"Basic {token}"

# Skip SSL cert verification (self-signed ES cert on localhost)
_SSL_CTX = ssl.create_default_context()
_SSL_CTX.check_hostname = False
_SSL_CTX.verify_mode    = ssl.CERT_NONE


def _request(method: str, url: str, body: dict = None) -> tuple[int, dict]:
    data    = json.dumps(body).encode() if body else None
    headers = {
        "Authorization":  _auth_header(),
        "Content-Type":   "application/json",
    }
    req  = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, context=_SSL_CTX, timeout=10) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


# ─────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────
def apply(index: str, mapping: dict) -> None:
    print(f"\n── {index} ──────────────────────────────")

    # 1. Delete if exists
    status, _ = _request("DELETE", f"{ES_HOST}/{index}")
    if status in (200, 404):
        print(f"  DELETE  → {'removed' if status == 200 else 'did not exist'}")
    else:
        print(f"  DELETE  → unexpected status {status} (continuing anyway)")

    # 2. Create with mapping
    status, resp = _request("PUT", f"{ES_HOST}/{index}", mapping)
    if status == 200:
        print(f"  CREATE  → ✅ mapping applied")
    else:
        print(f"  CREATE  → ❌ FAILED  status={status}")
        print(f"           {json.dumps(resp, indent=2)}")
        sys.exit(1)

    # 3. Verify ip field type
    status, resp = _request("GET", f"{ES_HOST}/{index}/_mapping")
    if status == 200:
        props = resp.get(index, {}).get("mappings", {}).get("properties", {})
        ip_type = props.get("ip", {}).get("type", "NOT FOUND")
        ts_type = props.get("timestamp", {}).get("type", "NOT FOUND")
        print(f"  VERIFY  → ip={ip_type}  timestamp={ts_type}")
        if ip_type == "ip" and ts_type == "date":
            print(f"  RESULT  → ✅ All field types correct")
        else:
            print(f"  RESULT  → ⚠️  Types unexpected — check output above")
    else:
        print(f"  VERIFY  → could not fetch mapping (status {status})")


if __name__ == "__main__":
    print("=" * 55)
    print("  SOC Pipeline — Elasticsearch Mapping Setup")
    print("=" * 55)

    # Quick connectivity check
    status, _ = _request("GET", f"{ES_HOST}/_cluster/health")
    if status != 200:
        print(f"\n❌ Cannot reach Elasticsearch at {ES_HOST}")
        print("   Make sure Elasticsearch is running first.")
        sys.exit(1)
    print(f"\n✅ Elasticsearch reachable at {ES_HOST}")

    apply(MAIN_INDEX,        MAIN_MAPPING)
    apply(DEAD_LETTER_INDEX, DEAD_LETTER_MAPPING)

    print("\n" + "=" * 55)
    print("  ✅ Done — start the consumer now")
    print("=" * 55)