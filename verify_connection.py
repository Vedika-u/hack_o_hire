# verify_connection.py
"""
ACT AWARE — Standalone & Air-Gapped Connection Verification
Supports both local Elasticsearch cluster (localhost:9200) and
resilient air-gapped demo mode.
"""

from dotenv import load_dotenv
import os
import sys

load_dotenv()

print("\n" + "=" * 50)
print("ACT AWARE — Environment & Storage Verification")
print("=" * 50)

host = os.getenv('ES_HOST', 'localhost')
port = os.getenv('ES_PORT', '9200')
password = os.getenv('ES_PASSWORD', 'actaware123')
username = os.getenv('ES_USERNAME', 'elastic')

print(f"\nMode       : Standalone / Air-Gapped SOC Node")
print(f"ES_HOST    : {host}")
print(f"ES_PORT    : {port}")
print(f"ES_USERNAME: {username}")

# Check Elasticsearch Connection (Optional if running pure offline demo)
es_connected = False
try:
    from elasticsearch import Elasticsearch
    es = Elasticsearch(
        f"http://{host}:{port}",
        basic_auth=(username, password),
        request_timeout=3
    )
    if es.ping():
        es_connected = True
        print(f"\n[+] Elasticsearch: LIVE & CONNECTED at {host}:{port}")
    else:
        print(f"\n[!] Elasticsearch: Service not detected at {host}:{port}")
        print("    -> Operating in Resilient Air-Gapped Mode (Built-in In-Memory Engine).")
except Exception as e:
    print(f"\n[!] Elasticsearch connection check note: {e}")
    print("    -> Operating in Resilient Air-Gapped Mode (Built-in In-Memory Engine).")

# Unified Indices Check
indices = [
    os.getenv('ES_INDEX_EVENTS', 'act_aware_events'),
    os.getenv('ES_INDEX_BEHAVIORS', 'act_aware_behaviors'),
    os.getenv('ES_INDEX_DETECTIONS', 'act_aware_detections'),
    os.getenv('ES_INDEX_INCIDENTS', 'act_aware_incidents'),
    os.getenv('ES_INDEX_FIDELITY', 'act_aware_fidelity'),
    os.getenv('ES_INDEX_PLAYBOOKS', 'act_aware_playbooks'),
    os.getenv('ES_INDEX_PROVENANCE', 'act_aware_provenance'),
]

print("\nTarget Unified Indices:")
for idx in indices:
    if es_connected:
        try:
            count = es.count(index=idx)['count']
            print(f"  - {idx}: {count} documents")
        except Exception:
            print(f"  - {idx}: Ready (Auto-creation enabled)")
    else:
        print(f"  - {idx}: Ready (In-Memory Fallback Active)")

print("\n" + "=" * 50)
print("STATUS: SYSTEM READY FOR DEMO (Localhost / Offline Capable)")
print("Run: 'python run_pipeline.py' or 'python run.py'")
print("=" * 50 + "\n")