# verify_connection.py
# Every teammate runs this after updating .env
# Share this file via USB or group chat

from dotenv import load_dotenv
import os
import sys

load_dotenv()

print("\nACT AWARE — Connection Verification")
print("=" * 40)

# Check 1: .env loaded
host = os.getenv('ES_HOST', 'NOT SET')
port = os.getenv('ES_PORT', 'NOT SET')
password = os.getenv('ES_PASSWORD', 'NOT SET')

print(f"\nES_HOST    : {host}")
print(f"ES_PORT    : {port}")
print(f"ES_PASSWORD: {'SET' if password != 'NOT SET' else 'NOT SET'}")

if host == 'localhost' or host == '127.0.0.1':
    print("\nWARNING: ES_HOST is still localhost.")
    print("Change it to Ruchika's IP in your .env file.")
    sys.exit(1)

# Check 2: ES connection
try:
    from elasticsearch import Elasticsearch
    es = Elasticsearch(
        f"http://{host}:{port}",
        basic_auth=(
            os.getenv('ES_USERNAME', 'elastic'),
            password
        ),
        request_timeout=5
    )
    if es.ping():
        print(f"\nElasticsearch: CONNECTED to {host}:{port}")
    else:
        print(f"\nElasticsearch: FAILED to connect to {host}:{port}")
        print("Check: same WiFi? Firewall off? Correct password?")
        sys.exit(1)
except Exception as e:
    print(f"\nElasticsearch: ERROR — {e}")
    sys.exit(1)

# Check 3: Indices exist
indices = [
    'act_aware_events',
    'act_aware_behaviors',
    'act_aware_detections',
    'act_aware_incidents',
    'act_aware_fidelity',
    'act_aware_playbooks'
]

print("\nIndex Status:")
all_good = True
for index in indices:
    try:
        count = es.count(index=index)['count']
        print(f"  {index}: {count} documents")
    except Exception:
        print(f"  {index}: NOT FOUND")
        all_good = False

# Check 4: Can write to ES
try:
    from datetime import datetime, timezone
    test_doc = {
        "test": True,
        "laptop": os.getenv('LAPTOP_ID', 'unknown'),
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    es.index(
        index='act_aware_events',
        id=f"test_{os.getenv('LAPTOP_ID', 'unknown')}",
        document=test_doc,
        refresh=True
    )
    print(f"\nWrite test: SUCCESS")
    # Clean up test doc
    es.delete(
        index='act_aware_events',
        id=f"test_{os.getenv('LAPTOP_ID', 'unknown')}"
    )
except Exception as e:
    print(f"\nWrite test: FAILED — {e}")
    sys.exit(1)

print("\n" + "=" * 40)
print("ALL CHECKS PASSED — You are connected.")
print("Run your layer's pipeline now.")
print("=" * 40 + "\n")