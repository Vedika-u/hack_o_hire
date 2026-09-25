# test_pipeline_and_api.py
"""
Integration test for ACT AWARE FastAPI Control Plane & End-to-End Pipeline
ASCII-only safe encoding for Windows terminals.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi.testclient import TestClient
from control_plane.main import app
from run_pipeline import run_act_aware_pipeline
from storage.es_client import es_client
from config.settings import settings


def test_api_and_pipeline():
    print("[1] Executing End-to-End Pipeline Run...")
    run_act_aware_pipeline()

    print("\n[2] Testing FastAPI Control Plane Endpoints...")
    client = TestClient(app)

    # Health Check
    res = client.get("/health")
    assert res.status_code == 200, f"Health check failed: {res.text}"
    print(f"  [PASS] /health -> {res.json()['status']}")

    # Root
    res = client.get("/")
    assert res.status_code == 200
    print(f"  [PASS] / -> {res.json()['system']}")

    # Auth token generation
    from control_plane.auth import create_access_token
    from control_plane.rbac import Role
    token = create_access_token({"sub": "vedika", "role": Role.SOC_MANAGER.value})
    headers = {"Authorization": f"Bearer {token}"}
    print("  [PASS] Created test JWT bearer token for SOC Manager (vedika)")

    # List Playbooks
    res = client.get("/api/v1/playbooks", headers=headers)
    assert res.status_code == 200, f"List playbooks failed: {res.text}"
    pb_list = res.json().get("playbooks", [])
    print(f"  [PASS] /api/v1/playbooks -> Found {len(pb_list)} playbook(s)")

    # Incidents
    res = client.get("/api/v1/incidents", headers=headers)
    assert res.status_code == 200, f"List incidents failed: {res.text}"
    incidents = res.json().get("incidents", [])
    print(f"  [PASS] /api/v1/incidents -> Found {len(incidents)} incident(s)")

    # Metrics
    res = client.get("/api/v1/metrics/dashboard?time_range=24h", headers=headers)
    assert res.status_code == 200, f"Metrics failed: {res.text}"
    print(f"  [PASS] /api/v1/metrics/dashboard -> Success")

    # Feedback stats
    res = client.get("/api/v1/feedback/stats?time_range=7d", headers=headers)
    assert res.status_code == 200, f"Feedback stats failed: {res.text}"
    print(f"  [PASS] /api/v1/feedback/stats -> Success")

    print("\n" + "=" * 50)
    print("ALL API AND PIPELINE INTEGRATION TESTS PASSED!")
    print("=" * 50)


if __name__ == "__main__":
    test_api_and_pipeline()
