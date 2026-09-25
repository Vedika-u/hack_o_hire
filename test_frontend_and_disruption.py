# test_frontend_and_disruption.py
"""
Verify the Web SOC Dashboard and Disruption Benchmark APIs.
"""

from fastapi.testclient import TestClient
from control_plane.main import app

client = TestClient(app)

def test_frontend_dashboard():
    response = client.get("/")
    assert response.status_code == 200, f"Expected 200, got {response.status_code}"
    assert "BANKING SOC COMMAND CENTER" in response.text
    assert "Real-World Disruption Benchmark" in response.text
    print("[PASS] Web SOC Dashboard served at '/' successfully.")

def test_disruption_stats():
    response = client.get("/api/v1/disruption/stats")
    assert response.status_code == 200, f"Expected 200, got {response.status_code}"
    data = response.json()
    assert data["air_gapped_compliant"] is True
    assert data["scenarios_available"] == 8
    print(f"[PASS] Disruption stats verified: {data['scenarios_available']} scenarios, {data['csv_stream_logs_count']} CSV stream logs.")

def test_disruption_run():
    response = client.post("/api/v1/disruption/run")
    assert response.status_code == 200, f"Expected 200, got {response.status_code}"
    data = response.json()
    assert data["status"] == "success"
    summary = data["summary"]
    print(f"[PASS] Disruption Run Pipeline ID: {data['pipeline_id']}")
    print(f"       Total Telemetry Logs: {summary['total_raw_telemetry']}")
    print(f"       Dead-Letter Quarantined: {summary['dead_letter_quarantined']}")
    print(f"       Correlated Incidents: {summary['correlated_banking_incidents']}")
    print(f"       Alert Reduction Rate: {summary['alert_reduction_rate']}")
    assert summary["dead_letter_quarantined"] == 2
    assert summary["correlated_banking_incidents"] > 0
    print("[PASS] Full disruption benchmark API verified.")

if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("RUNNING FRONTEND & DISRUPTION BENCHMARK INTEGRATION TESTS")
    print("=" * 60)
    test_frontend_dashboard()
    test_disruption_stats()
    test_disruption_run()
    print("=" * 60)
    print("ALL TESTS PASSED SUCCESSFULLY! [PASS]")
    print("=" * 60 + "\n")
