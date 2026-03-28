from layer3_storage.es_client import get_es_client
from config import (
    RAW_LOGS_INDEX, AGGREGATED_INDEX, FEATURES_INDEX,
    ANOMALY_INDEX, POSTURE_INDEX, AUDIT_INDEX
)


def create_indices():
    """Create all required indices with proper mappings"""
    client = get_es_client()

    indices = {

        # ── Raw Logs (Layer 1-2 output) ──
        RAW_LOGS_INDEX: {
            "mappings": {
                "properties": {
                    "timestamp":      {"type": "date"},
                    "user":           {"type": "keyword"},
                    "event_type":     {"type": "keyword"},
                    "severity":       {"type": "keyword"},
                    "source":         {"type": "keyword"},
                    "source_ip":      {"type": "ip"},
                    "destination_ip": {"type": "ip"},
                    "action":         {"type": "keyword"},
                    "status":         {"type": "keyword"},
                    "message":        {"type": "text"}
                }
            }
        },

        # ── Aggregated Behavior (Layer 4 output) ──
        AGGREGATED_INDEX: {
            "mappings": {
                "properties": {
                    "user":                    {"type": "keyword"},
                    "time_window_start":       {"type": "date"},
                    "time_window_end":         {"type": "date"},
                    "event_count":             {"type": "integer"},
                    "unique_events":           {"type": "integer"},
                    "failed_logins":           {"type": "integer"},
                    "successful_logins":       {"type": "integer"},
                    "admin_actions":           {"type": "integer"},
                    "privilege_escalations":   {"type": "integer"},
                    "data_exports":            {"type": "integer"},
                    "config_changes":          {"type": "integer"},
                    "high_severity_count":     {"type": "integer"},
                    "critical_severity_count": {"type": "integer"},
                    "unique_sources":          {"type": "integer"},
                    "unique_ips":              {"type": "integer"},
                    "fail_ratio":              {"type": "float"},
                    "admin_ratio":             {"type": "float"},
                    "high_sev_ratio":          {"type": "float"},
                    "priv_esc_ratio":          {"type": "float"},
                    "data_export_ratio":       {"type": "float"},
                    "created_at":              {"type": "date"}
                }
            }
        },

        # ── User Features (Layer 5 tsfresh output) ──
        FEATURES_INDEX: {
            "mappings": {
                "properties": {
                    "user":          {"type": "keyword"},
                    "features":      {"type": "object", "enabled": False},
                    "feature_count": {"type": "integer"},
                    "created_at":    {"type": "date"}
                }
            }
        },

        # ── Anomaly Scores (Layer 5 PyOD output) ──
        ANOMALY_INDEX: {
            "mappings": {
                "properties": {
                    "user":            {"type": "keyword"},
                    "iforest_score":   {"type": "float"},
                    "iforest_label":   {"type": "integer"},
                    "lof_score":       {"type": "float"},
                    "lof_label":       {"type": "integer"},
                    "hbos_score":      {"type": "float"},
                    "hbos_label":      {"type": "integer"},
                    "ensemble_score":  {"type": "float"},
                    "ensemble_label":  {"type": "integer"},
                    "is_anomaly":      {"type": "boolean"},
                    "model_used":      {"type": "keyword"},
                    "created_at":      {"type": "date"}
                }
            }
        },

        # ── Posture Risk (Layer 4 posture output) ──
        POSTURE_INDEX: {
            "mappings": {
                "properties": {
                    "user":        {"type": "keyword"},
                    "risk_type":   {"type": "keyword"},
                    "risk_score":  {"type": "float"},
                    "event_count": {"type": "integer"},
                    "fail_ratio":  {"type": "float"},
                    "admin_ratio": {"type": "float"},
                    "details":     {"type": "text"},
                    "time_window": {"type": "date"},
                    "created_at":  {"type": "date"}
                }
            }
        },

        # ── Audit Logs (Governance) ──
        AUDIT_INDEX: {
            "mappings": {
                "properties": {
                    "action":    {"type": "keyword"},
                    "module":    {"type": "keyword"},
                    "user":      {"type": "keyword"},
                    "details":   {"type": "text"},
                    "timestamp": {"type": "date"}
                }
            }
        }
    }

    for index_name, body in indices.items():
        if not client.indices.exists(index=index_name):
            client.indices.create(index=index_name, body=body)
            print(f"  ✅ Created index: {index_name}")
        else:
            print(f"  ℹ️  Already exists: {index_name}")

    print(f"\n✅ All {len(indices)} indices ready!")


if __name__ == "__main__":
    create_indices()