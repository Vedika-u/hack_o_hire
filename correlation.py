import pandas as pd
from datetime import timedelta


def correlate_events(anomaly_results, raw_logs, time_window_minutes=15):
    if "timestamp" in raw_logs.columns:
        raw_logs["timestamp"] = pd.to_datetime(raw_logs["timestamp"])

    anomalous_entities = anomaly_results[
        anomaly_results["is_anomaly"] == 1
    ]["entity_id"].tolist()

    flagged_logs = raw_logs[raw_logs["entity_id"].isin(anomalous_entities)].copy()

    if flagged_logs.empty:
        print("No anomalous entities found in logs.")
        return pd.DataFrame()

    correlated = []

    for entity_id in anomalous_entities:
        entity_logs = flagged_logs[
            flagged_logs["entity_id"] == entity_id
        ].sort_values("timestamp")

        if entity_logs.empty:
            continue

        sources_involved = entity_logs["source"].unique().tolist()
        event_types = entity_logs["event_type"].tolist()
        time_span = (
            entity_logs["timestamp"].max() - entity_logs["timestamp"].min()
        ).seconds / 60

        score_row = anomaly_results[anomaly_results["entity_id"] == entity_id]
        ensemble_score = score_row["ensemble_score"].values[0] if not score_row.empty else 0.0

        correlated.append({
            "entity_id": entity_id,
            "sources": ", ".join(sources_involved),
            "source_count": len(sources_involved),
            "event_chain": " -> ".join(event_types),
            "time_span_mins": round(time_span, 2),
            "ensemble_score": round(ensemble_score, 4),
            "multi_source": len(sources_involved) > 1
        })

    result_df = pd.DataFrame(correlated)
    result_df = result_df.sort_values(
        ["multi_source", "ensemble_score"], ascending=[False, False]
    ).reset_index(drop=True)

    return result_df


if __name__ == "__main__":
    import numpy as np
    from detection import run_ensemble_detection, classify_severity

    np.random.seed(42)
    normal = np.random.randn(95, 10)
    anomaly = np.random.randn(5, 10) * 5 + 10
    X_demo = np.vstack([normal, anomaly])

    df_features = pd.DataFrame(X_demo, columns=[f"feature_{i}" for i in range(10)])
    df_features.insert(0, "entity_id", [f"entity_{i}" for i in range(100)])

    detection_results = run_ensemble_detection(df_features)
    detection_results["severity"] = detection_results["ensemble_score"].apply(classify_severity)

    anomalous_ids = detection_results[
        detection_results["is_anomaly"] == 1
    ]["entity_id"].tolist()

    sources = ["IAM", "EDR", "Firewall", "AppLog"]
    event_types = ["login_attempt", "privilege_escalation", "lateral_move", "data_exfil"]
    log_rows = []

    for eid in anomalous_ids:
        for j, (src, evt) in enumerate(zip(sources, event_types)):
            log_rows.append({
                "entity_id": eid,
                "source": src,
                "timestamp": pd.Timestamp("2025-01-01 02:00:00") + timedelta(minutes=j * 3),
                "event_type": evt
            })

    logs_df = pd.DataFrame(log_rows)

    print("Running correlation engine...")
    correlated = correlate_events(detection_results, logs_df)
    print("\nCorrelated Incidents:")
    print(correlated.to_string(index=False))
