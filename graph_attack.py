import networkx as nx
import pandas as pd


def build_attack_graph(correlated_df):
    G = nx.DiGraph()

    for _, row in correlated_df.iterrows():
        entity = row["entity_id"]
        chain = row["event_chain"].split(" -> ")
        score = row["ensemble_score"]

        G.add_node(entity, score=score, sources=row["sources"])

        for i in range(len(chain) - 1):
            src_node = f"{entity}:{chain[i]}"
            dst_node = f"{entity}:{chain[i+1]}"
            G.add_node(src_node, event=chain[i])
            G.add_node(dst_node, event=chain[i+1])
            G.add_edge(src_node, dst_node, weight=score)

    return G


def detect_lateral_movement(G):
    lateral_paths = []
    nodes = list(G.nodes)

    for src in nodes:
        for dst in nodes:
            if src != dst:
                try:
                    paths = list(nx.all_simple_paths(G, src, dst, cutoff=5))
                    for path in paths:
                        if len(path) > 2:
                            lateral_paths.append({
                                "from": src,
                                "to": dst,
                                "path_len": len(path),
                                "path": " -> ".join(path)
                            })
                except nx.NetworkXNoPath:
                    continue

    return lateral_paths


def estimate_blast_radius(G, entry_node):
    if entry_node not in G:
        return {"entry_node": entry_node, "reachable_nodes": 0, "nodes": []}

    reachable = nx.descendants(G, entry_node)
    return {
        "entry_node": entry_node,
        "reachable_nodes": len(reachable),
        "nodes": list(reachable)
    }


def classify_incident(score, blast_radius, lateral_paths):
    if score >= 0.75 or blast_radius > 5 or lateral_paths > 3:
        return "HIGH"
    elif score >= 0.45 or blast_radius > 2 or lateral_paths > 1:
        return "MEDIUM"
    return "LOW"


if __name__ == "__main__":
    import numpy as np
    from datetime import timedelta
    from detection import run_ensemble_detection, classify_severity
    from correlation import correlate_events

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
    correlated = correlate_events(detection_results, logs_df)

    print("Building attack graph...")
    G = build_attack_graph(correlated)
    print(f"Graph: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges")

    print("\nDetecting lateral movement...")
    lateral = detect_lateral_movement(G)
    print(f"Lateral movement paths found: {len(lateral)}")

    if anomalous_ids:
        entry = f"{anomalous_ids[0]}:login_attempt"
        blast = estimate_blast_radius(G, entry)
        print(f"\nBlast radius from {blast['entry_node']}: {blast['reachable_nodes']} nodes")

        final_score = correlated.iloc[0]["ensemble_score"] if not correlated.empty else 0.5
        severity = classify_incident(final_score, blast["reachable_nodes"], len(lateral))
        print(f"Final Incident Classification: {severity}")
