"""
graph_attack.py
Layer 7 — Graph-Based Attack Modeling
Team: Phoenix Core | ACT AWARE | Kanchan
Follows: config/schemas.py v1.1.0
"""

import sys
sys.path.insert(0, '.')

import networkx as nx
from datetime import timedelta
from uuid import uuid4
from collections import defaultdict

from config.schemas import (
    UniversalEvent, CorrelatedIncident, GraphContext,
    GraphNode, GraphEdge, utc_now
)


def build_entity_graph(events: list):
    """
    Build a directed graph from raw events.
    Nodes = entities (users, hosts, IPs)
    Edges = interactions between entities (who accessed what)
    """
    G = nx.DiGraph()

    for event in events:
        # Source entity (actor)
        actor = event.user or event.ip or "unknown"
        actor_type = "user" if event.user else "ip"

        # Target entity
        target = event.host or event.destination_ip or event.resource
        target_type = "host" if event.host else ("ip" if event.destination_ip else "service")

        if not target or actor == target:
            continue

        # Add nodes
        if actor not in G:
            G.add_node(actor, entity_type=actor_type, events=0, severity_max="low", risk_score=0.0)
        if target not in G:
            G.add_node(target, entity_type=target_type, events=0, severity_max="low", risk_score=0.0)

        # Update node stats
        G.nodes[actor]["events"] += 1
        severity_order = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        if severity_order.get(event.severity, 0) > severity_order.get(G.nodes[actor]["severity_max"], 0):
            G.nodes[actor]["severity_max"] = event.severity

        # Add or update edge
        relation = f"{event.event_type}_{event.action}"
        if G.has_edge(actor, target):
            G[actor][target]["weight"] += 1
            G[actor][target]["events"].append({
                "event_id": event.event_id,
                "timestamp": event.timestamp,
                "relation": relation
            })
        else:
            G.add_edge(actor, target,
                       weight=1,
                       relation=relation,
                       events=[{
                           "event_id": event.event_id,
                           "timestamp": event.timestamp,
                           "relation": relation
                       }])

    return G


def build_attack_chain_graph(incident: CorrelatedIncident):
    """
    Build a directed graph specifically for one incident's attack chain.
    Uses the timeline events to create an ordered chain.
    """
    G = nx.DiGraph()

    timeline = sorted(incident.timeline, key=lambda t: t.timestamp)

    for i, event in enumerate(timeline):
        node_id = f"{event.entity_id}:{event.action}"

        if node_id not in G:
            G.add_node(node_id,
                       entity_id=event.entity_id,
                       action=event.action,
                       severity=event.severity,
                       timestamp=event.timestamp,
                       step=i)

        # Connect to next event in chain
        if i < len(timeline) - 1:
            next_event = timeline[i + 1]
            next_node = f"{next_event.entity_id}:{next_event.action}"

            if next_node not in G:
                G.add_node(next_node,
                           entity_id=next_event.entity_id,
                           action=next_event.action,
                           severity=next_event.severity,
                           timestamp=next_event.timestamp,
                           step=i + 1)

            G.add_edge(node_id, next_node,
                       weight=1.0,
                       step=i,
                       time_gap=(next_event.timestamp - event.timestamp).total_seconds())

    return G


def calculate_centrality(G: nx.DiGraph):
    """Calculate various centrality metrics for the graph."""
    if G.number_of_nodes() == 0:
        return {}, None

    # Betweenness centrality — identifies pivot points
    try:
        betweenness = nx.betweenness_centrality(G)
    except:
        betweenness = {n: 0.0 for n in G.nodes()}

    # Degree centrality — identifies highly connected nodes
    try:
        degree = nx.degree_centrality(G)
    except:
        degree = {n: 0.0 for n in G.nodes()}

    # Combined centrality score
    centrality = {}
    for node in G.nodes():
        centrality[node] = round(
            betweenness.get(node, 0.0) * 0.6 + degree.get(node, 0.0) * 0.4,
            4
        )

    # Find pivot entity (highest centrality)
    pivot = max(centrality, key=centrality.get) if centrality else None

    return centrality, pivot


def detect_lateral_movement(G: nx.DiGraph, entity_id: str):
    """
    Detect if an entity shows lateral movement patterns.
    Lateral movement = accessing multiple different hosts/IPs.
    """
    if entity_id not in G:
        return False, 0, []

    # Get all nodes this entity connects to
    successors = list(G.successors(entity_id))

    # Filter for host/IP type targets
    host_targets = []
    for target in successors:
        target_data = G.nodes.get(target, {})
        target_type = target_data.get("entity_type", "")
        if target_type in ("host", "ip"):
            host_targets.append(target)

    # Lateral movement if accessing 3+ different hosts
    is_lateral = len(host_targets) >= 3

    return is_lateral, len(host_targets), host_targets


def estimate_blast_radius(G: nx.DiGraph, entry_node: str):
    """
    Estimate how many nodes are reachable from the entry point.
    This represents the potential impact of the attack.
    """
    if entry_node not in G:
        return 0, []

    try:
        reachable = nx.descendants(G, entry_node)
        return len(reachable), list(reachable)
    except:
        return 0, []


def find_critical_paths(G: nx.DiGraph, max_length: int = 6):
    """
    Find the longest/most critical attack paths in the graph.
    These represent the most dangerous attack chains.
    """
    critical_paths = []

    for node in G.nodes():
        try:
            for target in G.nodes():
                if node != target:
                    paths = list(nx.all_simple_paths(G, node, target, cutoff=max_length))
                    for path in paths:
                        if len(path) >= 3:
                            # Calculate path weight
                            total_weight = sum(
                                G[path[i]][path[i + 1]].get("weight", 1.0)
                                for i in range(len(path) - 1)
                                if G.has_edge(path[i], path[i + 1])
                            )
                            critical_paths.append({
                                "path": path,
                                "length": len(path),
                                "weight": total_weight,
                                "chain": " → ".join(path)
                            })
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            continue

    # Sort by length and weight
    critical_paths.sort(key=lambda p: (p["length"], p["weight"]), reverse=True)
    return critical_paths[:10]  # Top 10 paths


def enrich_incident_with_graph(incident: CorrelatedIncident, entity_graph: nx.DiGraph):
    """
    Enrich a CorrelatedIncident with full graph analysis.
    Returns updated GraphContext following schema v1.1.0.
    """
    entity_id = incident.primary_entity

    # Build attack chain graph for this incident
    chain_graph = build_attack_chain_graph(incident)

    # Calculate centrality on entity graph
    centrality, pivot = calculate_centrality(entity_graph)

    # Detect lateral movement
    is_lateral, host_count, targets = detect_lateral_movement(entity_graph, entity_id)

    # Estimate blast radius
    blast_size, reachable = estimate_blast_radius(entity_graph, entity_id)

    # Build GraphNode objects
    graph_nodes = []
    for node in entity_graph.nodes():
        node_data = entity_graph.nodes[node]
        graph_nodes.append(GraphNode(
            id=node,
            type=node_data.get("entity_type", "user"),
            label=f"{node_data.get('entity_type', 'entity')}:{node}",
            risk_score=round(centrality.get(node, 0.0) * 100, 2)
        ))

    # Build GraphEdge objects
    graph_edges = []
    for src, dst, data in entity_graph.edges(data=True):
        edge_events = data.get("events", [])
        if edge_events:
            latest_event = max(edge_events, key=lambda e: e["timestamp"])
            graph_edges.append(GraphEdge(
                source=src,
                target=dst,
                weight=data.get("weight", 1.0),
                relation=data.get("relation", "unknown"),
                timestamp=latest_event["timestamp"],
                event_id=latest_event["event_id"]
            ))

    # Build GraphContext
    graph_context = GraphContext(
        nodes=graph_nodes[:50],  # Limit for performance
        edges=graph_edges[:100],
        centrality_scores={k: round(v, 4) for k, v in centrality.items()},
        pivot_entity=pivot,
        lateral_movement_detected=is_lateral,
        subgraph_size=blast_size + 1  # Include entry node
    )

    # Update incident with graph context
    incident.graph_context = graph_context

    return incident, {
        "blast_radius": blast_size,
        "lateral_movement": is_lateral,
        "hosts_reached": host_count,
        "pivot_entity": pivot,
        "critical_paths": find_critical_paths(chain_graph, max_length=5),
        "total_nodes": entity_graph.number_of_nodes(),
        "total_edges": entity_graph.number_of_edges()
    }


def analyze_all_incidents(incidents: list, raw_events: list):
    """
    Run full graph analysis on all incidents.
    Returns enriched incidents with graph context.
    """
    if not incidents:
        return [], []

    # Build entity graph from all events
    entity_graph = build_entity_graph(raw_events)

    enriched_incidents = []
    analysis_reports = []

    for incident in incidents:
        enriched, report = enrich_incident_with_graph(incident, entity_graph)
        enriched_incidents.append(enriched)
        analysis_reports.append(report)

    return enriched_incidents, analysis_reports


if __name__ == "__main__":
    import numpy as np
    from detection import aggregate_events, run_ensemble_detection
    from correlation import correlate_events, merge_related_incidents

    print("=" * 60)
    print("  Layer 7 — Graph Attack Modeling Test")
    print("=" * 60)

    now = utc_now()
    test_events = []
    pipeline_id = f"test_{str(uuid4())[:8]}"

    # Normal users
    for i in range(15):
        test_events.append(UniversalEvent(
            timestamp=now - timedelta(minutes=np.random.randint(1, 15)),
            source="winlogbeat",
            event_type="login",
            action="success",
            severity="low",
            user=f"normal_{i:02d}",
            host=f"ws_{i:02d}",
            ip=f"192.168.1.{i + 10}",
            pipeline_id=pipeline_id
        ))

    # Brute force attacker
    for _ in range(12):
        test_events.append(UniversalEvent(
            timestamp=now - timedelta(minutes=np.random.randint(1, 5)),
            source="winlogbeat",
            event_type="login",
            action="failure",
            severity="high",
            user="brute_attacker",
            host="dc-01",
            ip="10.0.0.99",
            pipeline_id=pipeline_id
        ))

    # Lateral movement attacker
    for h in range(7):
        test_events.append(UniversalEvent(
            timestamp=now - timedelta(minutes=np.random.randint(1, 10)),
            source="syslog",
            event_type="network",
            action="connect",
            severity="medium",
            user="lateral_attacker",
            host=f"server_{h:02d}",
            ip="10.0.0.77",
            destination_ip=f"10.0.{h}.1",
            pipeline_id=pipeline_id
        ))

    # Data thief
    for evt, act in [("file", "read"), ("file", "read"), ("file", "read"),
                     ("database", "read"), ("database", "read"),
                     ("privilege", "escalate"), ("file", "write")]:
        test_events.append(UniversalEvent(
            timestamp=now - timedelta(minutes=np.random.randint(1, 10)),
            source="filebeat",
            event_type=evt,
            action=act,
            severity="high",
            user="data_thief",
            host="db-prod-01",
            ip="10.0.0.55",
            destination_ip="10.0.5.100",
            pipeline_id=pipeline_id
        ))

    print(f"\nTotal events: {len(test_events)}")

    # Run full pipeline
    behaviors = aggregate_events(test_events, pipeline_id)
    detections = run_ensemble_detection(behaviors, pipeline_id)
    incidents = correlate_events(detections, test_events)
    incidents = merge_related_incidents(incidents)

    print(f"Incidents before graph: {len(incidents)}")

    # Run graph analysis
    enriched, reports = analyze_all_incidents(incidents, test_events)

    print(f"Incidents enriched: {len(enriched)}")

    # Build full entity graph for stats
    full_graph = build_entity_graph(test_events)
    print(f"\nEntity Graph: {full_graph.number_of_nodes()} nodes, {full_graph.number_of_edges()} edges")

    for i, (incident, report) in enumerate(zip(enriched, reports)):
        print(f"\n{'═' * 55}")
        print(f"  INCIDENT {i + 1}: {incident.incident_id[:12]}...")
        print(f"{'═' * 55}")
        print(f"  Entity:          {incident.primary_entity}")
        print(f"  Pattern:         {incident.pattern}")
        print(f"  Stage:           {incident.attack_stage}")
        print(f"  Severity:        {incident.severity.upper()}")
        print(f"  Duration:        {incident.duration_minutes} min")
        print(f"  ─── Graph Analysis ───")
        print(f"  Blast Radius:    {report['blast_radius']} nodes reachable")
        print(f"  Lateral Move:    {'YES' if report['lateral_movement'] else 'NO'}")
        print(f"  Hosts Reached:   {report['hosts_reached']}")
        print(f"  Pivot Entity:    {report['pivot_entity']}")
        print(f"  Graph Size:      {report['total_nodes']} nodes, {report['total_edges']} edges")

        gc = incident.graph_context
        print(f"  Subgraph Size:   {gc.subgraph_size}")
        print(f"  Graph Nodes:     {len(gc.nodes)}")
        print(f"  Graph Edges:     {len(gc.edges)}")

        if report["critical_paths"]:
            print(f"  ─── Critical Paths ───")
            for p in report["critical_paths"][:3]:
                print(f"    [{p['length']} hops] {p['chain']}")

    print(f"\n{'=' * 60}")
    print("  Graph attack modeling test PASSED")
    print(f"{'=' * 60}")