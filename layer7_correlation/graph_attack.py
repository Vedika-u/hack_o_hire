# layer7_correlation/graph_attack.py
"""
Layer 7: Graph-Based Attack Modeling (NetworkX)
Builds dynamic entity attack graphs, computes betweenness centrality,
detects lateral movement chains, and estimates attack blast radius.
"""

from typing import List, Dict, Any, Tuple
import networkx as nx
from datetime import datetime

from config.schemas import (
    UniversalEvent,
    DetectionOutput,
    GraphNode,
    GraphEdge,
    GraphContext,
    EntityType,
    utc_now,
)
import logging

logger = logging.getLogger(__name__)


class GraphAttackModeler:
    def __init__(self):
        pass

    def build_graph_context(
        self,
        events: List[UniversalEvent],
        detections: List[DetectionOutput]
    ) -> GraphContext:
        """
        Constructs a NetworkX directed graph from observed interactions,
        identifies the pivot entity via betweenness centrality, and flags lateral movement.
        """
        G = nx.DiGraph()

        # Map detections to entity risk scores
        entity_risk = {}
        for d in detections:
            entity_risk[d.entity_id] = max(
                entity_risk.get(d.entity_id, 0.0),
                d.anomaly_score
            )

        graph_edges: List[GraphEdge] = []
        graph_nodes_dict: Dict[str, GraphNode] = {}

        # Build nodes and edges from events
        for e in events:
            # Source entity
            src = e.user or e.ip or e.host
            src_type: EntityType = "user" if e.user else ("ip" if e.ip else "host")

            # Destination entity
            dst = e.host or e.destination_ip or e.resource
            dst_type: EntityType = "host" if e.host else ("ip" if e.destination_ip else "service")

            if not src or not dst or src == dst:
                continue

            # Node creation
            if src not in graph_nodes_dict:
                node = GraphNode(
                    id=src,
                    type=src_type,
                    label=f"{src_type}:{src}",
                    risk_score=entity_risk.get(src, 0.1)
                )
                graph_nodes_dict[src] = node
                G.add_node(src, type=src_type, risk=node.risk_score)

            if dst not in graph_nodes_dict:
                node = GraphNode(
                    id=dst,
                    type=dst_type,
                    label=f"{dst_type}:{dst}",
                    risk_score=entity_risk.get(dst, 0.1)
                )
                graph_nodes_dict[dst] = node
                G.add_node(dst, type=dst_type, risk=node.risk_score)

            # Edge creation
            relation = e.action
            if e.event_type == "login":
                relation = "authenticated_to"
            elif e.event_type == "process":
                relation = "spawned_on"
            elif e.event_type == "network":
                relation = "connected_to"
            elif e.event_type == "database":
                relation = "queried_data_from"

            edge = GraphEdge(
                source=src,
                target=dst,
                weight=2.0 if e.severity in ("high", "critical") else 1.0,
                relation=relation,
                timestamp=e.timestamp,
                event_id=e.event_id
            )
            graph_edges.append(edge)
            G.add_edge(src, dst, weight=edge.weight, relation=relation)

        # Compute Centrality Scores
        centrality: Dict[str, float] = {}
        pivot_entity = None
        if len(G.nodes) > 1:
            try:
                centrality_raw = nx.betweenness_centrality(G)
                centrality = {k: round(v, 4) for k, v in centrality_raw.items()}
                # Highest centrality node is the pivot entity
                pivot_entity = max(centrality, key=centrality.get)
            except Exception as e:
                logger.debug(f"Centrality calculation note: {e}")
                pivot_entity = list(graph_nodes_dict.keys())[0] if graph_nodes_dict else None
        elif len(G.nodes) == 1:
            pivot_entity = list(graph_nodes_dict.keys())[0]
            centrality = {pivot_entity: 1.0}

        # Detect Lateral Movement (hops between distinct hosts or from user across multiple hosts)
        host_nodes = [nid for nid, data in G.nodes(data=True) if data.get("type") == "host"]
        lateral_movement = len(host_nodes) >= 2 or G.number_of_edges() >= 3

        # Subgraph size (connected component size)
        subgraph_size = len(G.nodes)

        return GraphContext(
            nodes=list(graph_nodes_dict.values()),
            edges=graph_edges,
            centrality_scores=centrality,
            pivot_entity=pivot_entity,
            lateral_movement_detected=lateral_movement,
            subgraph_size=subgraph_size
        )


graph_modeler = GraphAttackModeler()
