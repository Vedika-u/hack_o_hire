# integration/check_integration.py
# Run this to see the current integration state.
# Shows what data exists in each index and whether
# it is in a format your layer can consume.
#
# Usage: python integration/check_integration.py

import os
import sys
sys.path.append(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)

from elasticsearch import Elasticsearch
from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table
from rich import box

load_dotenv()

console = Console()


def get_es():
    return Elasticsearch(
        f"http://{os.getenv('ES_HOST', 'localhost')}:"
        f"{os.getenv('ES_PORT', '9200')}",
        basic_auth=(
            os.getenv('ES_USERNAME', 'elastic'),
            os.getenv('ES_PASSWORD', 'actaware123')
        )
    )


def check_index(es, index_name: str) -> dict:
    try:
        count = es.count(index=index_name)["count"]
        if count == 0:
            return {
                "count": 0,
                "sample": None,
                "status": "empty"
            }
        sample = es.search(
            index=index_name,
            body={"size": 1, "query": {"match_all": {}}}
        )
        doc = sample["hits"]["hits"][0]["_source"]
        return {
            "count": count,
            "sample_keys": list(doc.keys())[:8],
            "has_pipeline_id": "pipeline_id" in doc,
            "has_timestamp": any(
                k in doc for k in [
                    "timestamp", "created_at",
                    "detected_at", "window_start"
                ]
            ),
            "status": "ok"
        }
    except Exception as e:
        return {"count": 0, "status": f"error: {e}"}


def check_incident_readiness(es) -> dict:
    """
    Checks whether incidents have all the fields
    the fidelity engine needs.
    """
    from integration.layer_adapter import LayerAdapter
    adapter = LayerAdapter(es)

    incidents = adapter.get_incidents_for_scoring(
        limit=5, only_unscored=False
    )

    if not incidents:
        return {
            "ready": False,
            "reason": "No incidents found in index"
        }

    # Check first incident has required fields
    inc = incidents[0]
    required = [
        "incident_id", "pipeline_id", "entities",
        "primary_entity", "detection_ids",
        "pattern", "attack_stage", "severity",
        "graph_context"
    ]
    missing = [f for f in required if not inc.get(f)]

    if missing:
        return {
            "ready": False,
            "reason": f"Missing fields after adaptation: {missing}",
            "sample_incident": inc
        }

    return {
        "ready": True,
        "sample_count": len(incidents),
        "sample_pattern": inc.get("pattern"),
        "sample_severity": inc.get("severity")
    }


def main():
    es = get_es()

    console.print(
        "\n[bold cyan]ACT AWARE — Integration Status Check"
        "[/bold cyan]\n"
    )

    # Connection check
    try:
        es.ping()
        console.print(
            f"[green]✓ Elasticsearch connected: "
            f"{os.getenv('ES_HOST')}:"
            f"{os.getenv('ES_PORT')}[/green]\n"
        )
    except Exception as e:
        console.print(
            f"[red]✗ Cannot connect to Elasticsearch: {e}"
            f"[/red]"
        )
        return

    # Index health table
    indices = {
        "Layer 1-2: Events": "act_aware_events",
        "Layer 3-5: Behaviors": "act_aware_behaviors",
        "Layer 6-7: Detections": "act_aware_detections",
        "Layer 6-7: Incidents": "act_aware_incidents",
        "Layer 8: Fidelity": "act_aware_fidelity",
        "Layer 9: Playbooks": "act_aware_playbooks",
        "Layer 9: Provenance": "act_aware_provenance"
    }

    table = Table(
        title="Index Health",
        box=box.SIMPLE
    )
    table.add_column("Layer", style="cyan")
    table.add_column("Index")
    table.add_column("Documents", style="bold")
    table.add_column("pipeline_id?")
    table.add_column("Timestamp?")
    table.add_column("Status")

    for layer, index in indices.items():
        info = check_index(es, index)
        count = info.get("count", 0)
        status = info.get("status", "unknown")

        table.add_row(
            layer,
            index,
            str(count),
            "✓" if info.get("has_pipeline_id") else (
                "—" if count == 0 else "✗"
            ),
            "✓" if info.get("has_timestamp") else (
                "—" if count == 0 else "✗"
            ),
            f"[green]{status}[/green]"
            if status == "ok"
            else f"[yellow]{status}[/yellow]"
        )

    console.print(table)

    # Incident readiness for fidelity scoring
    console.print(
        "\n[bold]Checking incident readiness for "
        "fidelity scoring...[/bold]"
    )
    readiness = check_incident_readiness(es)

    if readiness["ready"]:
        console.print(
            f"[green]✓ Incidents ready for scoring[/green]"
        )
        console.print(
            f"  Sample count   : {readiness['sample_count']}"
        )
        console.print(
            f"  Sample pattern : {readiness['sample_pattern']}"
        )
        console.print(
            f"  Sample severity: {readiness['sample_severity']}"
        )
    else:
        console.print(
            f"[red]✗ Incidents not ready: "
            f"{readiness['reason']}[/red]"
        )
        if readiness.get("sample_incident"):
            console.print(
                f"  Sample keys: "
                f"{list(readiness['sample_incident'].keys())}"
            )

    # What to do next
    console.print("\n[bold]Next steps:[/bold]")

    from integration.layer_adapter import LayerAdapter
    adapter = LayerAdapter(es)
    health = adapter.check_index_health()

    if health["events"]["count"] == 0:
        console.print(
            "[yellow]  → Layer 1-2: Ask teammate to point "
            "Filebeat/Winlogbeat to your Mac IP[/yellow]"
        )
    else:
        console.print(
            f"[green]  ✓ Layer 1-2: "
            f"{health['events']['count']} events[/green]"
        )

    if health["behaviors"]["count"] == 0:
        console.print(
            "[yellow]  → Layer 3-5: Teammate needs to run "
            "aggregation pointing to your Mac IP[/yellow]"
        )

    if health["detections"]["count"] == 0:
        console.print(
            "[yellow]  → Layer 6-7: Teammate needs to run "
            "PyOD detection pointing to your Mac IP[/yellow]"
        )

    if health["incidents"]["count"] == 0:
        console.print(
            "[yellow]  → Layer 6-7: No incidents yet. "
            "Your synthetic data is your only source "
            "until she connects.[/yellow]"
        )

    console.print()


if __name__ == "__main__":
    main()