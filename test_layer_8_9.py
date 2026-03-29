from elasticsearch import Elasticsearch
from fidelity.scoring_engine import FidelityScoringEngine
from rich import print
from rich.console import Console

console = Console()

# Connect to Elasticsearch
es = Elasticsearch("http://localhost:9200")


def test_all():
    console.rule("[bold blue]ACT-AWARE Layer 8 Test (Multiple Incidents)")

    # 🔹 Fetch valid incidents only
    res = es.search(
        index="act_aware_incidents",
        size=10,
        query={
            "exists": {
                "field": "detection_ids"
            }
        }
    )

    hits = res["hits"]["hits"]

    if not hits:
        print("[red]❌ No valid incidents found[/red]")
        return

    engine = FidelityScoringEngine(es)

    # 🔹 Process each incident
    for hit in hits:
        incident_id = hit["_id"]
        source = hit["_source"]

        pattern = source.get("pattern", "unknown")

        console.rule(f"[yellow]Incident: {pattern}[/yellow]")

        result = engine.score_incident(incident_id)

        print("[bold]Score:[/bold]", result["fidelity_score"])
        print("[bold]Confidence:[/bold]", result["confidence"])
        print("[bold]Stable:[/bold]", result["is_stable"])
        print("[bold]LLM Eligible:[/bold]", result["llm_eligible"])

    console.rule("[bold green]Test Complete")


if __name__ == "__main__":
    test_all()