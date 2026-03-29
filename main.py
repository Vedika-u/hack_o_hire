# main.py
# INTEGRATION VERSION
# Tries real upstream data first.
# Falls back to synthetic data if upstream layers
# have not pushed data yet.
#
# Usage: python main.py
# Usage: python main.py --synthetic   (force synthetic)
# Usage: python main.py --real        (real data only, no fallback)

import os
import sys
from elasticsearch import Elasticsearch
from dotenv import load_dotenv
from loguru import logger
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

load_dotenv()

console = Console()

USE_SYNTHETIC = "--synthetic" in sys.argv
REAL_ONLY = "--real" in sys.argv


def get_es():
    return Elasticsearch(
        f"http://{os.getenv('ES_HOST', 'localhost')}:"
        f"{os.getenv('ES_PORT', '9200')}",
        basic_auth=(
            os.getenv('ES_USERNAME', 'elastic'),
            os.getenv('ES_PASSWORD', 'actaware123')
        )
    )


def run():
    from fidelity.scoring_engine import FidelityScoringEngine
    from reasoning.agent import SOCReasoningAgent
    from reasoning.provenance_logger import ProvenanceLogger
    from integration.layer_adapter import LayerAdapter

    console.print(Panel(
        "[bold cyan]ACT AWARE — Full Pipeline[/bold cyan]\n"
        f"ES Host: {os.getenv('ES_HOST')}:"
        f"{os.getenv('ES_PORT')}",
        box=box.DOUBLE
    ))

    es = get_es()
    adapter = LayerAdapter(es)
    engine = FidelityScoringEngine(es)
    agent = SOCReasoningAgent()
    provenance = ProvenanceLogger(es)

    # ── Determine data source ──────────────────────────────────
    incidents_to_score = []

    if not USE_SYNTHETIC:
        console.print(
            "\n[yellow]Checking for real upstream data...[/yellow]"
        )
        real_incidents = adapter.get_incidents_for_scoring(
            limit=20,
            only_unscored=True
        )

        if real_incidents:
            console.print(
                f"[green]✓ Found {len(real_incidents)} real "
                f"unscored incidents from upstream layers"
                f"[/green]"
            )
            incidents_to_score = real_incidents
        else:
            if REAL_ONLY:
                console.print(
                    "[red]No real incidents found and "
                    "--real flag is set. Exiting.[/red]"
                )
                return
            console.print(
                "[yellow]No real incidents found. "
                "Falling back to synthetic data.[/yellow]"
            )

    if not incidents_to_score:
        # Use synthetic data
        from tests.synthetic_incidents import generate_and_push
        console.print(
            "\n[yellow]Generating synthetic test data..."
            "[/yellow]"
        )
        generated = generate_and_push()

        # Fetch the generated incidents through the adapter
        # so they go through the same normalization path
        for g in generated:
            try:
                result = es.get(
                    index=os.getenv(
                        'ES_INDEX_INCIDENTS',
                        'act_aware_incidents'
                    ),
                    id=g["incident_id"]
                )
                adapted = adapter._adapt_incident(
                    result['_source'],
                    g["incident_id"]
                )
                if adapted:
                    adapted["_expected_fidelity"] = (
                        g.get("expected_fidelity")
                    )
                    incidents_to_score.append(adapted)
            except Exception as e:
                logger.error(
                    f"Could not fetch generated incident: {e}"
                )

        console.print(
            f"[green]✓ {len(incidents_to_score)} synthetic "
            f"incidents ready[/green]"
        )

    # ── Fidelity scoring ───────────────────────────────────────
    console.print(
        "\n[bold yellow]FIDELITY SCORING (Layer 8)"
        "[/bold yellow]"
    )

    scored = []
    for inc in incidents_to_score:
        incident_id = inc["incident_id"]

        # Write adapted incident back to ES
        # (in case it came from upstream with missing fields)
        es.index(
            index=os.getenv(
                'ES_INDEX_INCIDENTS', 'act_aware_incidents'
            ),
            id=incident_id,
            document=inc,
            refresh=True
        )

        result = engine.score_incident(incident_id)
        if result:
            entry = {
                "incident_id": incident_id,
                "pattern": inc.get("pattern", "unknown"),
                "fidelity_score": result["fidelity_score"],
                "confidence": result["confidence"],
                "is_stable": result["is_stable"],
                "llm_eligible": result["llm_eligible"],
                "fidelity_id": result["fidelity_id"],
                "permitted_actions": result["permitted_actions"],
                "pipeline_id": result["pipeline_id"]
            }
            if inc.get("_expected_fidelity"):
                entry["expected"] = inc["_expected_fidelity"]
            scored.append(entry)

    # Print scoring table
    table = Table(
        title="Fidelity Scoring Results",
        box=box.SIMPLE
    )
    table.add_column("Pattern", style="cyan")
    table.add_column("Score", style="bold")
    table.add_column("Confidence")
    table.add_column("Stable")
    table.add_column("LLM Eligible")

    for s in scored:
        score = s["fidelity_score"]
        color = (
            "red" if score < 0.50 else
            "yellow" if score < 0.75 else
            "green"
        )
        table.add_row(
            s["pattern"],
            f"[{color}]{score}[/{color}]",
            s["confidence"],
            "✓" if s["is_stable"] else "✗",
            "✓" if s["llm_eligible"] else "✗"
        )

    console.print(table)

    # ── Reasoning on eligible incidents ───────────────────────
    console.print(
        "\n[bold yellow]AGENTIC REASONING (Layer 9)"
        "[/bold yellow]"
    )

    eligible = [s for s in scored if s["llm_eligible"]]

    if not eligible:
        console.print(
            "[yellow]No LLM-eligible incidents. "
            "All incidents below 0.75 fidelity or unstable."
            "[/yellow]"
        )
    else:
        console.print(
            f"[green]{len(eligible)} incident(s) eligible "
            f"for AI reasoning[/green]"
        )

        for inc in eligible:
            console.print(
                f"\n  [cyan]→ {inc['pattern']} "
                f"(score: {inc['fidelity_score']})[/cyan]"
            )

            result = agent.run(
                incident_id=inc["incident_id"],
                fidelity_id=inc["fidelity_id"],
                requested_by="demo_analyst"
            )

            if result["success"]:
                console.print(
                    f"  [green]✓ Playbook: "
                    f"{result['playbook_id']}[/green]"
                )
                console.print(
                    f"  Steps: {result['steps_count']} | "
                    f"Status: pending_review"
                )
                narrative = result.get(
                    "threat_narrative", ""
                )
                if narrative:
                    console.print(
                        f"  [dim]{narrative[:100]}..."
                        f"[/dim]"
                    )

                trail = provenance.get_full_trail(
                    result.get("pipeline_id", "")
                )
                console.print(
                    f"  [dim]Provenance records: "
                    f"{len(trail)}[/dim]"
                )
            else:
                reason = (
                    result.get("termination_reason") or
                    result.get("llm_error") or
                    result.get("error")
                )
                console.print(
                    f"  [red]✗ {reason}[/red]"
                )

    # ── Final summary ──────────────────────────────────────────
    health = adapter.check_index_health()
    console.print(Panel(
        f"Events ingested    : "
        f"{health['events']['count']}\n"
        f"Behaviors computed : "
        f"{health['behaviors']['count']}\n"
        f"Detections scored  : "
        f"{health['detections']['count']}\n"
        f"Incidents created  : "
        f"{health['incidents']['count']}\n"
        f"Fidelity records   : "
        f"{health['fidelity']['count']}\n"
        f"Playbooks generated: "
        f"{health['playbooks']['count']}\n"
        f"Provenance records : "
        f"{health['provenance']['count']}",
        title="[bold]System State[/bold]",
        box=box.SIMPLE
    ))


if __name__ == "__main__":
    run()