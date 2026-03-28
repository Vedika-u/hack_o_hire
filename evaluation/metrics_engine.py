# evaluation/metrics_engine.py
"""
Evaluation and Metrics Engine for Layer 10.
Tracks system effectiveness and stores results in Elasticsearch.

Key Metrics:
1. Alert Reduction Rate — raw events vs actionable incidents
2. False Positive Rate — incidents marked wrong after review
3. Playbook Acceptance Rate — how often LLM playbooks are approved
4. Action Success Rate — executed actions that succeeded
"""

from config.settings import settings
from storage.es_client import es_client
from typing import Dict, Any
from uuid import uuid4
from datetime import datetime, timezone
import logging

logger = logging.getLogger(__name__)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class MetricsEngine:
    """
    Computes all system metrics and stores snapshots in Elasticsearch.
    Called by the metrics API endpoint.
    """

    def compute_all_metrics(self, time_range: str = "24h") -> Dict[str, Any]:
        """
        Compute all system metrics for the given time range.
        Stores result in Elasticsearch and returns it.
        """
        metrics = {
            "metrics_id": str(uuid4()),
            "computed_at": utc_now().isoformat(),
            "time_range": time_range,
            "alert_metrics": self._compute_alert_metrics(time_range),
            "playbook_metrics": self._compute_playbook_metrics(time_range),
            "action_metrics": self._compute_action_metrics(time_range),
        }

        # Store in Elasticsearch
        es_client.store_metrics(metrics["metrics_id"], metrics)
        logger.info(f"Metrics computed and stored: {metrics['metrics_id']}")

        return metrics

    def _compute_alert_metrics(self, time_range: str) -> Dict[str, Any]:
        """
        How effectively are we reducing alert noise?
        Reads from Layer 2 events index and Layer 7 incidents index.
        """
        # Count raw events from Layer 2
        total_events = es_client.count_events(
            query={
                "query": {
                    "range": {
                        "timestamp": {"gte": f"now-{time_range}"}
                    }
                }
            }
        )

        # Count incidents from Layer 7
        total_incidents = es_client.count_incidents(
            query={
                "query": {
                    "range": {
                        "created_at": {"gte": f"now-{time_range}"}
                    }
                }
            }
        )

        # Count high/critical incidents
        high_severity = es_client.count_incidents(
            query={
                "query": {
                    "bool": {
                        "must": [
                            {"range": {"created_at": {"gte": f"now-{time_range}"}}},
                            {"terms": {"severity": ["high", "critical"]}}
                        ]
                    }
                }
            }
        )

        # Calculate reduction rate
        reduction_rate = 0.0
        if total_events > 0:
            reduction_rate = round(1.0 - (total_incidents / total_events), 4)

        return {
            "total_raw_events": total_events,
            "total_incidents": total_incidents,
            "high_severity_incidents": high_severity,
            "alert_reduction_rate": reduction_rate,
            "reduction_percentage": f"{reduction_rate * 100:.2f}%",
        }

    def _compute_playbook_metrics(self, time_range: str) -> Dict[str, Any]:
        """
        How effective is the LLM playbook generation?
        Reads from our own playbooks index.
        """
        total_playbooks = es_client.count_playbooks(
            query={
                "query": {
                    "range": {
                        "generated_at": {"gte": f"now-{time_range}"}
                    }
                }
            }
        )

        approved_playbooks = es_client.count_playbooks(
            query={
                "query": {
                    "bool": {
                        "must": [
                            {"range": {"generated_at": {"gte": f"now-{time_range}"}}},
                            {"terms": {"status": ["approved", "executed"]}}
                        ]
                    }
                }
            }
        )

        rejected_playbooks = es_client.count_playbooks(
            query={
                "query": {
                    "bool": {
                        "must": [
                            {"range": {"generated_at": {"gte": f"now-{time_range}"}}},
                            {"match": {"status": "rejected"}}
                        ]
                    }
                }
            }
        )

        acceptance_rate = 0.0
        if total_playbooks > 0:
            acceptance_rate = round(approved_playbooks / total_playbooks, 4)

        return {
            "total_playbooks_generated": total_playbooks,
            "approved_playbooks": approved_playbooks,
            "rejected_playbooks": rejected_playbooks,
            "acceptance_rate": acceptance_rate,
            "acceptance_percentage": f"{acceptance_rate * 100:.2f}%",
        }

    def _compute_action_metrics(self, time_range: str) -> Dict[str, Any]:
        """
        How many SOAR actions executed and did they succeed?
        Reads from our audit log index.
        """
        total_actions = es_client.count_audit(
            query={
                "query": {
                    "bool": {
                        "must": [
                            {"match": {"action": "execute_soar_action"}},
                            {"range": {"timestamp": {"gte": f"now-{time_range}"}}}
                        ]
                    }
                }
            }
        )

        successful_actions = es_client.count_audit(
            query={
                "query": {
                    "bool": {
                        "must": [
                            {"match": {"action": "execute_soar_action"}},
                            {"match": {"outcome": "success"}},
                            {"range": {"timestamp": {"gte": f"now-{time_range}"}}}
                        ]
                    }
                }
            }
        )

        denied_actions = es_client.count_audit(
            query={
                "query": {
                    "bool": {
                        "must": [
                            {"match": {"action": "execute_soar_action_blocked"}},
                            {"range": {"timestamp": {"gte": f"now-{time_range}"}}}
                        ]
                    }
                }
            }
        )

        success_rate = 0.0
        if total_actions > 0:
            success_rate = round(successful_actions / total_actions, 4)

        return {
            "total_actions_executed": total_actions,
            "successful_actions": successful_actions,
            "denied_actions": denied_actions,
            "action_success_rate": success_rate,
            "success_percentage": f"{success_rate * 100:.2f}%",
        }


# Singleton
metrics_engine = MetricsEngine()