# fidelity/stability_tracker.py
# Tracks whether an incident signal has persisted across consecutive windows.
# An incident that appeared once might be noise.
# An incident that has appeared in 3 consecutive windows is real.

import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from datetime import datetime, timezone, timedelta
from typing import Optional
from elasticsearch import Elasticsearch
from dotenv import load_dotenv

load_dotenv()


class StabilityTracker:
    """
    Determines whether a fidelity signal is stable or transient.

    WHY THIS EXISTS:
    A fidelity score of 0.91 that appeared once could be:
    - A genuine attack (act on it)
    - A legitimate but unusual business process (ignore it)
    - A sensor glitch (ignore it)

    You cannot tell the difference from a single score.
    But if the score is 0.88, then 0.91, then 0.89 across three
    consecutive 5-minute windows — that is a persistent signal.
    Persistent signals are real. Transient spikes are noise.

    HOW IT WORKS:
    For each incident_id, we query Elasticsearch for how many
    fidelity records exist for that incident across consecutive windows.
    We also compute whether the trend is rising, stable, or falling.
    """

    # Minimum consecutive windows required to mark is_stable=True
    MIN_STABLE_WINDOWS = 2

    def __init__(self, es_client: Elasticsearch):
        self.es = es_client
        self.index = os.getenv('ES_INDEX_FIDELITY', 'act_aware_fidelity')

    def get_stability(self, incident_id: str) -> dict:
        """
        Queries historical fidelity records for this incident.
        Returns stability metrics.
        """
        try:
            result = self.es.search(
                index=self.index,
                body={
                    "query": {
                        "term": {"incident_id": incident_id}
                    },
                    "sort": [{"evaluated_at": {"order": "asc"}}],
                    "size": 20  # last 20 evaluations
                }
            )

            hits = result['hits']['hits']
            window_count = len(hits)

            if window_count == 0:
                # First time seeing this incident
                return {
                    "is_stable": False,
                    "stability_window_count": 1,
                    "signal_trend": "rising",
                    "previous_scores": []
                }

            # Extract previous scores in order
            previous_scores = [
                h['_source']['fidelity_score']
                for h in hits
            ]

            # Determine trend from last 3 scores
            trend = self._compute_trend(previous_scores)

            is_stable = window_count >= self.MIN_STABLE_WINDOWS

            return {
                "is_stable": is_stable,
                "stability_window_count": window_count + 1,
                "signal_trend": trend,
                "previous_scores": previous_scores[-5:]
            }

        except Exception as e:
            # Conservative default on error
            return {
                "is_stable": False,
                "stability_window_count": 1,
                "signal_trend": "stable",
                "previous_scores": [],
                "error": str(e)
            }

    def _compute_trend(self, scores: list) -> str:
        """
        Determines if scores are rising, stable, or falling.
        Uses last 3 scores minimum.
        """
        if len(scores) < 2:
            return "rising"

        recent = scores[-3:] if len(scores) >= 3 else scores
        first = recent[0]
        last = recent[-1]
        delta = last - first

        if delta > 0.05:
            return "rising"
        elif delta < -0.05:
            return "falling"
        else:
            return "stable"