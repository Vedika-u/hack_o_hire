# evaluation/feedback_loop.py
"""
Feedback Loop for Layer 10.
Analysts submit feedback on incidents (true/false positive).
This feedback is stored in Elasticsearch and used to trigger retraining.
"""

from config.settings import settings
from storage.es_client import es_client
from typing import Literal, Optional, Dict, Any
from uuid import uuid4
from datetime import datetime, timezone
import logging

logger = logging.getLogger(__name__)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class FeedbackLoop:
    """
    Stores analyst feedback in Elasticsearch.
    Checks if false positive rate exceeds threshold.
    Triggers retraining flag when needed.
    """

    # If FP rate exceeds this → flag for retraining
    FP_RATE_THRESHOLD = 0.15  # 15%

    def submit_feedback(
        self,
        incident_id: str,
        analyst_username: str,
        feedback_type: str,
        severity_accurate: bool = True,
        notes: str = "",
        playbook_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Submit analyst feedback on an incident.
        Stores result in Elasticsearch feedback index.

        feedback_type options:
          - true_positive:  Real attack, detection correct
          - false_positive: Not a real attack, detection wrong
          - needs_tuning:   Partially correct, severity was off
        """
        feedback_id = str(uuid4())

        record = {
            "feedback_id": feedback_id,
            "incident_id": incident_id,
            "playbook_id": playbook_id,
            "analyst_username": analyst_username,
            "feedback_type": feedback_type,
            "severity_accurate": severity_accurate,
            "notes": notes,
            "submitted_at": utc_now().isoformat(),
        }

        # Store in Elasticsearch
        es_client.store_feedback(feedback_id, record)

        logger.info(
            f"Feedback stored: {feedback_type} for incident "
            f"{incident_id} by {analyst_username}"
        )

        # Check if retraining is needed
        should_retrain = self._check_retraining_needed()

        return {
            "feedback_id": feedback_id,
            "feedback_type": feedback_type,
            "incident_id": incident_id,
            "retraining_triggered": should_retrain,
            "message": "Feedback recorded successfully",
        }

    def _check_retraining_needed(self) -> bool:
        """
        Check false positive rate over last 7 days.
        If rate exceeds threshold, flag for retraining.
        """
        total = es_client.count_feedback(
            query={
                "query": {
                    "range": {"submitted_at": {"gte": "now-7d"}}
                }
            }
        )

        if total < 10:
            # Not enough data to decide
            return False

        false_positives = es_client.count_feedback(
            query={
                "query": {
                    "bool": {
                        "must": [
                            {"match": {"feedback_type": "false_positive"}},
                            {"range": {"submitted_at": {"gte": "now-7d"}}}
                        ]
                    }
                }
            }
        )

        fp_rate = false_positives / total

        if fp_rate > self.FP_RATE_THRESHOLD:
            logger.warning(
                f"FALSE POSITIVE RATE HIGH: {fp_rate:.2%} "
                f"exceeds threshold {self.FP_RATE_THRESHOLD:.2%}. "
                f"Model retraining recommended."
            )
            return True

        return False

    def get_stats(self, time_range: str = "7d") -> Dict[str, Any]:
        """
        Get feedback statistics.
        Used by the feedback stats API endpoint.
        """
        total = es_client.count_feedback(
            query={
                "query": {
                    "range": {"submitted_at": {"gte": f"now-{time_range}"}}
                }
            }
        )

        true_positives = es_client.count_feedback(
            query={
                "query": {
                    "bool": {
                        "must": [
                            {"match": {"feedback_type": "true_positive"}},
                            {"range": {"submitted_at": {"gte": f"now-{time_range}"}}}
                        ]
                    }
                }
            }
        )

        false_positives = es_client.count_feedback(
            query={
                "query": {
                    "bool": {
                        "must": [
                            {"match": {"feedback_type": "false_positive"}},
                            {"range": {"submitted_at": {"gte": f"now-{time_range}"}}}
                        ]
                    }
                }
            }
        )

        fp_rate = round(false_positives / total, 4) if total > 0 else 0.0

        return {
            "time_range": time_range,
            "total_feedback": total,
            "true_positives": true_positives,
            "false_positives": false_positives,
            "false_positive_rate": fp_rate,
            "fp_percentage": f"{fp_rate * 100:.2f}%",
            "retraining_threshold": self.FP_RATE_THRESHOLD,
            "retraining_needed": fp_rate > self.FP_RATE_THRESHOLD,
        }


# Singleton
feedback_loop = FeedbackLoop()