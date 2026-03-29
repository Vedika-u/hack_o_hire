# fidelity/normalizer.py
# FIXED VERSION
# Key fix: cold start now uses anomaly_score directly
# instead of trying to normalize an incorrect raw_score

import os
import sys
sys.path.append(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)

from datetime import datetime, timezone, timedelta
from typing import Dict, Optional
from elasticsearch import Elasticsearch
from dotenv import load_dotenv

load_dotenv()


class ScoreNormalizer:
    """
    Normalizes raw PyOD scores to 0-1.

    COLD START FIX:
    When fewer than MIN_HISTORY_COUNT scores exist,
    we use the anomaly_score directly (it is already 0-1
    from PyOD's normalize parameter).
    We do NOT apply the 0.7 penalty on cold start —
    that was causing all scores to collapse near zero.
    We DO flag cold_start=True so fidelity engine can
    apply a mild discount at the component level if desired.
    """

    COLD_START_RANGES = {
        "isolation_forest": {"min": -0.4, "max": 0.0},
        "lof":              {"min": 1.0,  "max": 10.0},
        "hbos":             {"min": 0.0,  "max": 80.0}
    }

    MIN_HISTORY_COUNT = 10

    def __init__(self, es_client: Elasticsearch):
        self.es = es_client
        self.index = os.getenv(
            'ES_INDEX_DETECTIONS', 'act_aware_detections'
        )
        self._cache: Dict[str, dict] = {}
        self._cache_time: Optional[datetime] = None

    def _get_score_range(self, model: str) -> dict:
        now = datetime.now(timezone.utc)

        if (self._cache_time is None or
                (now - self._cache_time).seconds > 300):
            self._cache = {}
            self._cache_time = now

        if model in self._cache:
            return self._cache[model]

        try:
            result = self.es.search(
                index=self.index,
                body={
                    "size": 0,
                    "query": {
                        "bool": {
                            "must": [
                                {"term": {"model": model}},
                                {"range": {
                                    "detected_at": {
                                        "gte": (
                                            now - timedelta(hours=24)
                                        ).isoformat()
                                    }
                                }}
                            ]
                        }
                    },
                    "aggs": {
                        "min_score": {
                            "min": {"field": "raw_score"}
                        },
                        "max_score": {
                            "max": {"field": "raw_score"}
                        },
                        "count": {
                            "value_count": {"field": "raw_score"}
                        }
                    }
                }
            )

            count = result['aggregations']['count']['value']
            min_val = result['aggregations']['min_score']['value']
            max_val = result['aggregations']['max_score']['value']

            if count < self.MIN_HISTORY_COUNT or min_val is None:
                range_data = {
                    **self.COLD_START_RANGES.get(
                        model, {"min": 0.0, "max": 1.0}
                    ),
                    "cold_start": True,
                    "count": count
                }
            else:
                range_data = {
                    "min": min_val,
                    "max": max_val,
                    "cold_start": False,
                    "count": count
                }

            self._cache[model] = range_data
            return range_data

        except Exception as e:
            return {
                **self.COLD_START_RANGES.get(
                    model, {"min": 0.0, "max": 1.0}
                ),
                "cold_start": True,
                "count": 0,
                "error": str(e)
            }

    def normalize(
        self,
        raw_score: float,
        model: str,
        anomaly_score: float = None
    ) -> dict:
        """
        Normalizes a raw score.

        CRITICAL FIX:
        If cold_start=True AND anomaly_score is provided,
        return anomaly_score directly.
        PyOD already outputs a 0-1 normalized anomaly_score.
        There is no reason to re-normalize it through a
        potentially wrong historical range.
        """
        range_data = self._get_score_range(model)

        if range_data.get("cold_start") and anomaly_score is not None:
            # Use PyOD's own normalized score directly
            return {
                "normalized_score": round(
                    max(0.0, min(1.0, anomaly_score)), 4
                ),
                "cold_start": True,
                "range_used": {
                    "min": range_data["min"],
                    "max": range_data["max"]
                },
                "history_count": range_data.get("count", 0),
                "source": "anomaly_score_direct"
            }

        # Full historical normalization
        min_val = range_data["min"]
        max_val = range_data["max"]

        if max_val == min_val:
            normalized = anomaly_score if anomaly_score else 0.5
        else:
            normalized = (
                (raw_score - min_val) / (max_val - min_val)
            )
            normalized = max(0.0, min(1.0, normalized))

        return {
            "normalized_score": round(normalized, 4),
            "cold_start": range_data.get("cold_start", False),
            "range_used": {"min": min_val, "max": max_val},
            "history_count": range_data.get("count", 0),
            "source": "historical_normalization"
        }