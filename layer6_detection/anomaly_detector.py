# layer6_detection/anomaly_detector.py
"""
Layer 6: Anomaly Detection Engine (PyOD / Isolation Forest / LOF / HBOS)
Reads AggregatedBehavior records from 'act_aware_behaviors'.
Scores behavioral feature vectors using unsupervised anomaly detection models.
Writes DetectionOutput records conforming to Frozen Data Contract v1.1.0
to 'act_aware_detections'.
"""

from typing import List, Dict, Any, Optional
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor

from config.schemas import (
    AggregatedBehavior,
    DetectionOutput,
    ModelType,
    SeverityLevel,
    utc_now,
)
from storage.es_client import es_client
from config.settings import settings
import logging

logger = logging.getLogger(__name__)

FEATURE_KEYS = [
    "login_fail_ratio",
    "event_rate_per_minute",
    "login_attempt_velocity",
    "data_transfer_rate",
    "process_spawn_rate",
    "suspicious_process_count",
    "sensitive_resource_access_count",
    "privilege_escalation_attempts",
    "admin_action_count",
    "db_rows_accessed",
]


class AnomalyDetector:
    def __init__(self, model_type: ModelType = "isolation_forest", threshold: float = 0.65):
        self.model_type = model_type
        self.threshold = threshold
        self.es = es_client

    def score_behaviors(
        self, behaviors: List[AggregatedBehavior]
    ) -> List[DetectionOutput]:
        """
        Extracts feature vectors, trains/fits anomaly model,
        computes normalized scores, labels anomalies, and writes to act_aware_detections.
        """
        if not behaviors:
            return []

        # Build feature matrix
        matrix = []
        feature_dicts = []
        for b in behaviors:
            f = b.features
            row = [
                float(f.login_fail_ratio),
                float(f.event_rate_per_minute),
                float(f.login_attempt_velocity),
                float(f.data_transfer_rate),
                float(f.process_spawn_rate),
                float(f.suspicious_process_count),
                float(f.sensitive_resource_access_count),
                float(f.privilege_escalation_attempts),
                float(f.admin_action_count),
                float(f.db_rows_accessed),
            ]
            matrix.append(row)
            feature_dicts.append(dict(zip(FEATURE_KEYS, row)))

        X = np.array(matrix, dtype=float)

        # Baseline padding if small dataset
        if len(behaviors) < 5:
            # Add synthetic baseline reference rows (normal activity) to calibrate scores
            baseline_rows = np.zeros((10, len(FEATURE_KEYS)), dtype=float)
            baseline_rows[:, 0] = np.random.uniform(0.0, 0.05, 10)  # low login fails
            baseline_rows[:, 1] = np.random.uniform(1.0, 5.0, 10)   # low event rate
            X_fit = np.vstack([X, baseline_rows])
        else:
            X_fit = X

        # Fit model
        if self.model_type == "isolation_forest":
            clf = IsolationForest(contamination=0.25, random_state=42)
            clf.fit(X_fit)
            # decision_function: lower means more abnormal
            raw_scores = clf.decision_function(X)
            # Invert and normalize to [0, 1]
            min_s, max_s = raw_scores.min(), raw_scores.max()
            if max_s > min_s:
                norm_scores = 1.0 - ((raw_scores - min_s) / (max_s - min_s))
            else:
                norm_scores = np.zeros(len(raw_scores))
        elif self.model_type == "lof":
            lof = LocalOutlierFactor(n_neighbors=min(5, len(X_fit) - 1), novelty=False)
            lof.fit_predict(X_fit)
            raw_scores = -lof.negative_outlier_factor_[:len(X)]
            norm_scores = np.clip((raw_scores - 1.0) / 3.0, 0.0, 1.0)
        else:  # hbos or statistical
            # HBOS proxy: sum of normalized feature z-scores
            stds = np.std(X_fit, axis=0) + 1e-6
            means = np.mean(X_fit, axis=0)
            z_scores = np.abs((X - means) / stds)
            raw_scores = np.mean(z_scores, axis=1)
            norm_scores = np.clip(raw_scores / 3.0, 0.0, 1.0)

        detection_outputs: List[DetectionOutput] = []

        for i, b in enumerate(behaviors):
            score = float(norm_scores[i])
            raw = float(raw_scores[i])
            margin = round(score - self.threshold, 4)
            is_anomaly = score >= self.threshold

            # Severity classification
            if score >= 0.85 or margin >= 0.20:
                severity: SeverityLevel = "critical"
            elif score >= 0.72 or margin >= 0.08:
                severity: SeverityLevel = "high"
            elif score >= self.threshold:
                severity: SeverityLevel = "medium"
            else:
                severity: SeverityLevel = "low"

            # Top contributing features
            f_dict = feature_dicts[i]
            sorted_features = sorted(
                f_dict.items(),
                key=lambda item: item[1],
                reverse=True
            )
            top_feats = [k for k, v in sorted_features if v > 0][:5]
            if not top_feats:
                top_feats = [sorted_features[0][0]]

            detection = DetectionOutput(
                pipeline_id=b.pipeline_id,
                behavior_id=b.behavior_id,
                entity_id=b.entity_id,
                entity_type=b.entity_type,
                window_start=b.window_start,
                window_end=b.window_end,
                detected_at=utc_now(),
                model=self.model_type,
                model_version="1.1",
                anomaly_score=round(score, 4),
                raw_score=round(raw, 4),
                threshold_used=self.threshold,
                score_margin=margin,
                label="anomaly" if is_anomaly else "normal",
                severity=severity,
                features_used=f_dict,
                top_contributing_features=top_feats,
            )

            # Store to act_aware_detections
            doc = detection.model_dump()
            doc["window_start"] = detection.window_start.isoformat()
            doc["window_end"] = detection.window_end.isoformat()
            doc["detected_at"] = detection.detected_at.isoformat()
            self.es.store_detection(detection.detection_id, doc)
            detection_outputs.append(detection)

        logger.info(
            f"Evaluated {len(behaviors)} behaviors with {self.model_type}: "
            f"{sum(1 for d in detection_outputs if d.label == 'anomaly')} anomalies detected."
        )
        return detection_outputs


anomaly_detector = AnomalyDetector()
