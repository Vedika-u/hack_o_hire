from pyod.models.iforest import IForest
from sklearn.preprocessing import StandardScaler
from config import ANOMALY_INDEX
from layer3_storage.es_client import get_es_client
from schemas import DetectionOutput

def detect_anomalies(features, contract_records):
    if features is None or features.empty:
        print("No features found")
        return []

    scaler = StandardScaler()
    X = scaler.fit_transform(features)

    model = IForest(contamination=0.2)
    model.fit(X)

    labels = model.labels_
    scores = model.decision_function(X)

    # Map user -> latest AggregatedBehavior record
    latest_behavior = {}
    for record in contract_records:
        latest_behavior[record.entity_id] = record

    detections = []

    for i, user in enumerate(features.index):
        behavior = latest_behavior.get(user)
        if not behavior:
            continue

        detection = DetectionOutput(
            entity_id=user,
            entity_type="user",
            window_start=behavior.window_start,
            window_end=behavior.window_end,
            model="isolation_forest",
            anomaly_score=float(scores[i]),
            normalized_score=float(scores[i]),
            label="anomaly" if int(labels[i]) == 1 else "normal",
            threshold=0.2,
            features_used={},
            contributing_features=[],
            model_metadata={"contamination": 0.2},
            source_behavior_id=behavior.behavior_id
        )

        detections.append(detection)

    print("✅ DetectionOutput records created")
    for d in detections:
        print(d.entity_id, d.label, d.anomaly_score)

    return detections


def store_anomalies(detections):
    client = get_es_client()

    for detection in detections:
        client.index(
            index=ANOMALY_INDEX,
            document=detection.model_dump(mode="json")
        )

    print("✅ DetectionOutput records stored in Elasticsearch")