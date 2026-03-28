import numpy as np
import pandas as pd
from pyod.models.iforest import IForest
from pyod.models.lof import LOF
from pyod.models.hbos import HBOS


def run_ensemble_detection(df, contamination=0.05):
    entity_ids = df["entity_id"] if "entity_id" in df.columns else None
    features = df.drop(columns=["entity_id"], errors="ignore")
    X = features.values

    iforest = IForest(contamination=contamination, random_state=42)
    iforest.fit(X)

    lof = LOF(contamination=contamination)
    lof.fit(X)

    hbos = HBOS(contamination=contamination)
    hbos.fit(X)

    ensemble_labels = (
        (iforest.labels_ + lof.labels_ + hbos.labels_) >= 2
    ).astype(int)

    def normalize(scores):
        mn, mx = scores.min(), scores.max()
        return np.zeros_like(scores) if mx == mn else (scores - mn) / (mx - mn)

    combined_score = (
        normalize(iforest.decision_scores_) +
        normalize(lof.decision_scores_) +
        normalize(hbos.decision_scores_)
    ) / 3

    return pd.DataFrame({
        "entity_id": entity_ids if entity_ids is not None else range(len(X)),
        "iforest_score": normalize(iforest.decision_scores_),
        "lof_score": normalize(lof.decision_scores_),
        "hbos_score": normalize(hbos.decision_scores_),
        "ensemble_score": combined_score,
        "is_anomaly": ensemble_labels
    })


def classify_severity(score):
    if score >= 0.75:
        return "HIGH"
    elif score >= 0.45:
        return "MEDIUM"
    return "LOW"


if __name__ == "__main__":
    import numpy as np
    np.random.seed(42)
    normal = np.random.randn(95, 10)
    anomaly = np.random.randn(5, 10) * 5 + 10
    X_demo = np.vstack([normal, anomaly])

    df_demo = pd.DataFrame(X_demo, columns=[f"feature_{i}" for i in range(10)])
    df_demo.insert(0, "entity_id", [f"entity_{i}" for i in range(100)])

    print("Running ensemble anomaly detection...")
    results = run_ensemble_detection(df_demo)
    results["severity"] = results["ensemble_score"].apply(classify_severity)

    print("\nAnomalies detected:")
    print(results[results["is_anomaly"] == 1][
        ["entity_id", "ensemble_score", "severity"]
    ].to_string(index=False))
