from elasticsearch import Elasticsearch
from dotenv import load_dotenv
import os
import pandas as pd
from datetime import datetime, timedelta

load_dotenv(os.path.join(os.path.dirname(__file__), '..', '.env'))

ES_HOST = "https://localhost:9200"
ES_USERNAME = "elastic"
ES_PASSWORD = "381EAB8luuUzmdzan_P+"

INDEX_NAME = "soc-logs"

client = Elasticsearch(
    ES_HOST,
    basic_auth=(ES_USERNAME, ES_PASSWORD),
    verify_certs=False
)

def fetch_logs():
    response = client.search(
        index=INDEX_NAME,
        body={
            "query": {"match_all": {}},
            "size": 1000
        }
    )
    logs = [hit["_source"] for hit in response["hits"]["hits"]]
    return pd.DataFrame(logs)

def aggregate_by_user(df):
    if df.empty:
        print("No logs found!")
        return
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df = df.dropna(subset=["timestamp"])
    df = df.sort_values("timestamp")
    df["time_window"] = df["timestamp"].dt.floor("15min")

    aggregated = df.groupby(["user", "time_window"]).agg(
        event_count=("event_type", "count"),
        unique_events=("event_type", "nunique"),
        severity_counts=("severity", lambda x: x.value_counts().to_dict()),
        source_counts=("source", lambda x: x.value_counts().to_dict())
    ).reset_index()

    return aggregated


# ✅ NEW FUNCTION (OUTSIDE main)
def store_behaviors(aggregated):
    if aggregated is None or aggregated.empty:
        return

    for _, row in aggregated.iterrows():
        doc = {
            "user": row["user"],
            "time_window": row["time_window"].isoformat(),
            "event_count": int(row["event_count"]),
            "unique_events": int(row["unique_events"]),
            "severity_counts": row["severity_counts"],
            "source_counts": row["source_counts"],
        }

        client.index(
            index="soc-behaviors",
            document=doc
        )


def run_aggregation():
    print("Fetching logs from Elasticsearch...")
    df = fetch_logs()
    print(f"Found {len(df)} logs")

    aggregated = aggregate_by_user(df)

    print("\nAggregated behavioral states per user per 15min window:")
    print(aggregated)

    store_behaviors(aggregated)   # ✅ ADDED

    return aggregated


if __name__ == "__main__":
    run_aggregation()