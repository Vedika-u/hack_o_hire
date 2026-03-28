import pandas as pd
from datetime import timedelta
from layer3_storage.es_client import get_es_client
from config import RAW_LOGS_INDEX, AGGREGATED_INDEX
from schemas import AggregatedBehavior, BehaviorFeatures


def fetch_logs():
    client = get_es_client()

    # ✅ UPDATED: Only fetch events with valid user and IP
    response = client.search(
        index=RAW_LOGS_INDEX,
        body={
            "query": {
                "bool": {
                    "must": [
                        {"exists": {"field": "user"}},
                        {"exists": {"field": "ip"}}
                    ],
                    "must_not": [
                        {"term": {"user": ""}},
                        {"term": {"user": "null"}}
                    ]
                }
            },
            "size": 10000  # ✅ Increased from 1000
        }
    )

    logs = [hit["_source"] for hit in response["hits"]["hits"]]
    
    # ✅ ADDED: Filter out None values in Python
    logs = [log for log in logs if log.get("user") is not None and log.get("user") != ""]
    
    print(f"📥 Fetched {len(logs)} events with valid user fields")
    
    df = pd.DataFrame(logs)

    if df.empty:
        print("⚠️  No logs found with valid user/ip after filtering")
        return df

    # Support integration/raw data variations
    if "timestamp" in df.columns:
        ts_col = "timestamp"
    elif "@timestamp" in df.columns:
        ts_col = "@timestamp"
    elif "ingested_at" in df.columns:
        ts_col = "ingested_at"
    else:
        print("❌ No timestamp-like field found in raw logs")
        print("Available columns:", list(df.columns))
        return pd.DataFrame()

    df["timestamp"] = pd.to_datetime(df[ts_col], format="ISO8601", utc=True, errors="coerce")
    df = df.dropna(subset=["timestamp"])
    df = df.sort_values("timestamp").reset_index(drop=True)
    
    print(f"✅ After timestamp parsing: {len(df)} valid events")

    return df


def aggregate_behavior():
    df = fetch_logs()

    if df.empty:
        return []

    # ✅ UPDATED: Safe defaults + handle None values
    if "event_id" not in df.columns:
        df["event_id"] = None
    if "event_type" not in df.columns:
        df["event_type"] = "unknown"
    if "action" not in df.columns:
        df["action"] = "unknown"
    if "user" not in df.columns:
        df["user"] = "unknown"

    # ✅ ADDED: Replace None/empty user values
    df["user"] = df["user"].fillna("unknown")
    df["user"] = df["user"].replace("", "unknown")

    # ✅ ADDED: Filter out rows where user is still invalid
    df = df[df["user"] != "unknown"]

    if df.empty:
        print("⚠️  No events remaining after filtering invalid users")
        return []

    print(f"✅ Processing {len(df)} events for aggregation")

    df["time_window"] = df["timestamp"].dt.floor("15min")

    aggregated = df.groupby(["user", "time_window"]).agg(
        event_count=("event_type", "count"),
        failed_logins=("action", lambda x: (x == "failure").sum()),
        successful_logins=("action", lambda x: (x == "success").sum()),
        admin_actions=("event_type", lambda x: (x == "privilege").sum()),
        unique_events=("event_type", "nunique"),
        source_event_ids=("event_id", lambda x: [str(i) for i in x if pd.notna(i)])
    ).reset_index()

    aggregated["fail_ratio"] = (
        aggregated["failed_logins"] / aggregated["event_count"]
    ).fillna(0.0)

    contract_records = []

    for _, row in aggregated.iterrows():
        features = BehaviorFeatures(
            login_fail_count=int(row["failed_logins"]),
            login_success_count=int(row["successful_logins"]),
            login_fail_ratio=float(row["fail_ratio"]),
            admin_action_count=int(row["admin_actions"]),
            unique_resources_accessed=int(row["unique_events"])
        )

        behavior = AggregatedBehavior(
            entity_id=str(row["user"]),
            entity_type="user",
            window_start=row["time_window"].to_pydatetime(),
            window_end=(row["time_window"] + timedelta(minutes=15)).to_pydatetime(),
            time_window="15min",
            event_count=int(row["event_count"]),
            source_event_ids=row["source_event_ids"],
            features=features
        )

        contract_records.append(behavior)

    print(f"✅ Aggregation completed: {len(contract_records)} AggregatedBehavior records")
    return contract_records


def store_aggregated(contract_records):
    client = get_es_client()

    for record in contract_records:
        client.index(
            index=AGGREGATED_INDEX,
            document=record.model_dump(mode="json")
        )

    print("✅ AggregatedBehavior records stored in Elasticsearch")


if __name__ == "__main__":
    records = aggregate_behavior()
    if records:
        store_aggregated(records)