import pandas as pd
from tsfresh import extract_features
from tsfresh.utilities.dataframe_functions import impute

def aggregated_behavior_to_dataframe(contract_records):
    if not contract_records:
        return pd.DataFrame()

    rows = []
    for record in contract_records:
        rows.append({
            "user": record.entity_id,
            "behavior_id": record.behavior_id,
            "time_window": pd.to_datetime(record.window_start),
            "window_end": pd.to_datetime(record.window_end),
            "event_count": record.event_count,
            "fail_ratio": record.features.login_fail_ratio,
            "admin_action_count": record.features.admin_action_count,
            "unique_resources_accessed": record.features.unique_resources_accessed
        })

    return pd.DataFrame(rows)

def prepare_multimetric_timeseries(contract_records):
    aggregated = aggregated_behavior_to_dataframe(contract_records)

    if aggregated.empty:
        print("No aggregated contract data")
        return None

    metric_map = {
        "event_count": "event_count",
        "fail_ratio": "fail_ratio",
        "admin_action_count": "admin_action_count",
        "unique_resources_accessed": "unique_resources_accessed"
    }

    ts_frames = []

    for metric in metric_map:
        temp = aggregated[["user", "time_window", metric]].copy()
        temp = temp.rename(columns={
            "user": "id",
            "time_window": "time",
            metric: "value"
        })
        temp["id"] = temp["id"] + "__" + metric
        temp["time"] = temp["time"].astype("int64") // 10**9
        ts_frames.append(temp)

    ts_data = pd.concat(ts_frames, ignore_index=True)
    return ts_data

def combine_features_per_user(features):
    if features is None or features.empty:
        return None

    features = features.reset_index()
    features = features.rename(columns={"index": "id"})

    features["user"] = features["id"].apply(lambda x: x.split("__")[0])
    features["metric"] = features["id"].apply(lambda x: x.split("__")[1])

    combined = []

    for user in features["user"].unique():
        user_rows = features[features["user"] == user]
        combined_row = {"user": user}

        for _, row in user_rows.iterrows():
            metric = row["metric"]
            for col in features.columns:
                if col not in ["id", "user", "metric"]:
                    combined_row[f"{metric}__{col}"] = row[col]

        combined.append(combined_row)

    combined_df = pd.DataFrame(combined)
    combined_df = combined_df.set_index("user")
    return combined_df

def extract_features_from_aggregated(contract_records):
    ts_data = prepare_multimetric_timeseries(contract_records)

    if ts_data is None or ts_data.empty:
        print("No time series data")
        return None

    features = extract_features(
        ts_data,
        column_id="id",
        column_sort="time",
        column_value="value"
    )

    impute(features)

    combined_features = combine_features_per_user(features)

    print("✅ Feature extraction completed from AggregatedBehavior contract")
    print(combined_features.head())

    return combined_features