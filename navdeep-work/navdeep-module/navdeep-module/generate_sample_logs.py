from datetime import datetime, timedelta, timezone
import random
from layer3_storage.es_client import get_es_client
from config import RAW_LOGS_INDEX
from schemas import UniversalEvent

def map_to_contract_event(user, event, severity, source, timestamp):
    if event in ["login_success", "login_failed"]:
        event_type = "login"
        action = "success" if event == "login_success" else "failure"
        outcome = "success" if event == "login_success" else "failure"
    elif event == "admin_action":
        event_type = "privilege"
        action = "escalate"
        outcome = "success"
    else:
        event_type = "file"
        action = "read"
        outcome = "success"

    return UniversalEvent(
        timestamp=timestamp,
        source="custom",
        event_type=event_type,
        severity=severity,
        user=user,
        action=action,
        outcome=outcome,
        resource="sample_resource",
        metadata={
            "original_event_type": event,
            "source_label": source
        }
    )

def generate():
    client = get_es_client()

    users = ["alice", "bob", "charlie", "eve"]
    events = ["login_success", "login_failed", "admin_action", "file_access"]
    severities = ["low", "medium", "high"]
    sources = ["iam", "endpoint", "application"]

    base_time = datetime.now(timezone.utc) - timedelta(hours=2)

    for i in range(200):
        timestamp = base_time + timedelta(minutes=i)

        event = map_to_contract_event(
            user=random.choice(users),
            event=random.choice(events),
            severity=random.choice(severities),
            source=random.choice(sources),
            timestamp=timestamp
        )

        client.index(index=RAW_LOGS_INDEX, document=event.model_dump(mode="json"))

    print("✅ Sample logs generated in UniversalEvent format")

if __name__ == "__main__":
    generate()