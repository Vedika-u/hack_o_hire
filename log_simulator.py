import json
import random
import time
from datetime import datetime, timezone
from kafka import KafkaProducer   # ✅ added

# ❌ OLD (removed)
# ENDPOINT = "http://localhost:8000/ingest/logs"

# ✅ NEW (Kafka)
KAFKA_BROKER = "127.0.0.1:9092"
TOPIC = "app-raw"

producer = KafkaProducer(
    bootstrap_servers=KAFKA_BROKER,
    value_serializer=lambda v: json.dumps(v).encode("utf-8")
)

NORMAL_USERS = [
    "rahul.sharma",
    "priya.patel",
    "amit.singh",
    "neha.gupta",
    "vikram.joshi"
]

ATTACKER = "ext_contractor_99"
ATTACKER_IP = "185.220.101.55"
INTERNAL_IPS = ["10.0.1.1", "10.0.1.2", "10.0.1.3", "10.0.2.1", "10.0.2.5"]

def utc_now():
    return datetime.now(timezone.utc).isoformat()

# ❌ OLD HTTP removed
# def send_log(log):
#     requests.post(...)

# ✅ NEW Kafka sender
def send_log(log):
    producer.send(TOPIC, log)
    print(f"📤 {log['user']} | {log['source']} | {log['event_type']} | {log['severity']}")

def send_normal_banking_logs(count=30):
    print("\n--- Normal banking activity ---")
    normal_events = [
        {"event_type": "customer_login", "source": "core_banking", "severity": "low"},
        {"event_type": "transaction_view", "source": "core_banking", "severity": "low"},
        {"event_type": "account_inquiry", "source": "customer_db", "severity": "low"},
        {"event_type": "loan_check", "source": "loan_system", "severity": "low"},
        {"event_type": "report_generate", "source": "core_banking", "severity": "low"},
        {"event_type": "user_login", "source": "iam", "severity": "low"},
        {"event_type": "atm_monitor", "source": "atm_network", "severity": "low"},
    ]
    for _ in range(count):
        event = random.choice(normal_events)
        log = {
            "source": "application",   # ✅ important for normalizer
            "event_type": "api_call",
            "severity": event["severity"],
            "message": f"Normal banking operation: {event['event_type']}",
            "host": f"bank-workstation-{random.randint(1,10)}",
            "host_os": "windows",
            "user": random.choice(NORMAL_USERS),
            "ip": random.choice(INTERNAL_IPS),
            "outcome": "success",
            "timestamp": utc_now()
        }
        send_log(log)
        time.sleep(0.3)

def send_banking_attack():
    print("\n--- Banking attack simulation ---")

    send_log({
        "source": "application",
        "event_type": "api_call",
        "severity": "critical",
        "message": "Unauthorized access",
        "host": "bank-server",
        "host_os": "linux",
        "user": ATTACKER,
        "ip": ATTACKER_IP,
        "outcome": "failure",
        "timestamp": utc_now()
    })

if __name__ == "__main__":
    print("=== Banking SOC Log Simulator ===")
    send_normal_banking_logs(30)
    send_banking_attack()