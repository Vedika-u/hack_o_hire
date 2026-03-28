import json
import time
import random
from kafka import KafkaProducer
from datetime import datetime, UTC

# ✅ FIX: force IPv4
KAFKA_BROKER = "127.0.0.1:9092"

TOPIC = "edr-raw"

producer = KafkaProducer(
    bootstrap_servers=KAFKA_BROKER,
    value_serializer=lambda v: json.dumps(v).encode("utf-8")
)

USERS = ["nandn", "admin", "guest"]
PROCESSES = ["powershell.exe", "cmd.exe", "chrome.exe", "python.exe"]
SEVERITY = ["low", "medium", "high"]

def generate_event():
    return {
        "event_type": "process_start",
        "user": random.choice(USERS),
        "process_name": random.choice(PROCESSES),
        "severity": random.choice(SEVERITY),
        "timestamp": datetime.now(UTC).isoformat(),
        "source": "edr",
        "host": "LAPTOP-BUS150CH"
    }

print("🚀 EDR Simulator running...")

while True:
    event = generate_event()
    producer.send(TOPIC, event)
    print(f"📤 Sent: {event['process_name']} by {event['user']}")
    time.sleep(2)