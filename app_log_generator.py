import json
import time
import random
from kafka import KafkaProducer
from datetime import datetime

# Kafka producer configuration
producer = KafkaProducer(
    bootstrap_servers="127.0.0.1:9092",
    value_serializer=lambda v: json.dumps(v).encode("utf-8")
)

USERS = ["rahul", "priya", "amit"]
IPS = ["10.0.0.1", "10.0.0.2", "192.168.1.5"]
ACTIONS = ["login", "logout", "api_call", "file_upload", "query"]
OUTCOMES = ["success", "failure"]
HOSTS = ["web-server-01", "app-server-02", "api-gateway-03"]

print("🚀 App Log Generator running - sending to Kafka topic 'soc-logs'...")
event_count = 0

while True:
    user = random.choice(USERS)
    ip = random.choice(IPS)
    action = random.choice(ACTIONS)
    outcome = random.choice(OUTCOMES)
    host = random.choice(HOSTS)
    
    # Create structured log event
    event = {
        "source": "app_log_generator",
        "data_source": "application_logs",
        "event_type": f"application.{action}",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "user": user,
        "ip": ip,
        "action": action,
        "outcome": outcome,
        "host": host,
        "host_os": "linux",
        "severity": "low" if outcome == "success" else "medium",
        "process_name": "app.py",
        "resource": f"/api/v1/{action}"
    }
    
    # Send to Kafka
    producer.send("soc-logs", value=event)
    event_count += 1
    
    print(f"📤 Sent app log #{event_count}: {user} | {action} | {outcome} | {ip}")
    
    time.sleep(2)