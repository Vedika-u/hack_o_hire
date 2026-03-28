import json
import time
from kafka import KafkaProducer

producer = KafkaProducer(
    bootstrap_servers="127.0.0.1:9092",
    api_version=(0, 10, 1),
    value_serializer=lambda v: json.dumps(v).encode("utf-8")
)

print("🚀 Firewall Simulator running...")

event_count = 0

while True:
    event = {
        "source": "firewall_simulator",  # ✅ CHANGED from "syslog"
        "data_source": "network_firewall",  # ✅ ADDED
        "event_type": "network",
        "action": "allowed",
        "ip": "192.168.1.10",
        "destination_ip": "8.8.8.8",
        "destination_port": 443,
        "network_protocol": "tcp",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ")
    }

    producer.send("soc-logs", event)  # ✅ CHANGED from "firewall-raw"
    event_count += 1
    print(f"📤 Sent firewall log #{event_count}")
    time.sleep(2)