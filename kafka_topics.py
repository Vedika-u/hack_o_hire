from kafka.admin import KafkaAdminClient, NewTopic
from kafka.errors import TopicAlreadyExistsError

KAFKA_BROKER = "localhost:9092"

TOPICS = [
    NewTopic(name="edr-raw",          num_partitions=3, replication_factor=1),
    NewTopic(name="firewall-raw",     num_partitions=3, replication_factor=1),
    NewTopic(name="iam-raw",          num_partitions=3, replication_factor=1),
    NewTopic(name="app-raw",          num_partitions=3, replication_factor=1),
    NewTopic(name="db-raw",           num_partitions=3, replication_factor=1),
    NewTopic(name="filebeat-raw",     num_partitions=3, replication_factor=1),
    NewTopic(name="winlogbeat-raw",   num_partitions=3, replication_factor=1),
    NewTopic(name="siem-alerts",      num_partitions=3, replication_factor=1),
]

def create_topics():
    admin_client = KafkaAdminClient(
        bootstrap_servers=KAFKA_BROKER,
        client_id="soc-admin"
    )
    for topic in TOPICS:
        try:
            admin_client.create_topics([topic])
            print(f"✅ Created topic: {topic.name}")
        except TopicAlreadyExistsError:
            print(f"⚠️ Topic already exists: {topic.name}")
        except Exception as e:
            print(f"❌ Error creating {topic.name}: {e}")

    admin_client.close()
    print("Done.")

if __name__ == "__main__":
    create_topics()