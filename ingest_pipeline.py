from elasticsearch import Elasticsearch
from dotenv import load_dotenv
import os

load_dotenv()

client = Elasticsearch(
    os.getenv("ES_HOST"),
    basic_auth=(os.getenv("ES_USERNAME"), os.getenv("ES_PASSWORD")),
    verify_certs=True,
    ca_certs=os.getenv("ES_CA_CERT")
)

pipeline = {
    "description": "SOC ECS normalization pipeline",
    "processors": [
        {
            "date": {
                "field": "timestamp",
                "target_field": "@timestamp",
                "formats": ["ISO8601"],
                "ignore_failure": True
            }
        },
        {
            "rename": {
                "field": "host.name",
                "target_field": "host.hostname",
                "ignore_missing": True
            }
        },
        {
            "geoip": {
                "field": "source.ip",
                "target_field": "source.geo",
                "ignore_missing": True,
                "ignore_failure": True
            }
        },
        {
            "set": {
                "field": "event.ingested",
                "value": "{{_ingest.timestamp}}"
            }
        },
        {
            "lowercase": {
                "field": "event.category",
                "ignore_missing": True
            }
        },
        {
            "lowercase": {
                "field": "event.type",
                "ignore_missing": True
            }
        }
    ]
}

def create_pipeline():
    try:
        client.ingest.put_pipeline(
            id="soc-ecs-pipeline",
            body=pipeline
        )
        print("✅ Ingest pipeline created: soc-ecs-pipeline")
    except Exception as e:
        print(f"❌ Error creating pipeline: {e}")

if __name__ == "__main__":
    create_pipeline()