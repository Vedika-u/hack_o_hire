from elasticsearch import Elasticsearch
from config import ES_URL, ES_USERNAME, ES_PASSWORD, ES_CA_CERT

def get_es_client():
    client = Elasticsearch(
        ES_URL,
        basic_auth=(ES_USERNAME, ES_PASSWORD) if ES_USERNAME and ES_PASSWORD else None,
        ca_certs=ES_CA_CERT if ES_CA_CERT else None,
        verify_certs=False if not ES_CA_CERT else True
    )

    print("Trying to connect to:", ES_URL)
    print("Using username:", ES_USERNAME)

    if not client.ping():
        raise ConnectionError("❌ Cannot connect to Elasticsearch")

    print("✅ Connected to Elasticsearch")
    return client