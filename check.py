import sys
sys.path.insert(0, '.')
from dotenv import load_dotenv
import os
load_dotenv()

print("ES_HOST:", os.getenv("ES_HOST"))
print("INDEX_NAME:", os.getenv("INDEX_NAME"))

from elasticsearch import Elasticsearch
host = os.getenv("ES_HOST", "")
user = os.getenv("ES_USERNAME", "elastic")
password = os.getenv("ES_PASSWORD", "")

if host:
    try:
        es = Elasticsearch(host, basic_auth=(user, password), verify_certs=False)
        if es.ping():
            print("\n✅ Elasticsearch CONNECTED!")
            indexes = es.indices.get_alias(index="*")
            print("Available indexes:")
            for idx in indexes:
                print(f"  - {idx}")
        else:
            print("\n❌ Ping FAILED!")
    except Exception as e:
        print(f"\n❌ Error: {e}")