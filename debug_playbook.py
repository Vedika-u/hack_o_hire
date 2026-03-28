# debug_playbook.py
from storage.es_client import es_client

# Search for the playbook by playbook_id field
results = es_client.client.search(
    index="act_aware_playbooks",
    body={
        "query": {
            "term": {
                "playbook_id.keyword": "a88bb047-9b87-4156-a8b8-f6f71298a89d"
            }
        }
    }
)

hits = results['hits']['hits']
print(f"Found: {len(hits)} documents")

if hits:
    print(f"ES _id (document ID): {hits[0]['_id']}")
    print(f"playbook_id field:    {hits[0]['_source'].get('playbook_id')}")
    print(f"Are they same?        {hits[0]['_id'] == hits[0]['_source'].get('playbook_id')}")