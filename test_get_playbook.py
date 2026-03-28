from storage.es_client import es_client

playbook_id = "a88bb047-9b87-4156-a8b8-f6f71298a89d"

# Check how it's stored in ES
result = es_client.client.search(
    index="act_aware_playbooks",
    body={
        "query": {"match_all": {}}
    },
    size=3
)

hits = result['hits']['hits']
print(f"Total playbooks in ES: {result['hits']['total']['value']}")
print()

for hit in hits:
    print(f"ES _id:       {hit['_id']}")
    print(f"playbook_id:  {hit['_source'].get('playbook_id')}")
    print(f"Same?         {hit['_id'] == hit['_source'].get('playbook_id')}")
    print("-" * 50)