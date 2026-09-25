from storage.es_client import es_client

playbook_id = "a88bb047-9b87-4156-a8b8-f6f71298a89d"

playbooks = es_client.search_documents(
    index="act_aware_playbooks",
    query={"query": {"match_all": {}}},
    size=3,
)

print(f"Total playbooks in storage: {len(playbooks)}")
print()

for playbook in playbooks:
    stored_id = playbook.get("playbook_id")
    print(f"playbook_id:  {stored_id}")
    print(f"Matches requested ID? {stored_id == playbook_id}")
    print("-" * 50)