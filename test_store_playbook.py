# test_store_playbook.py
from storage.es_client import es_client

playbook_id = "a88bb047-9b87-4156-a8b8-f6f71298a89d"

# Get current state
current = es_client.get_playbook(playbook_id)
print(f"Current status: {current.get('status')}")
print(f"Current approved: {current['steps'][0].get('approved')}")

# Test update
current['steps'][0]['approved'] = True
current['steps'][0]['approved_by'] = "test_analyst"
current['status'] = "approved"

result = es_client.store_playbook(playbook_id, current)
print(f"\nStore result: {result}")

# Verify it was saved
updated = es_client.get_playbook(playbook_id)
print(f"\nAfter update:")
print(f"Status: {updated.get('status')}")
print(f"Approved: {updated['steps'][0].get('approved')}")
print(f"Approved by: {updated['steps'][0].get('approved_by')}")