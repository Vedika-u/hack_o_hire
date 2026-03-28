# test_fix.py
from config.schemas import PlaybookOutput
from storage.es_client import es_client

results = es_client.search_playbooks({"query": {"match_all": {}}})
if results:
    try:
        pb = PlaybookOutput(**results[0])
        print(f"Schema OK: {pb.playbook_id}")
        print(f"Status: {pb.status}")
        print(f"Steps: {len(pb.steps)}")
        print(f"Pattern: {pb.pattern}")
    except Exception as e:
        print(f"ERROR: {e}")
else:
    print("No playbooks found")