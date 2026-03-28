from elasticsearch import Elasticsearch
import os
from dotenv import load_dotenv

load_dotenv()

es = Elasticsearch(
    f"http://{os.getenv('ES_HOST')}:{os.getenv('ES_PORT')}",
    basic_auth=(os.getenv('ES_USERNAME'), os.getenv('ES_PASSWORD'))
)

# Test 1: Count total events
total = es.count(index="act_aware_events")['count']
print(f"✅ Total events in act_aware_events: {total}\n")

# Test 2: Get sample event and show all fields
result = es.search(index="act_aware_events", body={
    "size": 1,
    "query": {"match_all": {}}
})

if result['hits']['total']['value'] > 0:
    doc = result['hits']['hits'][0]['_source']
    print("📄 Sample event fields and types:")
    for key in sorted(doc.keys()):
        value = doc[key]
        print(f"   {key:25} : {type(value).__name__:10} = {str(value)[:50]}")
else:
    print("❌ No events found!")

# Test 3: Check what fields exist across multiple events
print("\n🔍 Checking field presence across 100 events...")

result = es.search(index="act_aware_events", body={
    "size": 100,
    "query": {"match_all": {}}
})

field_counts = {}
for hit in result['hits']['hits']:
    doc = hit['_source']
    for key in doc.keys():
        field_counts[key] = field_counts.get(key, 0) + 1

print("\nField presence (out of 100 events):")
for field, count in sorted(field_counts.items()):
    print(f"   {field:25} : {count:3} events")