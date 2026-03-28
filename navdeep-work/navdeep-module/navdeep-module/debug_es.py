from elasticsearch import Elasticsearch

tests = [
    {
        "name": "HTTP no auth",
        "client": Elasticsearch("http://localhost:9200")
    },
    {
        "name": "HTTPS no auth",
        "client": Elasticsearch("https://localhost:9200", verify_certs=False)
    },
    {
        "name": "HTTPS with elastic/changeme",
        "client": Elasticsearch(
            "https://localhost:9200",
            basic_auth=("elastic", "changeme"),
            verify_certs=False
        )
    }
]

for test in tests:
    print(f"\nTesting: {test['name']}")
    try:
        print("Ping:", test["client"].ping())
        if test["client"].ping():
            print(test["client"].info())
    except Exception as e:
        print("Error:", e)