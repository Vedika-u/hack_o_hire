from elasticsearch import Elasticsearch

# ✅ FIXED CONNECTION (no env dependency)
client = Elasticsearch(
    "https://localhost:9200",
    basic_auth=("elastic", "381EAB8luuUzmdzan_P+"),
    verify_certs=False
)


def create_ilm_policy():
    policy = {
        "policy": {
            "phases": {
                "hot": {
                    "min_age": "0ms",
                    "actions": {
                        "rollover": {
                            "max_size": "10gb",
                            "max_age": "1d"
                        }
                    }
                },
                "warm": {
                    "min_age": "7d",
                    "actions": {
                        "shrink": {"number_of_shards": 1},
                        "forcemerge": {"max_num_segments": 1}
                    }
                },
                "cold": {
                    "min_age": "30d",
                    "actions": {
                        "freeze": {}
                    }
                },
                "delete": {
                    "min_age": "90d",
                    "actions": {
                        "delete": {}
                    }
                }
            }
        }
    }

    try:
        client.ilm.put_lifecycle(name="soc-logs-policy", body=policy)
        print("✅ ILM policy created: soc-logs-policy")
    except Exception as e:
        print(f"❌ Error creating ILM policy: {e}")


def create_index_template():
    template = {
        "index_patterns": ["soc-logs-*", "filebeat-*", "winlogbeat-*"],
        "template": {
            "settings": {
                "number_of_shards": 1,
                "number_of_replicas": 1,
                "index.lifecycle.name": "soc-logs-policy",
                "default_pipeline": "soc-ecs-pipeline"
            },
            "mappings": {
                "properties": {
                    "@timestamp": {"type": "date"},
                    "message": {"type": "text"},
                    "tags": {"type": "keyword"},

                    "event": {
                        "properties": {
                            "category": {"type": "keyword"},
                            "type": {"type": "keyword"},
                            "severity": {"type": "integer"},
                            "action": {"type": "keyword"},
                            "ingested": {"type": "date"}
                        }
                    },

                    "host": {
                        "properties": {
                            "name": {"type": "keyword"},
                            "hostname": {"type": "keyword"}
                        }
                    },

                    "user": {
                        "properties": {
                            "name": {"type": "keyword"}
                        }
                    },

                    "source": {
                        "properties": {
                            "ip": {"type": "ip"},
                            "domain": {"type": "keyword"},
                            "geo": {"type": "object"}
                        }
                    }
                }
            }
        }
    }

    try:
        client.indices.put_index_template(
            name="soc-logs-template",
            body=template
        )
        print("✅ Index template created: soc-logs-template")
    except Exception as e:
        print(f"❌ Error creating index template: {e}")


if __name__ == "__main__":
    create_ilm_policy()
    create_index_template()