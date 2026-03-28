import os
from dotenv import load_dotenv

load_dotenv()

# Elasticsearch connection
ES_HOST = os.getenv("ES_HOST", "localhost")
ES_PORT = os.getenv("ES_PORT", "9200")
ES_URL = f"http://{ES_HOST}:{ES_PORT}"

ES_USERNAME = os.getenv("ES_USERNAME")
ES_PASSWORD = os.getenv("ES_PASSWORD")
ES_CA_CERT = os.getenv("ES_CA_CERT", "")

# Shared team index names
RAW_LOGS_INDEX = os.getenv("ES_INDEX_EVENTS", "act_aware_events")
AGGREGATED_INDEX = os.getenv("ES_INDEX_BEHAVIORS", "act_aware_behaviors")
ANOMALY_INDEX = os.getenv("ES_INDEX_DETECTIONS", "act_aware_detections")
INCIDENT_INDEX = os.getenv("ES_INDEX_INCIDENTS", "act_aware_incidents")
FIDELITY_INDEX = os.getenv("ES_INDEX_FIDELITY", "act_aware_fidelity")
PLAYBOOK_INDEX = os.getenv("ES_INDEX_PLAYBOOKS", "act_aware_playbooks")

# Internal optional indices for your layer
FEATURES_INDEX = "act_aware_features"
POSTURE_INDEX = "act_aware_posture"
AUDIT_INDEX = "act_aware_audit"

# Other services
OLLAMA_HOST = os.getenv("OLLAMA_HOST")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "mistral")
PIPELINE_ENV = os.getenv("PIPELINE_ENV", "development")
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
SCHEMA_VERSION = os.getenv("SCHEMA_VERSION", "1.1.0")