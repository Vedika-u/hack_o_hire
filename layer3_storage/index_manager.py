# layer3_storage/index_manager.py
"""
Layer 3: Storage & Index Management Backbone
Manages Elasticsearch indices, mappings, RBAC permissions, and lifecycle rules.
Ensures unified indices conform to Frozen Data Contract v1.1.0.
"""

from storage.es_client import es_client
from config.settings import settings
import logging

logger = logging.getLogger(__name__)


class IndexManager:
    def __init__(self):
        self.es = es_client

    def setup_indices(self) -> bool:
        """Verify and initialize all indices with correct mappings."""
        logger.info("Initializing ACT AWARE Elasticsearch index topology...")
        self.es._ensure_all_indices()
        return True

    def get_index_stats(self) -> dict:
        """Retrieve document counts across all pipeline indices."""
        stats = {
            "events": self.es.count_documents(settings.ES_INDEX_EVENTS),
            "behaviors": self.es.count_documents(settings.ES_INDEX_BEHAVIORS),
            "detections": self.es.count_documents(settings.ES_INDEX_DETECTIONS),
            "incidents": self.es.count_documents(settings.ES_INDEX_INCIDENTS),
            "fidelity": self.es.count_documents(settings.ES_INDEX_FIDELITY),
            "playbooks": self.es.count_documents(settings.ES_INDEX_PLAYBOOKS),
            "provenance": self.es.count_documents(settings.ES_INDEX_PROVENANCE),
            "audit_logs": self.es.count_documents(settings.INDEX_AUDIT),
            "metrics": self.es.count_documents(settings.INDEX_METRICS),
        }
        return stats


index_manager = IndexManager()
