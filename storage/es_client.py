from elasticsearch import Elasticsearch
from config.settings import settings
from typing import Dict, Any, Optional, List
import logging

logger = logging.getLogger(__name__)


class ESClient:

    def __init__(self):
        self.client = Elasticsearch(
            settings.ES_HOST,
            basic_auth=(settings.ES_USERNAME, settings.ES_PASSWORD),
            verify_certs=settings.ES_VERIFY_CERTS,
            request_timeout=30
        )
        self._ensure_own_indices()

    def _ensure_own_indices(self):
        own_indices = {
            settings.INDEX_AUDIT: {
                "settings": {"number_of_shards": 1, "number_of_replicas": 0},
                "mappings": {
                    "properties": {
                        "audit_id": {"type": "keyword"},
                        "timestamp": {"type": "date"},
                        "action": {"type": "keyword"},
                        "actor": {"type": "keyword"},
                        "actor_role": {"type": "keyword"},
                        "target_type": {"type": "keyword"},
                        "target_id": {"type": "keyword"},
                        "outcome": {"type": "keyword"},
                        "pipeline_id": {"type": "keyword"},
                    }
                }
            },
            settings.INDEX_METRICS: {
                "settings": {"number_of_shards": 1, "number_of_replicas": 0},
                "mappings": {
                    "properties": {
                        "metrics_id": {"type": "keyword"},
                        "computed_at": {"type": "date"},
                        "time_range": {"type": "keyword"},
                    }
                }
            },
            settings.INDEX_FEEDBACK: {
                "settings": {"number_of_shards": 1, "number_of_replicas": 0},
                "mappings": {
                    "properties": {
                        "feedback_id": {"type": "keyword"},
                        "incident_id": {"type": "keyword"},
                        "analyst_username": {"type": "keyword"},
                        "feedback_type": {"type": "keyword"},
                        "submitted_at": {"type": "date"},
                        "severity_accurate": {"type": "boolean"},
                    }
                }
            },
            settings.INDEX_ACTIONS: {
                "settings": {"number_of_shards": 1, "number_of_replicas": 0},
                "mappings": {
                    "properties": {
                        "action_id": {"type": "keyword"},
                        "playbook_id": {"type": "keyword"},
                        "step_number": {"type": "integer"},
                        "action": {"type": "keyword"},
                        "target": {"type": "keyword"},
                        "executed_by": {"type": "keyword"},
                        "executed_at": {"type": "date"},
                        "success": {"type": "boolean"},
                        "outcome": {"type": "text"},
                    }
                }
            },
        }

        for index_name, index_body in own_indices.items():
            try:
                if not self.client.indices.exists(index=index_name):
                    self.client.indices.create(index=index_name, body=index_body)
                    logger.info(f"Created index: {index_name}")
                else:
                    logger.info(f"Index exists: {index_name}")
            except Exception as e:
                logger.error(f"Failed to create index {index_name}: {e}")

    def store_playbook(self, playbook_id: str, body: Dict[str, Any]) -> bool:
        try:
            result = self.client.search(
                index=settings.INDEX_PLAYBOOKS,
                body={"query": {"term": {"playbook_id.keyword": playbook_id}}},
                size=1
            )
            hits = result['hits']['hits']
            if hits:
                doc_id = hits[0]['_id']
                self.client.index(
                    index=settings.INDEX_PLAYBOOKS,
                    id=doc_id,
                    body=body,
                    refresh=True
                )
                logger.info(f"Updated playbook {playbook_id}")
            else:
                self.client.index(
                    index=settings.INDEX_PLAYBOOKS,
                    id=playbook_id,
                    body=body,
                    refresh=True
                )
                logger.info(f"Created playbook {playbook_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to store playbook {playbook_id}: {e}")
            return False

    def store_audit_log(self, audit_id: str, body: Dict[str, Any]) -> bool:
        return self._index(settings.INDEX_AUDIT, audit_id, body)

    def store_metrics(self, metrics_id: str, body: Dict[str, Any]) -> bool:
        return self._index(settings.INDEX_METRICS, metrics_id, body)

    def store_feedback(self, feedback_id: str, body: Dict[str, Any]) -> bool:
        return self._index(settings.INDEX_FEEDBACK, feedback_id, body)

    def get_incident(self, incident_id: str) -> Optional[Dict[str, Any]]:
        return self._get(settings.INDEX_INCIDENTS, incident_id)

    def get_fidelity(self, fidelity_id: str) -> Optional[Dict[str, Any]]:
        return self._get(settings.INDEX_FIDELITY, fidelity_id)

    def get_playbook(self, playbook_id: str) -> Optional[Dict[str, Any]]:
        try:
            try:
                result = self.client.get(
                    index=settings.INDEX_PLAYBOOKS,
                    id=playbook_id
                )
                return result["_source"]
            except Exception:
                pass
            result = self.client.search(
                index=settings.INDEX_PLAYBOOKS,
                body={"query": {"term": {"playbook_id.keyword": playbook_id}}},
                size=1
            )
            hits = result['hits']['hits']
            if hits:
                return hits[0]['_source']
            return None
        except Exception as e:
            logger.error(f"Failed to get playbook {playbook_id}: {e}")
            return None

    def search_incidents(self, query: Dict[str, Any], size: int = 50) -> List[Dict[str, Any]]:
        return self._search(settings.INDEX_INCIDENTS, query, size)

    def search_fidelity(self, query: Dict[str, Any], size: int = 50) -> List[Dict[str, Any]]:
        return self._search(settings.INDEX_FIDELITY, query, size)

    def search_playbooks(self, query: Dict[str, Any], size: int = 100) -> List[Dict[str, Any]]:
        return self._search(settings.INDEX_PLAYBOOKS, query, size)

    def search_audit(self, query: Dict[str, Any], size: int = 100) -> List[Dict[str, Any]]:
        return self._search(settings.INDEX_AUDIT, query, size)

    def search_feedback(self, query: Dict[str, Any], size: int = 100) -> List[Dict[str, Any]]:
        return self._search(settings.INDEX_FEEDBACK, query, size)

    def update_playbook(self, playbook_id: str, updates: Dict[str, Any]) -> bool:
        try:
            result = self.client.search(
                index=settings.INDEX_PLAYBOOKS,
                body={"query": {"term": {"playbook_id.keyword": playbook_id}}},
                size=1
            )
            hits = result['hits']['hits']
            if not hits:
                logger.error(f"Playbook {playbook_id} not found")
                return False
            doc_id = hits[0]['_id']
            self.client.update(
                index=settings.INDEX_PLAYBOOKS,
                id=doc_id,
                body={"doc": updates},
                refresh=True
            )
            return True
        except Exception as e:
            logger.error(f"Failed to update playbook {playbook_id}: {e}")
            return False

    def count_incidents(self, query: Optional[Dict[str, Any]] = None) -> int:
        return self._count(settings.INDEX_INCIDENTS, query)

    def count_events(self, query: Optional[Dict[str, Any]] = None) -> int:
        return self._count("act_aware_events", query)

    def count_playbooks(self, query: Optional[Dict[str, Any]] = None) -> int:
        return self._count(settings.INDEX_PLAYBOOKS, query)

    def count_audit(self, query: Optional[Dict[str, Any]] = None) -> int:
        return self._count(settings.INDEX_AUDIT, query)

    def count_feedback(self, query: Optional[Dict[str, Any]] = None) -> int:
        return self._count(settings.INDEX_FEEDBACK, query)

    def _index(self, index: str, doc_id: str, body: Dict[str, Any]) -> bool:
        try:
            self.client.index(index=index, id=doc_id, body=body, refresh=True)
            return True
        except Exception as e:
            logger.error(f"Failed to index {doc_id} to {index}: {e}")
            return False

    def _get(self, index: str, doc_id: str) -> Optional[Dict[str, Any]]:
        try:
            result = self.client.get(index=index, id=doc_id)
            return result["_source"]
        except Exception as e:
            logger.error(f"Failed to get {doc_id} from {index}: {e}")
            return None

    def _search(self, index: str, query: Dict[str, Any], size: int = 100) -> List[Dict[str, Any]]:
        try:
            result = self.client.search(index=index, body=query, size=size)
            return [hit["_source"] for hit in result["hits"]["hits"]]
        except Exception as e:
            logger.error(f"Search failed on {index}: {e}")
            return []

    def _update(self, index: str, doc_id: str, updates: Dict[str, Any]) -> bool:
        try:
            self.client.update(index=index, id=doc_id, body={"doc": updates})
            return True
        except Exception as e:
            logger.error(f"Failed to update {doc_id} in {index}: {e}")
            return False

    def _count(self, index: str, query: Optional[Dict[str, Any]] = None) -> int:
        try:
            body = query if query else {"query": {"match_all": {}}}
            result = self.client.count(index=index, body=body)
            return result["count"]
        except Exception as e:
            logger.error(f"Count failed on {index}: {e}")
            return 0

    def check_connection(self) -> bool:
        try:
            info = self.client.info()
            logger.info(f"Connected to ES: {info['version']['number']}")
            return True
        except Exception as e:
            logger.error(f"Cannot connect to ES: {e}")
            return False


es_client = ESClient()