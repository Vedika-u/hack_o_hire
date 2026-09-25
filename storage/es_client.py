# storage/es_client.py
"""
Central Elasticsearch Client for ACT AWARE.
Connects to Elasticsearch cluster if available; seamlessly falls back to
an in-memory mock store for air-gapped demo mode or local offline testing.
"""

from elasticsearch import Elasticsearch
from config.settings import settings
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone
import logging

logger = logging.getLogger(__name__)


class ESClient:
    def __init__(self):
        self.connected = False
        self.client = None
        self._fallback_store: Dict[str, Dict[str, Any]] = {
            settings.ES_INDEX_EVENTS: {},
            settings.ES_INDEX_BEHAVIORS: {},
            settings.ES_INDEX_DETECTIONS: {},
            settings.ES_INDEX_INCIDENTS: {},
            settings.ES_INDEX_FIDELITY: {},
            settings.ES_INDEX_PLAYBOOKS: {},
            settings.ES_INDEX_PROVENANCE: {},
            settings.INDEX_AUDIT: {},
            settings.INDEX_METRICS: {},
            settings.INDEX_FEEDBACK: {},
            settings.INDEX_ACTIONS: {},
            "soc-dead-letter": {},
        }
        self._init_connection()

    def _init_connection(self):
        try:
            self.client = Elasticsearch(
                settings.ES_HOST,
                basic_auth=(settings.ES_USERNAME, settings.ES_PASSWORD),
                verify_certs=settings.ES_VERIFY_CERTS,
                request_timeout=1,
            )
            if self.client.ping():
                self.connected = True
                logger.info(f"Connected to Elasticsearch at {settings.ES_HOST}")
                self._ensure_all_indices()
            else:
                logger.warning(
                    f"Elasticsearch ping failed at {settings.ES_HOST}. "
                    "Operating in resilient offline/fallback mode."
                )
                self.connected = False
        except Exception as e:
            logger.warning(
                f"Cannot connect to Elasticsearch at {settings.ES_HOST} ({e}). "
                "Operating in resilient offline/fallback mode."
            )
            self.connected = False

    def _ensure_all_indices(self):
        if not self.connected or not self.client:
            return

        indices_to_ensure = {
            settings.ES_INDEX_EVENTS: {
                "settings": {"number_of_shards": 1, "number_of_replicas": 0},
                "mappings": {
                    "properties": {
                        "@timestamp": {"type": "date"},
                        "timestamp": {"type": "date"},
                        "ingested_at": {"type": "date"},
                        "event_id": {"type": "keyword"},
                        "pipeline_id": {"type": "keyword"},
                        "source": {"type": "keyword"},
                        "event_type": {"type": "keyword"},
                        "severity": {"type": "keyword"},
                        "user": {"type": "keyword"},
                        "host": {"type": "keyword"},
                        "ip": {"type": "ip"},
                        "action": {"type": "keyword"},
                        "resource": {"type": "keyword"},
                        "is_valid": {"type": "boolean"},
                    }
                }
            },
            settings.ES_INDEX_BEHAVIORS: {
                "settings": {"number_of_shards": 1, "number_of_replicas": 0},
                "mappings": {
                    "properties": {
                        "behavior_id": {"type": "keyword"},
                        "pipeline_id": {"type": "keyword"},
                        "entity_id": {"type": "keyword"},
                        "entity_type": {"type": "keyword"},
                        "window_start": {"type": "date"},
                        "window_end": {"type": "date"},
                        "time_window": {"type": "keyword"},
                        "event_count": {"type": "integer"},
                    }
                }
            },
            settings.ES_INDEX_DETECTIONS: {
                "settings": {"number_of_shards": 1, "number_of_replicas": 0},
                "mappings": {
                    "properties": {
                        "detection_id": {"type": "keyword"},
                        "pipeline_id": {"type": "keyword"},
                        "behavior_id": {"type": "keyword"},
                        "entity_id": {"type": "keyword"},
                        "entity_type": {"type": "keyword"},
                        "model": {"type": "keyword"},
                        "anomaly_score": {"type": "float"},
                        "label": {"type": "keyword"},
                        "severity": {"type": "keyword"},
                        "detected_at": {"type": "date"},
                    }
                }
            },
            settings.ES_INDEX_INCIDENTS: {
                "settings": {"number_of_shards": 1, "number_of_replicas": 0},
                "mappings": {
                    "properties": {
                        "incident_id": {"type": "keyword"},
                        "pipeline_id": {"type": "keyword"},
                        "primary_entity": {"type": "keyword"},
                        "pattern": {"type": "keyword"},
                        "attack_stage": {"type": "keyword"},
                        "severity": {"type": "keyword"},
                        "created_at": {"type": "date"},
                        "updated_at": {"type": "date"},
                    }
                }
            },
            settings.ES_INDEX_FIDELITY: {
                "settings": {"number_of_shards": 1, "number_of_replicas": 0},
                "mappings": {
                    "properties": {
                        "fidelity_id": {"type": "keyword"},
                        "incident_id": {"type": "keyword"},
                        "fidelity_score": {"type": "float"},
                        "confidence": {"type": "keyword"},
                        "is_stable": {"type": "boolean"},
                        "evaluated_at": {"type": "date"},
                    }
                }
            },
            settings.ES_INDEX_PLAYBOOKS: {
                "settings": {"number_of_shards": 1, "number_of_replicas": 0},
                "mappings": {
                    "properties": {
                        "playbook_id": {"type": "keyword"},
                        "incident_id": {"type": "keyword"},
                        "pipeline_id": {"type": "keyword"},
                        "status": {"type": "keyword"},
                        "generated_at": {"type": "date"},
                    }
                }
            },
            settings.ES_INDEX_PROVENANCE: {
                "settings": {"number_of_shards": 1, "number_of_replicas": 0},
                "mappings": {
                    "properties": {
                        "provenance_id": {"type": "keyword"},
                        "incident_id": {"type": "keyword"},
                        "timestamp": {"type": "date"},
                        "layer": {"type": "keyword"},
                    }
                }
            },
            settings.INDEX_AUDIT: {
                "settings": {"number_of_shards": 1, "number_of_replicas": 0},
                "mappings": {
                    "properties": {
                        "audit_id": {"type": "keyword"},
                        "timestamp": {"type": "date"},
                        "action": {"type": "keyword"},
                        "actor": {"type": "keyword"},
                    }
                }
            },
            settings.INDEX_METRICS: {
                "settings": {"number_of_shards": 1, "number_of_replicas": 0},
                "mappings": {
                    "properties": {
                        "metrics_id": {"type": "keyword"},
                        "computed_at": {"type": "date"},
                    }
                }
            },
            settings.INDEX_FEEDBACK: {
                "settings": {"number_of_shards": 1, "number_of_replicas": 0},
                "mappings": {
                    "properties": {
                        "feedback_id": {"type": "keyword"},
                        "incident_id": {"type": "keyword"},
                    }
                }
            },
            settings.INDEX_ACTIONS: {
                "settings": {"number_of_shards": 1, "number_of_replicas": 0},
                "mappings": {
                    "properties": {
                        "action_id": {"type": "keyword"},
                        "executed_at": {"type": "date"},
                    }
                }
            },
        }

        for idx_name, idx_body in indices_to_ensure.items():
            try:
                if not self.client.indices.exists(index=idx_name):
                    self.client.indices.create(index=idx_name, body=idx_body)
                    logger.info(f"Created index: {idx_name}")
            except Exception as e:
                logger.debug(f"Index {idx_name} check/create note: {e}")

    # ── Generic Index / Get / Search with Fallback ─────

    def index_document(self, index: str, doc_id: str, body: Dict[str, Any]) -> bool:
        if index not in self._fallback_store:
            self._fallback_store[index] = {}
        self._fallback_store[index][doc_id] = body

        if self.connected and self.client:
            try:
                self.client.index(index=index, id=doc_id, body=body, refresh=True)
                return True
            except Exception as e:
                logger.error(f"Failed to index {doc_id} to ES index {index}: {e}")
                return False
        return True

    def get_document(self, index: str, doc_id: str) -> Optional[Dict[str, Any]]:
        if self.connected and self.client:
            try:
                res = self.client.get(index=index, id=doc_id)
                return res["_source"]
            except Exception:
                pass
        return self._fallback_store.get(index, {}).get(doc_id)

    def search_documents(
        self, index: str, query: Optional[Dict[str, Any]] = None, size: int = 100
    ) -> List[Dict[str, Any]]:
        if self.connected and self.client:
            try:
                q = query if query else {"query": {"match_all": {}}}
                res = self.client.search(index=index, body=q, size=size)
                return [hit["_source"] for hit in res["hits"]["hits"]]
            except Exception as e:
                logger.debug(f"Search failed on ES {index}: {e}")

        docs = list(self._fallback_store.get(index, {}).values())
        return docs[:size]

    def count_documents(self, index: str, query: Optional[Dict[str, Any]] = None) -> int:
        if self.connected and self.client:
            try:
                q = query if query else {"query": {"match_all": {}}}
                res = self.client.count(index=index, body=q)
                return res["count"]
            except Exception:
                pass
        return len(self._fallback_store.get(index, {}))

    # ── Backward Compatibility Aliases ────────────────
    def _index(self, index: str, doc_id: str, body: Dict[str, Any]) -> bool:
        return self.index_document(index, doc_id, body)

    def _get(self, index: str, doc_id: str) -> Optional[Dict[str, Any]]:
        return self.get_document(index, doc_id)

    def _search(self, index: str, query: Dict[str, Any], size: int = 100) -> List[Dict[str, Any]]:
        return self.search_documents(index, query, size)

    def _count(self, index: str, query: Optional[Dict[str, Any]] = None) -> int:
        return self.count_documents(index, query)

    def _update(self, index: str, doc_id: str, updates: Dict[str, Any]) -> bool:
        doc = self.get_document(index, doc_id)
        if doc:
            doc.update(updates)
            return self.index_document(index, doc_id, doc)
        return False

    # ── Specialized Layer Helpers ──────────────────────

    def store_event(self, event_id: str, body: Dict[str, Any]) -> bool:
        # Populate @timestamp for Elastic Common Schema / Kibana
        if "timestamp" in body and "@timestamp" not in body:
            body["@timestamp"] = body["timestamp"]
        return self.index_document(settings.ES_INDEX_EVENTS, event_id, body)

    def store_behavior(self, behavior_id: str, body: Dict[str, Any]) -> bool:
        return self.index_document(settings.ES_INDEX_BEHAVIORS, behavior_id, body)

    def store_detection(self, detection_id: str, body: Dict[str, Any]) -> bool:
        return self.index_document(settings.ES_INDEX_DETECTIONS, detection_id, body)

    def store_incident(self, incident_id: str, body: Dict[str, Any]) -> bool:
        return self.index_document(settings.ES_INDEX_INCIDENTS, incident_id, body)

    def store_fidelity(self, fidelity_id: str, body: Dict[str, Any]) -> bool:
        return self.index_document(settings.ES_INDEX_FIDELITY, fidelity_id, body)

    def store_playbook(self, playbook_id: str, body: Dict[str, Any]) -> bool:
        return self.index_document(settings.ES_INDEX_PLAYBOOKS, playbook_id, body)

    def store_provenance(self, provenance_id: str, body: Dict[str, Any]) -> bool:
        return self.index_document(settings.ES_INDEX_PROVENANCE, provenance_id, body)

    def store_audit_log(self, audit_id: str, body: Dict[str, Any]) -> bool:
        return self.index_document(settings.INDEX_AUDIT, audit_id, body)

    def store_metrics(self, metrics_id: str, body: Dict[str, Any]) -> bool:
        return self.index_document(settings.INDEX_METRICS, metrics_id, body)

    def store_feedback(self, feedback_id: str, body: Dict[str, Any]) -> bool:
        return self.index_document(settings.INDEX_FEEDBACK, feedback_id, body)

    def get_playbook(self, playbook_id: str) -> Optional[Dict[str, Any]]:
        # Check by id or playbook_id field
        doc = self.get_document(settings.ES_INDEX_PLAYBOOKS, playbook_id)
        if doc:
            return doc
        for d in self._fallback_store.get(settings.ES_INDEX_PLAYBOOKS, {}).values():
            if d.get("playbook_id") == playbook_id:
                return d
        if self.connected and self.client:
            try:
                res = self.client.search(
                    index=settings.ES_INDEX_PLAYBOOKS,
                    body={"query": {"term": {"playbook_id.keyword": playbook_id}}},
                    size=1,
                )
                hits = res["hits"]["hits"]
                if hits:
                    return hits[0]["_source"]
            except Exception:
                pass
        return None

    def update_playbook(self, playbook_id: str, updates: Dict[str, Any]) -> bool:
        doc = self.get_playbook(playbook_id)
        if not doc:
            return False
        doc.update(updates)
        self.store_playbook(playbook_id, doc)
        if self.connected and self.client:
            try:
                res = self.client.search(
                    index=settings.ES_INDEX_PLAYBOOKS,
                    body={"query": {"term": {"playbook_id.keyword": playbook_id}}},
                    size=1,
                )
                hits = res["hits"]["hits"]
                if hits:
                    es_id = hits[0]["_id"]
                    self.client.update(
                        index=settings.ES_INDEX_PLAYBOOKS,
                        id=es_id,
                        body={"doc": updates},
                        refresh=True,
                    )
            except Exception as e:
                logger.error(f"Error updating playbook {playbook_id} in ES: {e}")
        return True

    def get_incident(self, incident_id: str) -> Optional[Dict[str, Any]]:
        return self.get_document(settings.ES_INDEX_INCIDENTS, incident_id)

    def get_fidelity(self, fidelity_id: str) -> Optional[Dict[str, Any]]:
        return self.get_document(settings.ES_INDEX_FIDELITY, fidelity_id)

    def search_incidents(self, query: Dict[str, Any], size: int = 50) -> List[Dict[str, Any]]:
        return self.search_documents(settings.ES_INDEX_INCIDENTS, query, size)

    def search_fidelity(self, query: Dict[str, Any], size: int = 50) -> List[Dict[str, Any]]:
        return self.search_documents(settings.ES_INDEX_FIDELITY, query, size)

    def search_playbooks(self, query: Dict[str, Any], size: int = 100) -> List[Dict[str, Any]]:
        return self.search_documents(settings.ES_INDEX_PLAYBOOKS, query, size)

    def search_audit(self, query: Dict[str, Any], size: int = 100) -> List[Dict[str, Any]]:
        return self.search_documents(settings.INDEX_AUDIT, query, size)

    def search_feedback(self, query: Dict[str, Any], size: int = 100) -> List[Dict[str, Any]]:
        return self.search_documents(settings.INDEX_FEEDBACK, query, size)

    def count_incidents(self, query: Optional[Dict[str, Any]] = None) -> int:
        return self.count_documents(settings.ES_INDEX_INCIDENTS, query)

    def count_events(self, query: Optional[Dict[str, Any]] = None) -> int:
        return self.count_documents(settings.ES_INDEX_EVENTS, query)

    def count_playbooks(self, query: Optional[Dict[str, Any]] = None) -> int:
        return self.count_documents(settings.ES_INDEX_PLAYBOOKS, query)

    def count_audit(self, query: Optional[Dict[str, Any]] = None) -> int:
        return self.count_documents(settings.INDEX_AUDIT, query)

    def count_feedback(self, query: Optional[Dict[str, Any]] = None) -> int:
        return self.count_documents(settings.INDEX_FEEDBACK, query)

    def check_connection(self) -> bool:
        if self.connected and self.client:
            try:
                info = self.client.info()
                logger.info(f"Connected to ES version: {info['version']['number']}")
                return True
            except Exception:
                return False
        return False


es_client = ESClient()