from pydantic import BaseModel, Field
from typing import Optional, Literal, List, Dict, Any
from datetime import datetime, timezone
from uuid import uuid4

# ─────────────────────────────────────────────
# ENUMS / LITERALS
# ─────────────────────────────────────────────

SourceType = Literal["winlogbeat", "filebeat", "syslog", "custom"]

EventType = Literal[
    "login", "process", "network", "file", "dns", "privilege", "api_call", "database"
]

ActionType = Literal[
    "success", "failure", "exec", "read", "write", "delete", "escalate", "connect", "disconnect"
]

SeverityLevel = Literal["low", "medium", "high", "critical"]
EntityType = Literal["user", "host", "ip", "service"]
ModelType = Literal["isolation_forest", "lof", "hbos"]
TimeWindow = Literal["1min", "5min", "15min", "1hr", "6hr", "24hr"]

# ─────────────────────────────────────────────
# UNIVERSAL EVENT
# ─────────────────────────────────────────────

class UniversalEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime
    ingested_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    source: SourceType
    source_file: Optional[str] = None

    event_type: EventType
    severity: SeverityLevel = "low"

    user: Optional[str] = None
    user_domain: Optional[str] = None
    user_privilege_level: Optional[Literal["standard", "admin", "service", "system"]] = None

    host: Optional[str] = None
    host_os: Optional[Literal["windows", "linux", "macos", "unknown"]] = None
    ip: Optional[str] = None
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None
    geo_country: Optional[str] = None

    action: ActionType
    resource: Optional[str] = None
    process_name: Optional[str] = None
    process_id: Optional[int] = None
    parent_process: Optional[str] = None

    outcome: Optional[Literal["success", "failure", "unknown"]] = None
    error_code: Optional[str] = None

    metadata: Dict[str, Any] = Field(default_factory=dict)

# ─────────────────────────────────────────────
# BEHAVIOR FEATURES
# ─────────────────────────────────────────────

class BehaviorFeatures(BaseModel):
    login_fail_count: int = 0
    login_success_count: int = 0
    login_fail_ratio: float = 0.0

    unique_ips_accessed: int = 0
    unique_destinations: int = 0
    outbound_data_volume: float = 0.0
    inbound_data_volume: float = 0.0
    unique_ports_used: int = 0

    process_count: int = 0
    unique_process_names: int = 0
    suspicious_process_count: int = 0

    unique_hosts_accessed: int = 0
    unique_resources_accessed: int = 0
    sensitive_resource_access_count: int = 0

    privilege_escalation_attempts: int = 0
    admin_action_count: int = 0
    failed_privilege_actions: int = 0

    after_hours_activity: bool = False
    weekend_activity: bool = False
    activity_hour_spread: int = 0

    file_read_count: int = 0
    file_write_count: int = 0
    file_delete_count: int = 0
    unique_file_extensions: int = 0

    db_query_count: int = 0
    db_failed_query_count: int = 0
    db_rows_accessed: int = 0

    dns_query_count: int = 0
    unique_dns_domains: int = 0
    suspicious_dns_count: int = 0

# ─────────────────────────────────────────────
# AGGREGATED BEHAVIOR
# ─────────────────────────────────────────────

class AggregatedBehavior(BaseModel):
    behavior_id: str = Field(default_factory=lambda: str(uuid4()))
    entity_id: str
    entity_type: EntityType

    window_start: datetime
    window_end: datetime
    time_window: TimeWindow
    event_count: int = 0

    source_event_ids: List[str] = Field(default_factory=list)
    features: BehaviorFeatures = Field(default_factory=BehaviorFeatures)

# ─────────────────────────────────────────────
# DETECTION OUTPUT
# ─────────────────────────────────────────────

class DetectionOutput(BaseModel):
    detection_id: str = Field(default_factory=lambda: str(uuid4()))

    entity_id: str
    entity_type: EntityType

    window_start: datetime
    window_end: datetime

    model: ModelType

    anomaly_score: float
    normalized_score: float

    label: Literal["normal", "anomaly"]
    threshold: float

    features_used: Dict[str, float] = Field(default_factory=dict)
    contributing_features: List[str] = Field(default_factory=list)

    model_metadata: Dict[str, Any] = Field(default_factory=dict)

    source_behavior_id: str