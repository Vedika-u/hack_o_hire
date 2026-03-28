from pydantic import BaseModel, Field, field_validator, model_validator
from typing import Optional, Literal, List, Dict, Any
from datetime import datetime, timezone
from uuid import uuid4

SCHEMA_VERSION = "1.1.0"


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


SourceType = Literal["winlogbeat", "filebeat", "syslog", "custom"]
EventType = Literal["login", "process", "network", "file", "dns", "privilege", "api_call", "database"]
ActionType = Literal["success", "failure", "exec", "read", "write", "delete", "escalate", "connect", "disconnect"]
SeverityLevel = Literal["low", "medium", "high", "critical"]
ConfidenceLevel = Literal["low", "medium", "high", "critical"]
EntityType = Literal["user", "host", "ip", "service"]
ModelType = Literal["isolation_forest", "lof", "hbos"]
AttackPattern = Literal["lateral_movement", "brute_force", "data_exfiltration", "privilege_escalation", "insider_threat", "api_abuse", "ransomware", "unknown"]
AttackStage = Literal["reconnaissance", "initial_access", "execution", "persistence", "privilege_escalation", "lateral_movement", "collection", "exfiltration", "unknown"]
TimeWindow = Literal["1min", "5min", "15min", "1hr", "6hr", "24hr"]
RiskLevel = Literal["low", "medium", "high", "critical"]
SOARAction = Literal["block_ip", "disable_account", "isolate_endpoint", "force_logout", "revoke_token", "alert_analyst", "increase_monitoring", "quarantine_file"]
BlastRadius = Literal["user", "host", "department", "network", "system"]


class SOARConstraints(BaseModel):
    require_human_approval: bool = True
    allowed_soar_actions: List[SOARAction] = Field(
        default_factory=lambda: ["alert_analyst", "increase_monitoring"]
    )
    max_blast_radius: BlastRadius = "user"
    escalation_required_above_score: float = 0.85


class PlaybookStep(BaseModel):
    step_number: int
    action: SOARAction
    target_entity: str
    reason: str
    requires_approval: bool = True
    approved: Optional[bool] = None
    approved_by: Optional[str] = None
    approved_at: Optional[datetime] = None
    executed: bool = False
    executed_at: Optional[datetime] = None


class PlaybookOutput(BaseModel):
    model_config = {"extra": "allow"}
    schema_version: str = SCHEMA_VERSION
    pipeline_id: str
    playbook_id: str = Field(default_factory=lambda: str(uuid4()))
    incident_id: str
    llm_request_id: Optional[str] = None    
    generated_at: datetime = Field(default_factory=utc_now)
    threat_narrative: str
    attack_hypothesis: str
    steps: List[PlaybookStep] = Field(default_factory=list)
    within_constraints: bool = False
    validation_errors: List[str] = Field(default_factory=list)
    status: Literal[
        "pending_review",
        "partially_approved",
        "approved",
        "executed",
        "rejected"
    ] = "pending_review"

    @field_validator("generated_at")
    @classmethod
    def must_be_timezone_aware(cls, v):
        if v.tzinfo is None:
            raise ValueError("generated_at must be timezone-aware UTC.")
        return v


class BehaviorFeatures(BaseModel):
    login_fail_count: int = 0
    login_success_count: int = 0
    login_fail_ratio: float = 0.0
    event_rate_per_minute: float = 0.0
    login_attempt_velocity: float = 0.0
    data_transfer_rate: float = 0.0
    process_spawn_rate: float = 0.0
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


class GraphNode(BaseModel):
    id: str
    type: EntityType
    label: str
    risk_score: float = 0.0


class GraphEdge(BaseModel):
    source: str
    target: str
    weight: float = 1.0
    relation: str
    timestamp: datetime
    event_id: str

    @field_validator("timestamp")
    @classmethod
    def must_be_timezone_aware(cls, v):
        if v.tzinfo is None:
            raise ValueError("GraphEdge.timestamp must be timezone-aware.")
        return v


class GraphContext(BaseModel):
    nodes: List[GraphNode] = Field(default_factory=list)
    edges: List[GraphEdge] = Field(default_factory=list)
    centrality_scores: Dict[str, float] = Field(default_factory=dict)
    pivot_entity: Optional[str] = None
    lateral_movement_detected: bool = False
    subgraph_size: int = 0


class ScoreBreakdown(BaseModel):
    anomaly_component: float = Field(ge=0.0, le=1.0)
    graph_component: float = Field(ge=0.0, le=1.0)
    posture_component: float = Field(ge=0.0, le=1.0)
    temporal_component: float = Field(ge=0.0, le=1.0)
    weights: Dict[str, float] = Field(
        default_factory=lambda: {
            "anomaly": 0.40,
            "graph": 0.30,
            "posture": 0.20,
            "temporal": 0.10
        }
    )

    @model_validator(mode="after")
    def weights_must_sum_to_one(self):
        total = sum(self.weights.values())
        if self.weights and abs(total - 1.0) > 0.001:
            raise ValueError(f"Weights must sum to 1.0. Got {total:.4f}.")
        return self


class FidelityOutput(BaseModel):
    schema_version: str = SCHEMA_VERSION
    pipeline_id: str
    fidelity_id: str = Field(default_factory=lambda: str(uuid4()))
    incident_id: str
    evaluated_at: datetime = Field(default_factory=utc_now)
    fidelity_score: float = Field(ge=0.0, le=1.0)
    confidence: ConfidenceLevel
    score_breakdown: ScoreBreakdown
    is_stable: bool
    stability_window_count: int = 1
    signal_trend: Literal["rising", "stable", "falling"] = "stable"
    reasoning: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("evaluated_at")
    @classmethod
    def must_be_timezone_aware(cls, v):
        if v.tzinfo is None:
            raise ValueError("evaluated_at must be timezone-aware UTC.")
        return v


class TimelineEvent(BaseModel):
    event_id: str
    timestamp: datetime
    entity_id: str
    action: ActionType
    resource: Optional[str] = None
    severity: SeverityLevel = "low"

    @field_validator("timestamp")
    @classmethod
    def must_be_timezone_aware(cls, v):
        if v.tzinfo is None:
            raise ValueError("timestamp must be timezone-aware.")
        return v


class CorrelatedIncident(BaseModel):
    schema_version: str = SCHEMA_VERSION
    pipeline_id: str
    incident_id: str = Field(default_factory=lambda: str(uuid4()))
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
    entities: List[str]
    entity_types: Dict[str, EntityType]
    primary_entity: str
    detection_ids: List[str]
    source_event_ids: List[str]
    incident_start: datetime
    incident_end: datetime
    duration_minutes: float
    timeline: List[TimelineEvent] = Field(default_factory=list)
    pattern: AttackPattern
    attack_stage: AttackStage
    severity: SeverityLevel
    graph_context: GraphContext = Field(default_factory=GraphContext)

    @field_validator("incident_start", "incident_end", "created_at", "updated_at")
    @classmethod
    def must_be_timezone_aware(cls, v):
        if v.tzinfo is None:
            raise ValueError("All datetime fields must be timezone-aware UTC.")
        return v

    @model_validator(mode="after")
    def end_after_start(self):
        if self.incident_start and self.incident_end:
            if self.incident_end < self.incident_start:
                raise ValueError("incident_end must not be before incident_start.")
        return self


class DetectionOutput(BaseModel):
    schema_version: str = SCHEMA_VERSION
    pipeline_id: str
    detection_id: str = Field(default_factory=lambda: str(uuid4()))
    behavior_id: str
    entity_id: str
    entity_type: EntityType
    window_start: datetime
    window_end: datetime
    detected_at: datetime = Field(default_factory=utc_now)
    model: ModelType
    model_version: str = "1.0"
    anomaly_score: float = Field(ge=0.0, le=1.0)
    raw_score: float
    threshold_used: float
    score_margin: float
    label: Literal["normal", "anomaly"]
    severity: SeverityLevel
    features_used: Dict[str, float] = Field(default_factory=dict)
    top_contributing_features: List[str] = Field(default_factory=list)

    @field_validator("window_start", "window_end", "detected_at")
    @classmethod
    def must_be_timezone_aware(cls, v):
        if v.tzinfo is None:
            raise ValueError("All datetime fields must be timezone-aware UTC.")
        return v


class AggregatedBehavior(BaseModel):
    schema_version: str = SCHEMA_VERSION
    pipeline_id: str
    behavior_id: str = Field(default_factory=lambda: str(uuid4()))
    entity_id: str
    entity_type: EntityType
    window_start: datetime
    window_end: datetime
    time_window: TimeWindow
    event_count: int = 0
    source_event_ids: List[str] = Field(default_factory=list)
    features: BehaviorFeatures = Field(default_factory=BehaviorFeatures)

    @field_validator("window_start", "window_end")
    @classmethod
    def must_be_timezone_aware(cls, v):
        if v.tzinfo is None:
            raise ValueError("window datetimes must be timezone-aware.")
        return v

    @model_validator(mode="after")
    def window_end_after_start(self):
        if self.window_start and self.window_end:
            if self.window_end <= self.window_start:
                raise ValueError("window_end must be after window_start.")
        return self


class UniversalEvent(BaseModel):
    schema_version: str = SCHEMA_VERSION
    pipeline_id: str = Field(default_factory=lambda: str(uuid4()))
    event_id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime
    ingested_at: datetime = Field(default_factory=utc_now)
    source: SourceType
    source_file: Optional[str] = None
    event_type: EventType
    severity: SeverityLevel = "low"
    user: Optional[str] = None
    user_domain: Optional[str] = None
    host: Optional[str] = None
    ip: Optional[str] = None
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None
    action: ActionType
    resource: Optional[str] = None
    process_name: Optional[str] = None
    process_id: Optional[int] = None
    outcome: Optional[Literal["success", "failure", "unknown"]] = None
    is_valid: bool = True
    validation_errors: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("timestamp")
    @classmethod
    def timestamp_must_be_timezone_aware(cls, v):
        if v.tzinfo is None:
            raise ValueError("timestamp must be timezone-aware.")
        return v


class LLMInput(BaseModel):
    schema_version: str = SCHEMA_VERSION
    pipeline_id: str
    llm_request_id: Optional[str] = None
    incident_id: str
    fidelity_id: str
    requested_at: datetime = Field(default_factory=utc_now)
    requested_by: str
    incident_summary: str
    pattern: AttackPattern
    attack_stage: AttackStage
    risk_level: RiskLevel
    fidelity_score: float = Field(ge=0.0, le=1.0)
    affected_entities: List[Dict[str, str]]
    timeline_summary: List[Dict[str, Any]]
    top_anomalous_features: List[Dict[str, Any]]
    score_breakdown: Dict[str, float]
    max_timeline_entries: int = 10
    max_features: int = 5
    recommended_action: List[SOARAction] = Field(default_factory=list)
    constraints: SOARConstraints = Field(default_factory=SOARConstraints)

    @field_validator("requested_at")
    @classmethod
    def must_be_timezone_aware(cls, v):
        if v.tzinfo is None:
            raise ValueError("requested_at must be timezone-aware UTC.")
        return v