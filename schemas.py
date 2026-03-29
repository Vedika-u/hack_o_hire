# config/schemas.py
# ACT AWARE — Frozen Data Contract v1.1.0
# Every layer of the pipeline reads/writes these schemas.
# DO NOT modify mid-project without updating all dependent layers.
# All datetime fields use timezone-aware UTC (timezone.utc) — never utcnow().

from pydantic import BaseModel, Field, validator, root_validator
from typing import Optional, Literal, List, Dict, Any
from datetime import datetime, timezone
from uuid import uuid4

# ─────────────────────────────────────────────
# VERSIONING
# Bump minor for additive changes.
# Bump major for breaking changes.
# Add schema_version to any schema that touches Elasticsearch.
# ─────────────────────────────────────────────

SCHEMA_VERSION = "1.1.0"


def utc_now() -> datetime:
    """
    Single source of truth for current UTC time across the entire pipeline.
    Use this everywhere. Never use datetime.utcnow() — it is timezone-naive
    and will silently corrupt time window aggregations and cross-system correlations.
    """
    return datetime.now(timezone.utc)


# ─────────────────────────────────────────────
# ENUMS / LITERALS
# Shared across all schemas.
# ─────────────────────────────────────────────

SourceType = Literal[
    "winlogbeat",
    "filebeat",
    "syslog",
    "custom"
]

EventType = Literal[
    "login",
    "process",
    "network",
    "file",
    "dns",
    "privilege",
    "api_call",
    "database"
]

ActionType = Literal[
    "success",
    "failure",
    "exec",
    "read",
    "write",
    "delete",
    "escalate",
    "connect",
    "disconnect"
]

SeverityLevel = Literal["low", "medium", "high", "critical"]

ConfidenceLevel = Literal["low", "medium", "high", "critical"]

EntityType = Literal["user", "host", "ip", "service"]

ModelType = Literal["isolation_forest", "lof", "hbos"]

AttackPattern = Literal[
    "lateral_movement",
    "brute_force",
    "data_exfiltration",
    "privilege_escalation",
    "insider_threat",
    "api_abuse",
    "ransomware",
    "unknown"
]

AttackStage = Literal[
    "reconnaissance",
    "initial_access",
    "execution",
    "persistence",
    "privilege_escalation",
    "lateral_movement",
    "collection",
    "exfiltration",
    "unknown"
]

TimeWindow = Literal["1min", "5min", "15min", "1hr", "6hr", "24hr"]

RiskLevel = Literal["low", "medium", "high", "critical"]

SOARAction = Literal[
    "block_ip",
    "disable_account",
    "isolate_endpoint",
    "force_logout",
    "revoke_token",
    "alert_analyst",
    "increase_monitoring",
    "quarantine_file"
]

BlastRadius = Literal["user", "host", "department", "network", "system"]


# ─────────────────────────────────────────────
# SCHEMA 1 — UNIVERSAL EVENT SCHEMA
# Layer: Log Collection → Ingestion → Normalization
# Every raw log from every source normalizes into this.
# ─────────────────────────────────────────────

class UniversalEvent(BaseModel):

    schema_version: str = Field(
        default=SCHEMA_VERSION,
        description="Schema version at time of record creation. "
                    "Used to detect and handle schema drift in Elasticsearch."
    )

    # ── Pipeline Tracing ──────────────────────
    pipeline_id: str = Field(
        default_factory=lambda: str(uuid4()),
        description="Tracks a full pipeline run across all layers. "
                    "Set ONCE at ingestion and propagated to every downstream record. "
                    "Never regenerate this — pass it through."
    )

    # ── Core Identity ─────────────────────────
    event_id: str = Field(
        default_factory=lambda: str(uuid4()),
        description="Unique ID for this event. "
                    "Referenced by AggregatedBehavior, DetectionOutput, CorrelatedIncident."
    )
    timestamp: datetime = Field(
        description="When the event occurred. "
                    "Must be timezone-aware UTC. "
                    "Reject events without timezone info."
    )
    ingested_at: datetime = Field(
        default_factory=utc_now,
        description="When this event entered the pipeline. "
                    "Compare with timestamp to measure collection lag."
    )

    # ── Source ────────────────────────────────
    source: SourceType = Field(
        description="Which collector produced this log."
    )
    source_file: Optional[str] = Field(
        default=None,
        description="Original log file path if collected by Filebeat."
    )

    # ── Classification ────────────────────────
    event_type: EventType = Field(
        description="Category of the security event."
    )
    severity: SeverityLevel = Field(
        default="low",
        description="Pre-classification severity. Assigned by ingestion rules "
                    "before ML runs. ML may upgrade this later."
    )

    # ── Actor ─────────────────────────────────
    user: Optional[str] = Field(
        default=None,
        description="Username. None for network-only events."
    )
    user_domain: Optional[str] = Field(
        default=None,
        description="Domain e.g. CORP, LOCAL, WORKGROUP."
    )
    user_privilege_level: Optional[Literal[
        "standard", "admin", "service", "system"
    ]] = Field(
        default=None,
        description="Privilege level at time of event."
    )

    # ── Infrastructure ────────────────────────
    host: Optional[str] = Field(
        default=None,
        description="Hostname where the event originated."
    )
    host_os: Optional[Literal[
        "windows", "linux", "macos", "unknown"
    ]] = Field(
        default=None,
        description="Operating system of the source host."
    )
    ip: Optional[str] = Field(
        default=None,
        description="Source IP address."
    )
    destination_ip: Optional[str] = Field(
        default=None,
        description="Destination IP for network events."
    )
    destination_port: Optional[int] = Field(
        default=None,
        description="Destination port for network events."
    )
    geo_country: Optional[str] = Field(
        default=None,
        description="Country derived from IP. Populated by enrichment layer."
    )

    # ── Action ────────────────────────────────
    action: ActionType = Field(
        description="What happened."
    )
    resource: Optional[str] = Field(
        default=None,
        description="What was acted on — file path, process name, API endpoint, DB table."
    )
    process_name: Optional[str] = Field(
        default=None,
        description="Process name for process-type events."
    )
    process_id: Optional[int] = Field(
        default=None,
        description="PID for process-type events."
    )
    parent_process: Optional[str] = Field(
        default=None,
        description="Parent process name. Critical for detecting process injection."
    )

    # ── Outcome ───────────────────────────────
    outcome: Optional[Literal["success", "failure", "unknown"]] = Field(
        default=None,
        description="Result of the action."
    )
    error_code: Optional[str] = Field(
        default=None,
        description="Error or status code if action failed."
    )

    # ── Data Quality Flags ────────────────────
    is_valid: bool = Field(
        default=True,
        description="False if the event failed any validation check. "
                    "Invalid events are stored but excluded from ML pipeline. "
                    "Never silently drop — always store with is_valid=False."
    )
    validation_errors: List[str] = Field(
        default_factory=list,
        description="List of validation failure reasons. "
                    "Empty if is_valid=True. "
                    "Examples: 'missing timestamp', 'unrecognized event_type', "
                    "'timezone-naive datetime'."
    )

    # ── Flexible Extension ────────────────────
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Source-specific fields that don't fit above. "
                    "Always a dict, never None. "
                    "Do not put validated fields here — promote them to explicit fields."
    )

    # ── Validators ────────────────────────────
    @validator("timestamp")
    def timestamp_must_be_timezone_aware(cls, v):
        if v.tzinfo is None:
            raise ValueError(
                "timestamp must be timezone-aware. "
                "Got naive datetime. "
                "Use datetime.now(timezone.utc) at source."
            )
        return v

    @validator("destination_port")
    def port_must_be_valid(cls, v):
        if v is not None and not (0 <= v <= 65535):
            raise ValueError(f"destination_port {v} is out of valid range 0-65535.")
        return v

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat()}


# ─────────────────────────────────────────────
# SCHEMA 2 — AGGREGATED BEHAVIOR SCHEMA
# Layer: Behavioral Aggregation
# Raw events → per-entity time-windowed feature summaries.
# One record per entity per time window.
# ─────────────────────────────────────────────

class BehaviorFeatures(BaseModel):

    # ── Login Behavior ────────────────────────
    login_fail_count: int = Field(default=0)
    login_success_count: int = Field(default=0)
    login_fail_ratio: float = Field(
        default=0.0,
        description="login_fail / (login_fail + login_success). "
                    "High ratio = brute force signal."
    )

    # ── Velocity Signals ──────────────────────
    # These track rate of change, not just totals.
    # Critical for detecting brute force spikes and exfil bursts.
    event_rate_per_minute: float = Field(
        default=0.0,
        description="Total events in window / window duration in minutes. "
                    "Sudden spike = automated attack or scripted action."
    )
    login_attempt_velocity: float = Field(
        default=0.0,
        description="Login attempts per minute in this window. "
                    "Separate from total count — a slow brute force attack "
                    "has low count but the velocity spike appears in short sub-windows."
    )
    data_transfer_rate: float = Field(
        default=0.0,
        description="Bytes transferred per minute (outbound). "
                    "Spike = possible exfiltration burst."
    )
    process_spawn_rate: float = Field(
        default=0.0,
        description="New processes spawned per minute. "
                    "High rate = possible malware execution or scripted attack."
    )

    # ── Network Behavior ──────────────────────
    unique_ips_accessed: int = Field(default=0)
    unique_destinations: int = Field(default=0)
    outbound_data_volume: float = Field(
        default=0.0,
        description="Total estimated bytes sent. 0 if not available."
    )
    inbound_data_volume: float = Field(default=0.0)
    unique_ports_used: int = Field(default=0)

    # ── Process Behavior ──────────────────────
    process_count: int = Field(default=0)
    unique_process_names: int = Field(default=0)
    suspicious_process_count: int = Field(
        default=0,
        description="Count of processes matching known suspicious patterns "
                    "e.g. mimikatz, psexec, certutil, wscript."
    )

    # ── Access Behavior ───────────────────────
    unique_hosts_accessed: int = Field(default=0)
    unique_resources_accessed: int = Field(default=0)
    sensitive_resource_access_count: int = Field(
        default=0,
        description="Access to flagged sensitive resources "
                    "e.g. /etc/passwd, SAM database, /proc/keys."
    )

    # ── Privilege Behavior ────────────────────
    privilege_escalation_attempts: int = Field(default=0)
    admin_action_count: int = Field(default=0)
    failed_privilege_actions: int = Field(default=0)

    # ── Temporal Behavior ─────────────────────
    after_hours_activity: bool = Field(
        default=False,
        description="True if any events occurred outside 08:00-20:00 local time."
    )
    weekend_activity: bool = Field(default=False)
    activity_hour_spread: int = Field(
        default=0,
        description="Number of distinct hours in window with activity. "
                    "Helps detect slow-and-low attacks spread over many hours."
    )

    # ── File Behavior ─────────────────────────
    file_read_count: int = Field(default=0)
    file_write_count: int = Field(default=0)
    file_delete_count: int = Field(default=0)
    unique_file_extensions: int = Field(
        default=0,
        description="Variety of file types touched. High = possible staged exfiltration."
    )

    # ── Database Behavior ─────────────────────
    db_query_count: int = Field(default=0)
    db_failed_query_count: int = Field(default=0)
    db_rows_accessed: int = Field(
        default=0,
        description="Estimated rows returned. High = bulk data access."
    )

    # ── DNS Behavior ──────────────────────────
    dns_query_count: int = Field(default=0)
    unique_dns_domains: int = Field(default=0)
    suspicious_dns_count: int = Field(
        default=0,
        description="Queries matching threat intel blocklists or DGA patterns."
    )


class AggregatedBehavior(BaseModel):

    schema_version: str = Field(default=SCHEMA_VERSION)

    # ── Pipeline Tracing ──────────────────────
    pipeline_id: str = Field(
        description="Propagated from UniversalEvent. Never regenerate."
    )

    # ── Identity ──────────────────────────────
    behavior_id: str = Field(
        default_factory=lambda: str(uuid4()),
        description="Unique ID for this aggregation record."
    )
    entity_id: str = Field(
        description="The user, host, or IP being profiled."
    )
    entity_type: EntityType = Field(
        description="What kind of entity this is."
    )

    # ── Time Window ───────────────────────────
    window_start: datetime = Field(
        description="Start of aggregation window. "
                    "Must be timezone-aware UTC. Required by tsfresh."
    )
    window_end: datetime = Field(
        description="End of aggregation window. "
                    "Must be timezone-aware UTC."
    )
    time_window: TimeWindow = Field(
        description="Named window size for reference."
    )
    event_count: int = Field(
        default=0,
        description="Total raw events aggregated into this window."
    )

    # ── Traceability ──────────────────────────
    source_event_ids: List[str] = Field(
        default_factory=list,
        description="event_ids of all UniversalEvents contributing to this window. "
                    "Used to trace any aggregation back to raw logs."
    )

    # ── Features ──────────────────────────────
    features: BehaviorFeatures = Field(
        default_factory=BehaviorFeatures,
        description="All computed behavioral features for this entity in this window."
    )

    # ── Validators ────────────────────────────
    @validator("window_start", "window_end")
    def must_be_timezone_aware(cls, v):
        if v.tzinfo is None:
            raise ValueError(
                "window_start and window_end must be timezone-aware. "
                "Use datetime.now(timezone.utc)."
            )
        return v

    @root_validator
    def window_end_after_start(cls, values):
        start = values.get("window_start")
        end = values.get("window_end")
        if start and end and end <= start:
            raise ValueError("window_end must be after window_start.")
        return values

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat()}


# ─────────────────────────────────────────────
# SCHEMA 3 — DETECTION OUTPUT SCHEMA
# Layer: UEBA + Anomaly Detection (PyOD)
# One record per entity per model per window.
# ─────────────────────────────────────────────

class DetectionOutput(BaseModel):

    schema_version: str = Field(default=SCHEMA_VERSION)

    # ── Pipeline Tracing ──────────────────────
    pipeline_id: str = Field(
        description="Propagated from AggregatedBehavior. Never regenerate."
    )

    # ── Identity ──────────────────────────────
    detection_id: str = Field(default_factory=lambda: str(uuid4()))
    behavior_id: str = Field(
        description="Links back to AggregatedBehavior that was scored."
    )
    entity_id: str
    entity_type: EntityType
    window_start: datetime
    window_end: datetime
    detected_at: datetime = Field(default_factory=utc_now)

    # ── Model Info ────────────────────────────
    model: ModelType = Field(
        description="Which PyOD model produced this score."
    )
    model_version: str = Field(
        default="1.0",
        description="Model version. Increment when retraining."
    )

    # ── Scores ────────────────────────────────
    anomaly_score: float = Field(
        ge=0.0, le=1.0,
        description="Normalized anomaly score. 0 = normal, 1 = maximally anomalous."
    )
    raw_score: float = Field(
        description="Raw model output before normalization."
    )
    threshold_used: float = Field(
        description="The threshold applied to classify anomaly. "
                    "Stored so fidelity layer knows margin above threshold."
    )
    score_margin: float = Field(
        description="anomaly_score - threshold_used. "
                    "Positive = anomaly, magnitude = confidence margin."
    )

    # ── Classification ────────────────────────
    label: Literal["normal", "anomaly"] = Field(
        description="Final binary classification."
    )
    severity: SeverityLevel = Field(
        description="Severity derived from score_margin bands."
    )

    # ── Explainability ────────────────────────
    features_used: Dict[str, float] = Field(
        default_factory=dict,
        description="All feature values input to the model for this detection."
    )
    top_contributing_features: List[str] = Field(
        default_factory=list,
        description="Top 3-5 features with highest contribution to anomaly score. "
                    "Fed directly into LLM prompt for explainable playbooks. "
                    "Do not leave empty — this is what makes playbooks useful."
    )

    # ── Validators ────────────────────────────
    @validator("window_start", "window_end", "detected_at")
    def must_be_timezone_aware(cls, v):
        if v.tzinfo is None:
            raise ValueError("All datetime fields must be timezone-aware UTC.")
        return v

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat()}


# ─────────────────────────────────────────────
# SCHEMA 4 — CORRELATED INCIDENT SCHEMA
# Layer: Correlation Engine + Graph Modeling
# Groups related detections across entities into one incident.
# ─────────────────────────────────────────────

class TimelineEvent(BaseModel):
    event_id: str = Field(description="Links to UniversalEvent.event_id.")
    timestamp: datetime = Field(
        description="Must be timezone-aware UTC."
    )
    entity_id: str
    action: ActionType
    resource: Optional[str] = None
    severity: SeverityLevel = "low"

    @validator("timestamp")
    def must_be_timezone_aware(cls, v):
        if v.tzinfo is None:
            raise ValueError("TimelineEvent.timestamp must be timezone-aware UTC.")
        return v

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat()}


class GraphEdge(BaseModel):
    source: str = Field(description="Source entity_id.")
    target: str = Field(description="Target entity_id.")
    weight: float = Field(
        default=1.0,
        description="Edge weight. Higher = stronger or more frequent relationship."
    )
    relation: str = Field(
        description="Type of relationship e.g. 'accessed', 'spawned', 'connected_to'."
    )
    # ── Time-aware edge fields (new) ──────────
    timestamp: datetime = Field(
        description="When this relationship was observed. "
                    "Enables time-ordered graph replay and attack chain reconstruction. "
                    "Must be timezone-aware UTC."
    )
    event_id: str = Field(
        description="The UniversalEvent.event_id that created this edge. "
                    "Enables full traceability from graph edge to raw log."
    )

    @validator("timestamp")
    def must_be_timezone_aware(cls, v):
        if v.tzinfo is None:
            raise ValueError("GraphEdge.timestamp must be timezone-aware UTC.")
        return v

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat()}


class GraphNode(BaseModel):
    id: str = Field(description="entity_id.")
    type: EntityType
    label: str = Field(description="Human-readable label e.g. 'user:john.doe'.")
    risk_score: float = Field(
        default=0.0,
        description="Cumulative risk score for this node across all detections."
    )


class GraphContext(BaseModel):
    nodes: List[GraphNode] = Field(
        default_factory=list,
        description="All entities in the attack graph."
    )
    edges: List[GraphEdge] = Field(
        default_factory=list,
        description="All observed relationships. Now time-aware."
    )
    centrality_scores: Dict[str, float] = Field(
        default_factory=dict,
        description="entity_id → betweenness centrality. "
                    "Highest = pivot point of the attack."
    )
    pivot_entity: Optional[str] = Field(
        default=None,
        description="Entity with highest centrality. Core of the attack chain."
    )
    lateral_movement_detected: bool = Field(
        default=False,
        description="True if graph shows movement across hosts or users."
    )
    subgraph_size: int = Field(
        default=0,
        description="Number of entities in the connected component."
    )


class CorrelatedIncident(BaseModel):

    schema_version: str = Field(default=SCHEMA_VERSION)

    # ── Pipeline Tracing ──────────────────────
    pipeline_id: str = Field(
        description="Propagated from DetectionOutput. Never regenerate."
    )

    # ── Identity ──────────────────────────────
    incident_id: str = Field(default_factory=lambda: str(uuid4()))
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)

    # ── Entities ──────────────────────────────
    entities: List[str] = Field(
        description="All entity_ids involved in this incident."
    )
    entity_types: Dict[str, EntityType] = Field(
        description="entity_id → entity_type mapping."
    )
    primary_entity: str = Field(
        description="Entity where the attack originated or is most active."
    )

    # ── Linked Records ────────────────────────
    detection_ids: List[str] = Field(
        description="All DetectionOutput.detection_id records in this incident."
    )
    source_event_ids: List[str] = Field(
        description="All raw UniversalEvent.event_id records involved."
    )

    # ── Timeline ──────────────────────────────
    incident_start: datetime = Field(
        description="Timestamp of first event. Must be timezone-aware UTC."
    )
    incident_end: datetime = Field(
        description="Timestamp of most recent event. Must be timezone-aware UTC."
    )
    duration_minutes: float = Field(
        description="incident_end - incident_start in minutes."
    )
    timeline: List[TimelineEvent] = Field(
        default_factory=list,
        description="Ordered list of key events. "
                    "Used by LLM to narrate the attack chain."
    )

    # ── Classification ────────────────────────
    pattern: AttackPattern
    attack_stage: AttackStage
    severity: SeverityLevel = Field(
        description="Highest severity across all detections in this incident."
    )

    # ── Graph ─────────────────────────────────
    graph_context: GraphContext = Field(
        default_factory=GraphContext
    )

    # ── Validators ────────────────────────────
    @validator("incident_start", "incident_end", "created_at", "updated_at")
    def must_be_timezone_aware(cls, v):
        if v.tzinfo is None:
            raise ValueError("All CorrelatedIncident datetime fields must be timezone-aware UTC.")
        return v

    @root_validator
    def end_after_start(cls, values):
        start = values.get("incident_start")
        end = values.get("incident_end")
        if start and end and end < start:
            raise ValueError("incident_end must not be before incident_start.")
        return values

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat()}


# ─────────────────────────────────────────────
# SCHEMA 5 — FIDELITY OUTPUT SCHEMA
# Layer: Fidelity Scoring Engine
# Combines anomaly + graph + posture + temporal into one score.
# LLM layer ONLY activates when is_stable=True AND confidence=high/critical.
# ─────────────────────────────────────────────

class ScoreBreakdown(BaseModel):
    anomaly_component: float = Field(
        ge=0.0, le=1.0,
        description="Weighted contribution from PyOD anomaly scores."
    )
    graph_component: float = Field(
        ge=0.0, le=1.0,
        description="Weighted contribution from graph centrality and lateral movement."
    )
    posture_component: float = Field(
        ge=0.0, le=1.0,
        description="Weighted contribution from privilege misuse and behavioral drift."
    )
    temporal_component: float = Field(
        ge=0.0, le=1.0,
        description="Weighted contribution from after-hours, weekend, signal stability."
    )
    weights: Dict[str, float] = Field(
        default_factory=lambda: {
            "anomaly": 0.40,
            "graph": 0.30,
            "posture": 0.20,
            "temporal": 0.10
        },
        description="Weights applied to each component. Must sum to 1.0."
    )

    @root_validator
    def weights_must_sum_to_one(cls, values):
        weights = values.get("weights", {})
        total = sum(weights.values())
        if weights and abs(total - 1.0) > 0.001:
            raise ValueError(
                f"ScoreBreakdown weights must sum to 1.0. Got {total:.4f}."
            )
        return values


class FidelityOutput(BaseModel):

    schema_version: str = Field(default=SCHEMA_VERSION)

    # ── Pipeline Tracing ──────────────────────
    pipeline_id: str = Field(
        description="Propagated from CorrelatedIncident. Never regenerate."
    )

    # ── Identity ──────────────────────────────
    fidelity_id: str = Field(default_factory=lambda: str(uuid4()))
    incident_id: str = Field(description="Links to CorrelatedIncident.")
    evaluated_at: datetime = Field(default_factory=utc_now)

    # ── Score ─────────────────────────────────
    fidelity_score: float = Field(
        ge=0.0, le=1.0,
        description="Final weighted confidence score. "
                    "0.50-0.74 = medium. 0.75-0.89 = high. 0.90+ = critical."
    )
    confidence: ConfidenceLevel = Field(
        description="Human-readable confidence band from fidelity_score."
    )
    score_breakdown: ScoreBreakdown = Field(
        description="Full component breakdown for transparency and audit."
    )

    # ── Stability ─────────────────────────────
    is_stable: bool = Field(
        description="True if signal has persisted across at least 2 consecutive windows. "
                    "LLM reasoning ONLY activates when this is True. "
                    "Prevents playbook generation on transient noise spikes."
    )
    stability_window_count: int = Field(
        default=1,
        description="How many consecutive windows this incident has been active."
    )
    signal_trend: Literal["rising", "stable", "falling"] = Field(
        default="stable",
        description="Whether fidelity score is increasing, stable, or decaying."
    )

    # ── Reasoning Trail ───────────────────────
    reasoning: Dict[str, Any] = Field(
        default_factory=dict,
        description="Structured explanation of why this score was assigned. "
                    "Stored in Elasticsearch for compliance audit."
    )

    # ── Validators ────────────────────────────
    @validator("evaluated_at")
    def must_be_timezone_aware(cls, v):
        if v.tzinfo is None:
            raise ValueError("FidelityOutput.evaluated_at must be timezone-aware UTC.")
        return v

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat()}


# ─────────────────────────────────────────────
# SCHEMA 6 — LLM INPUT SCHEMA
# Layer: Agentic SOC Reasoning (LangGraph + Ollama)
# Constructed from FidelityOutput + CorrelatedIncident.
# LLM never auto-triggers — always requires explicit human request.
# ─────────────────────────────────────────────

class SOARConstraints(BaseModel):
    require_human_approval: bool = Field(
        default=True,
        description="All generated actions must be approved before execution. "
                    "Must ALWAYS be True in production. Never override."
    )
    allowed_soar_actions: List[SOARAction] = Field(
        default_factory=lambda: [
            "alert_analyst",
            "increase_monitoring"
        ],
        description="Whitelist of actions the LLM may recommend. "
                    "Start minimal. Expand only per verified role."
    )
    max_blast_radius: BlastRadius = Field(
        default="user",
        description="Maximum scope of any recommended action. "
                    "LLM cannot recommend actions beyond this scope."
    )
    escalation_required_above_score: float = Field(
        default=0.85,
        description="Fidelity score above which human escalation is mandatory "
                    "regardless of other settings."
    )


class LLMInput(BaseModel):

    schema_version: str = Field(default=SCHEMA_VERSION)

    # ── Pipeline Tracing ──────────────────────
    pipeline_id: str = Field(
        description="Propagated from FidelityOutput. Never regenerate."
    )

    # ── Identity ──────────────────────────────
    llm_request_id: str = Field(default_factory=lambda: str(uuid4()))
    incident_id: str
    fidelity_id: str
    requested_at: datetime = Field(default_factory=utc_now)
    requested_by: str = Field(
        description="Username or role that triggered playbook generation. "
                    "LLM never auto-triggers — this field must always be set."
    )

    # ── Incident Context ──────────────────────
    incident_summary: str = Field(
        description="1-3 sentence plain-English summary written by the correlation layer. "
                    "Not generated by the LLM — given to the LLM as grounding context."
    )
    pattern: AttackPattern
    attack_stage: AttackStage
    risk_level: RiskLevel
    fidelity_score: float = Field(ge=0.0, le=1.0)

    # ── Evidence ──────────────────────────────
    affected_entities: List[Dict[str, str]] = Field(
        description="[{entity_id, entity_type, role_in_incident}]. "
                    "Role examples: 'attacker', 'pivot', 'target', 'victim'."
    )
    timeline_summary: List[Dict[str, Any]] = Field(
        description="Condensed attack timeline: [{timestamp, entity, action, resource}]. "
                    "Hard capped at max_timeline_entries. "
                    "Oldest events dropped first if over limit."
    )
    top_anomalous_features: List[Dict[str, Any]] = Field(
        description="[{feature_name, value, why_suspicious}]. "
                    "Hard capped at max_features. "
                    "These are what make the playbook specific and explainable."
    )
    score_breakdown: Dict[str, float] = Field(
        description="Component scores from FidelityOutput. "
                    "Gives LLM context for why the incident scored high."
    )

    # ── Prompt Size Limits ────────────────────
    max_timeline_entries: int = Field(
        default=10,
        description="Hard limit on timeline_summary length. "
                    "Enforced by the layer building this schema, not the LLM. "
                    "Keeps prompt size predictable and prevents context overflow."
    )
    max_features: int = Field(
        default=5,
        description="Hard limit on top_anomalous_features length. "
                    "Enforced by the layer building this schema, not the LLM."
    )

    # ── Output Spec ───────────────────────────
    recommended_action: List[SOARAction] = Field(
        default_factory=list,
        description="Pre-computed actions from rule engine. "
                    "LLM may add to this list but must never remove from it."
    )
    constraints: SOARConstraints = Field(
        default_factory=SOARConstraints,
        description="Hard constraints on what the LLM is allowed to recommend. "
                    "Validated again on PlaybookOutput before any action executes."
    )

    # ── Validators ────────────────────────────
    @validator("timeline_summary")
    def enforce_timeline_limit(cls, v, values):
        limit = values.get("max_timeline_entries", 10)
        if len(v) > limit:
            return v[-limit:]  # keep most recent
        return v

    @validator("top_anomalous_features")
    def enforce_features_limit(cls, v, values):
        limit = values.get("max_features", 5)
        return v[:limit]

    @validator("requested_at")
    def must_be_timezone_aware(cls, v):
        if v.tzinfo is None:
            raise ValueError("LLMInput.requested_at must be timezone-aware UTC.")
        return v

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat()}


# ─────────────────────────────────────────────
# SCHEMA 7 — PLAYBOOK OUTPUT SCHEMA
# Layer: LLM Output → SOAR Execution
# Validated against SOARConstraints before any action runs.
# ─────────────────────────────────────────────

class PlaybookStep(BaseModel):
    step_number: int
    action: SOARAction
    target_entity: str
    reason: str = Field(
        description="Why this specific action on this specific entity. "
                    "Written by LLM. Must be specific, not generic."
    )
    requires_approval: bool = Field(
        default=True,
        description="Always True unless explicitly overridden by authorized role."
    )
    approved: Optional[bool] = Field(
        default=None,
        description="Set by human analyst. None = pending review."
    )
    approved_by: Optional[str] = Field(default=None)
    approved_at: Optional[datetime] = Field(default=None)
    executed: bool = Field(default=False)
    executed_at: Optional[datetime] = Field(default=None)

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat()}


class PlaybookOutput(BaseModel):

    schema_version: str = Field(default=SCHEMA_VERSION)

    # ── Pipeline Tracing ──────────────────────
    pipeline_id: str = Field(
        description="Propagated from LLMInput. Never regenerate. "
                    "This is the field that ties every record in the system "
                    "back to one pipeline execution."
    )

    # ── Identity ──────────────────────────────
    playbook_id: str = Field(default_factory=lambda: str(uuid4()))
    incident_id: str
    llm_request_id: str
    generated_at: datetime = Field(default_factory=utc_now)

    # ── LLM Narrative ─────────────────────────
    threat_narrative: str = Field(
        description="LLM-written paragraph explaining the attack in analyst language. "
                    "Should reference specific entities, timestamps, and features."
    )
    attack_hypothesis: str = Field(
        description="LLM's best hypothesis for attacker intent."
    )

    # ── Steps ─────────────────────────────────
    steps: List[PlaybookStep] = Field(
        description="Ordered response actions. All require_approval=True by default."
    )

    # ── Constraint Validation ─────────────────
    within_constraints: bool = Field(
        description="True if all steps are within SOARConstraints. "
                    "Set by validator layer, never by LLM. "
                    "Must be True before any step can be approved."
    )
    validation_errors: List[str] = Field(
        default_factory=list,
        description="Constraint violations found. "
                    "Must be empty before execution is permitted."
    )

    # ── Status ────────────────────────────────
    status: Literal[
        "pending_review",
        "partially_approved",
        "approved",
        "executed",
        "rejected"
    ] = Field(default="pending_review")

    # ── Validators ────────────────────────────
    @validator("generated_at")
    def must_be_timezone_aware(cls, v):
        if v.tzinfo is None:
            raise ValueError("PlaybookOutput.generated_at must be timezone-aware UTC.")
        return v

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat()}