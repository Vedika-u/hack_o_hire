# ACT AWARE — HACK-O-HIRE PRESENTATION & ARCHITECTURE GUIDE
**Team Name:** PHEONIX CORE  
**Theme:** Cyber Incident Response in Banking  
**System Name:** ACT AWARE (Autonomous Cyber Threat Awareness, Reasoning & Execution)  
**Contract Version:** Frozen Data Contract v1.1.0  

---

## 1. What do you READ from ES and what do you WRITE to ES? (Layer-by-Layer Master Matrix)

This is the definitive answer for every teammate and every layer of the architecture:

| Layer | Owner | Component Name | READ from Elasticsearch | WRITE to Elasticsearch |
| :--- | :--- | :--- | :--- | :--- |
| **Layer 1–2** | **Nandni** | Data Collection & Normalization (Winlogbeat, Filebeat, Syslog, Ingest Pipeline) | **Nothing** (reads raw streaming logs from collectors, agents & simulators) | **`act_aware_events`** (validated ECS events)<br>`soc-dead-letter` (invalid logs) |
| **Layer 3–5** | **Navdeep** | Storage, Sliding Window Aggregation & Security Posture Engine | **`act_aware_events`** | **`act_aware_behaviors`** (per-entity time-window feature summaries) |
| **Layer 6–7** | **Kanchan** | Anomaly Detection (PyOD) & NetworkX Graph Attack Modeling | **`act_aware_behaviors`** (for feature scoring)<br>**`act_aware_events`** (for timeline reconstruction) | **`act_aware_detections`** (anomaly scores)<br>**`act_aware_incidents`** (correlated attack chains + graph context) |
| **Layer 8–9** | **Ruchika** | Fidelity Scoring & Agentic SOC Reasoning (LangGraph + Ollama) | **`act_aware_incidents`**<br>**`act_aware_detections`**<br>**`act_aware_behaviors`** | **`act_aware_fidelity`** (belief strength & stability)<br>**`act_aware_playbooks`** (advisory response playbooks)<br>**`act_aware_provenance`** (auditable AI reasoning steps) |
| **Layer 9–10** | **Vedika** | FastAPI Control Plane, SOAR Execution, Governance & Evaluation | **`act_aware_incidents`**<br>**`act_aware_fidelity`**<br>**`act_aware_playbooks`**<br>`soc_audit_log`<br>`soc_feedback` | **`act_aware_playbooks`** (status updates after human approval)<br>**`soc_actions`** (executed SOAR response records)<br>**`soc_audit_log`** (immutable compliance audit trail)<br>**`soc_evaluation_metrics`** (alert reduction rate & metrics)<br>**`soc_feedback`** (analyst feedback for retraining) |

---

## 2. Issues Identified in Team Chat & How They Are Fully Resolved

1. **Issue 1 (Index Name Mismatch — Nandni):**
   * *Problem:* Nandni was indexing to `soc-logs`.
   * *Resolution:* Standardized to `act_aware_events`. Invalid/corrupt logs route to `soc-dead-letter`.
2. **Issue 2 (Detection & Incident Index Overwrite — Kanchan):**
   * *Problem:* Kanchan wrote detections back to `act_aware_events`.
   * *Resolution:* Split into dedicated indices `act_aware_detections` (raw PyOD anomaly scores) and `act_aware_incidents` (correlated multi-stage incidents with attack graph).
3. **Issue 3 (Missing Behavior Index — Navdeep):**
   * *Problem:* Navdeep wrote to `soc-aggregated-behavior`.
   * *Resolution:* Standardized to `act_aware_behaviors` matching Frozen Data Contract v1.1.0.
4. **Issue 4 (Timestamp vs @timestamp):**
   * *Problem:* Python Pydantic contract uses `timestamp`, but Elasticsearch & Kibana require `@timestamp` for time-series aggregation.
   * *Resolution:* Normalizer (`layer1_ingestion/normalizer.py`) and ES client (`storage/es_client.py`) populate both fields simultaneously.
5. **Issue 5 (IP Address & Air-Gapped Mode):**
   * *Problem:* Distributed laptops on WiFi might disconnect or face firewall drops.
   * *Resolution:* Environment variables now dynamically resolve `172.20.132.59:9200` (team central node) and fall back gracefully to in-memory resilient mock storage if disconnected.

---

## 3. The 10-Layer System Architecture

```
[ LAYER 1-2: TELEMETRY & INGESTION ]
  Winlogbeat (AD/Sysmon) + Filebeat (Banking Apps) + Syslog (Firewall) + DB Logs
                           │
                           ▼ (Normalizer & ECS Mapping)
                  [ act_aware_events ]
                           │
[ LAYER 3-5: AGGREGATION & POSTURE ]
  Sliding Window Aggregator (1min, 5min, 15min) + Security Posture Engine
                           │
                           ▼
                [ act_aware_behaviors ]
                           │
[ LAYER 6-7: DETECTION & CORRELATION ]
  PyOD / Isolation Forest Anomaly Detection ──► [ act_aware_detections ]
                           │
                           ▼
  Multi-Source Correlation Engine + NetworkX Graph Attack Modeling
                           │
                           ▼
                 [ act_aware_incidents ]
                           │
[ LAYER 8-9: FIDELITY & AGENTIC REASONING ]
  Fidelity Scoring Engine (Anomaly 40% + Graph 30% + Posture 20% + Temporal 10%)
                           │
                           ▼
                 [ act_aware_fidelity ]
                           │ (Gated: is_stable=True AND confidence>=High AND human trigger)
                           ▼
  Agentic SOC Reasoning (LangGraph + Ollama Mistral)
                           ├──► [ act_aware_provenance ] (Audit Trail)
                           └──► [ act_aware_playbooks ] (Status: pending_review)
                           │
[ LAYER 9-10: CONTROL, SOAR & EVALUATION ]
  FastAPI Control Plane (RBAC: analyst, soc_manager)
                           │ (Human-in-the-loop Approval)
                           ▼
  SOAR Execution Engine (safety checks + rate limits) ──► [ soc_actions ]
                           ├──► [ soc_audit_log ]
                           ├──► [ soc_evaluation_metrics ] (Alert Reduction: 98%)
                           └──► [ soc_feedback ] (Closed-loop Model Retraining)
```

---

## 4. Banking Attack Scenario Walkthrough (Demo Day Pitch)

### Grounded in Real Banking Incidents:
* **Bangladesh Bank Heist (2016):** Attackers manipulated SWIFT credentials, moved laterally across local servers, and deleted logs to delay detection.
* **Capital One Breach (2019):** SSRF privilege escalation allowed unauthorized access to 100M+ customer credit card records.
* **US Treasury Incident (2024):** Advanced persistent threat leveraging compromised administrative tokens.

### How ACT AWARE Detects & Neutralizes It in the Demo:
1. **Stage 1 (Brute Force):** Attacker sprays passwords against `sarah.analyst` from IP `198.51.100.42`. Layer 4 detects a spike in `login_attempt_velocity` and `login_fail_ratio` (0.92).
2. **Stage 2 (Privilege Escalation):** Attacker gains entry, spawns `powershell.exe` -> `mimikatz.exe`, acquires `admin_token`, and accesses `SAM database`. Layer 5 Posture Engine flags critical privilege misuse.
3. **Stage 3 (Lateral Movement):** Attacker traverses to `host:dc-prod-01` and pivots to `host:swift-core-srv` via SMB 445 using `psexec`. Layer 7 NetworkX graph maps the lateral hops and calculates betweenness centrality, isolating `sarah.analyst` / `host:workstation-088` as the primary pivot.
4. **Stage 4 (Database Exfiltration):** Attacker issues bulk SQL query dumping 52,400 customer records and tunnels 157MB outbound to foreign C2 `203.0.113.88`. Layer 6 PyOD flags anomaly score of `1.0000`.
5. **Stage 5 (Fidelity & Playbook):** Fidelity Engine evaluates persistence across windows -> assigns Score `0.8655 (HIGH, STABLE)`. Senior analyst triggers AI reasoning. The Agentic SOC engine drafts an advisory response playbook.
6. **Stage 6 (Human Approval & SOAR):** SOC Manager reviews the proposed actions:
   * `[ISOLATE_ENDPOINT]` on primary pivot `sarah.analyst`
   * `[FORCE_LOGOUT]` for active sessions
   * `[REVOKE_TOKEN]` for `admin.domain`
   * `[BLOCK_IP]` on ingress `198.51.100.42` and egress `203.0.113.88`
   * `[ALERT_ANALYST]` priority emergency ticket
   All actions execute with zero human error under strict safety checks.
7. **Stage 7 (Metrics):** Alert reduction of **98.00%** (50 noisy events condensed to 1 actionable incident).

---

## 5. How to Run the Demo for Judges

### Command 1: End-to-End Autonomous Pipeline Simulation
```powershell
python run_pipeline.py
```
*Outputs complete execution log, anomaly scoring, NetworkX graph metrics, fidelity calculation, advisory playbook, SOAR execution, and evaluation metrics.*

### Command 2: Start the FastAPI Control Plane
```powershell
python run.py
```
*Starts Swagger UI at `http://localhost:8000/docs`.*

### Command 3: Run Full Test Suite
```powershell
python test_pipeline_and_api.py
```
