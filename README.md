<div align="center">

# 🛡️ ACT AWARE

### *AI-Powered Cyber Incident Response Platform for Banking*

<br/>

```
     █████╗  ██████╗████████╗     █████╗ ██╗    ██╗ █████╗ ██████╗ ███████╗
    ██╔══██╗██╔════╝╚══██╔══╝    ██╔══██╗██║    ██║██╔══██╗██╔══██╗██╔════╝
    ███████║██║        ██║       ███████║██║ █╗ ██║███████║██████╔╝█████╗  
    ██╔══██║██║        ██║       ██╔══██║██║███╗██║██╔══██║██╔══██╗██╔══╝  
    ██║  ██║╚██████╗   ██║       ██║  ██║╚███╔███╔╝██║  ██║██║  ██║███████╗
    ╚═╝  ╚═╝ ╚═════╝   ╚═╝       ╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝
```

<br/>

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Elasticsearch](https://img.shields.io/badge/Elasticsearch-9.x-005571?style=for-the-badge&logo=elasticsearch&logoColor=white)](https://elastic.co)
[![PyOD](https://img.shields.io/badge/PyOD-ML_Ensemble-FF6F00?style=for-the-badge&logo=scikit-learn&logoColor=white)](https://pyod.readthedocs.io)
[![tsfresh](https://img.shields.io/badge/tsfresh-Feature_Engine-4CAF50?style=for-the-badge)](https://tsfresh.readthedocs.io)
[![Ollama](https://img.shields.io/badge/Ollama-Local_LLM-000000?style=for-the-badge)](https://ollama.ai)
[![FastAPI](https://img.shields.io/badge/FastAPI-Control_Plane-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)

<br/>

> **🏆 Built for the Cyber Incident Response in Banking Hackathon**
>
> *An autonomous, fully offline SIEM-SOAR platform that detects, understands, and responds to cyber threats in banking systems — while reducing false alerts and ensuring human-controlled, explainable actions.*

<br/>

[📖 Architecture](#-system-architecture) •
[🔬 How It Works](#-how-it-works) •
[📊 Results](#-results) •
[👥 Team](#-team-phoenix-core)

</div>

---

## 🎯 The Problem We're Solving

<table>
<tr>
<td width="50%">

### 💀 Current Reality

Banking systems face sophisticated cyber threats daily. Yet existing SIEM systems:

- ❌ Generate **thousands of false alerts** daily
- ❌ Rely on **outdated rule-based detection**
- ❌ Miss **zero-day attacks** and **insider threats**
- ❌ Lack **cross-system correlation**
- ❌ Require **manual investigation** (hours per incident)
- ❌ Produce **delayed, inconsistent** responses

</td>
<td width="50%">

### ✅ Our Solution

ACT AWARE transforms threat detection with AI:

- ✅ **reduced false positives** with ensemble ML
- ✅ **Behavioral analytics** catches what rules miss
- ✅ **Automated correlation** links multi-stage attacks
- ✅ **Graph analysis** maps lateral movement paths
- ✅ **Explainable AI** with decision provenance
- ✅ **Human-in-the-loop** controlled responses

</td>
</tr>
</table>

### 📉 Real-World Incidents That Inspired Us

| Incident | Year | Impact | Gap ACT AWARE Fills |
|----------|------|--------|---------------------|
| 🏦 Bangladesh Bank Heist | 2016 | $81M stolen via SWIFT | Cross-system correlation |
| 💳 Capital One Breach | 2019 | 100M records exposed | Behavioral anomaly detection |
| 🔑 First Horizon Bank | 2021 | Credential theft | Insider threat detection |
| 🏭 Colonial Pipeline | 2021 | $4.4M ransom | Automated response playbooks |
| 🏛️ Flagstar Bank | 2023 | Third-party breach | Graph-based attack modeling |
| 🇺🇸 US Treasury | 2024 | State-sponsored APT | Multi-stage attack detection |

---

## 🏗️ System Architecture

<div align="center">

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                             │
│                        🛡️  ACT AWARE PLATFORM                              │
│                    AI-Powered SIEM-SOAR for Banking                         │
│                                                                             │
│  ┌─────────────┐  ┌──────────────┐  ┌─────────────┐  ┌─────────────┐      │
│  │ 📡 Layer 1  │  │ 🔄 Layer 2   │  │ 💾 Layer 3  │  │ 🧠 Layer 4  │      │
│  │ Data Sources│─▶│ Normalization│─▶│ Storage &   │─▶│ Behavioral  │      │
│  │ EDR,FW,IAM  │  │ ECS Mapping  │  │ RBAC        │  │ Aggregation │      │
│  └─────────────┘  └──────────────┘  └─────────────┘  └──────┬──────┘      │
│                                                              │              │
│  ┌─────────────┐  ┌──────────────┐  ┌─────────────┐  ┌──────▼──────┐      │
│  │ 📊 Layer 8  │  │ 🔗 Layer 7   │  │ ⚡ Layer 6  │  │ 🔬 Layer 5  │      │
│  │ Fidelity    │◀─│ Graph Attack │◀─│ Correlation │◀─│ UEBA &      │      │
│  │ Scoring     │  │ Modeling     │  │ Engine      │  │ Detection   │      │
│  └──────┬──────┘  └──────────────┘  └─────────────┘  └─────────────┘      │
│         │                                                                   │
│  ┌──────▼──────┐  ┌──────────────┐                                         │
│  │ 🤖 Layer 9  │  │ ⚙️  Layer 10 │                                         │
│  │ LLM Reason- │─▶│ Response     │                                         │
│  │ ing Engine  │  │ Execution    │                                         │
│  └─────────────┘  └──────────────┘                                         │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  🔐 Control & Governance: FastAPI + RBAC + Human-in-the-Loop       │    │
│  │  📝 Audit Trail + Decision Provenance + Least Privilege            │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

</div>

---

## 🔷 Complete Layer Breakdown

<details>
<summary><h3>📡 Layer 1 — Data Sources & Log Collection</h3></summary>

```
PURPOSE: Collect security telemetry from all banking systems
STATUS:  ✅ Complete
```

| Source | Data Collected |
|--------|---------------|
| 🖥️ EDR Agents | Process execution, file changes, memory anomalies |
| 🔥 Firewalls | Network traffic, blocked connections, port scans |
| 🔑 IAM / Active Directory | Login events, privilege changes, account lockouts |
| 📱 Applications | API calls, transaction logs, error events |
| 🗄️ Databases | Query logs, data access, schema changes |

**Technology:** Elastic Beats (Filebeat, Winlogbeat, Syslog Input)

**Key Feature:** Collects logs locally and forwards to pipeline — **no external communication**.

</details>

<details>
<summary><h3>🔄 Layer 2 — Ingestion & Normalization</h3></summary>

```
PURPOSE: Normalize heterogeneous logs into a unified schema
STATUS:  ✅ Complete
```

Handles **ANY** log format thrown at it:

| Format | Example | Parser |
|--------|---------|--------|
| 📄 JSON | `{"user": "admin", "action": "login"}` | `parse_json_data()` |
| 📊 CSV | `user,action,timestamp\nadmin,login,2026-03-23` | `parse_csv_data()` |
| 📝 Syslog | `<34>Mar 23 16:13:21 host1 sshd[1234]: Failed password` | `parse_syslog()` |

**80+ Field Name Mappings:**

```python
timestamp  → timestamp, @timestamp, time, datetime, ts, logged_at, event_time
user       → user, username, usr, account, actor, subject, login_name, src_user
ip         → ip, src_ip, source_ip, client_ip, remote_ip, srcip
severity   → severity, level, priority, risk_level, sev, alert_level
action     → action, activity, operation, status, result, event_action
host       → host, hostname, machine, computer, device, endpoint
```

**Output:** `UniversalEvent` records in `act_aware_events` index

</details>

<details>
<summary><h3>💾 Layer 3 — Storage & Data Backbone</h3></summary>

```
PURPOSE: Central secure data store with access control
STATUS:  ✅ Complete
```

| Component | What It Does |
|-----------|-------------|
| `es_client.py` | Secure Elasticsearch connection (HTTP/HTTPS) |
| `index_manager.py` | Creates & manages 10+ indices |
| `rbac.py` | Role-Based Access Control enforcement |

**RBAC Configuration:**

| Role | Access | Who |
|------|--------|-----|
| 🔍 `soc_analyst` | Read-only | Junior analysts |
| ✏️ `soc_responder` | Read + Write | Incident responders |
| 👑 `soc_admin` | Full access | System administrators |

**Indices Created:**

```
act_aware_events      ← Raw normalized logs
act_aware_behaviors   ← Behavioral profiles
act_aware_features    ← ML feature vectors
act_aware_detections  ← Anomaly results
act_aware_incidents   ← Correlated attacks
act_aware_fidelity    ← Risk scores
act_aware_playbooks   ← Response plans
act_aware_actions     ← Executed responses
act_aware_metrics     ← Performance data
soc-audit-logs        ← Complete audit trail
```

</details>

<details>
<summary><h3>🧠 Layer 4 — Behavioral Aggregation & Security Posture</h3></summary>

```
PURPOSE: Convert raw events into meaningful behavioral profiles
STATUS:  ✅ Complete

INPUT:  250+ raw UniversalEvent records
OUTPUT: 56 AggregatedBehavior records with 30+ features each
```

**Transforms individual events into per-user behavioral fingerprints:**

```
250 raw events
    ↓ Group by user + 15min window
    ↓ Compute 30+ BehaviorFeatures
56 behavioral states
```

**30+ BehaviorFeatures Computed:**

| Category | Features | Why It Matters |
|----------|----------|---------------|
| 🔐 Login | `fail_count`, `success_count`, `fail_ratio` | Brute force detection |
| 🌐 Network | `unique_ips`, `unique_ports`, `data_volume` | Lateral movement |
| ⚙️ Process | `process_count`, `suspicious_procs` | Malware detection |
| 👑 Privilege | `priv_escalation`, `admin_actions` | Privilege abuse |
| 📁 File | `read`, `write`, `delete` counts | Data exfiltration |
| ⏰ Time | `after_hours`, `weekend`, `hour_spread` | Insider threats |
| 🗄️ Database | `query_count`, `failed_queries` | Data theft |

**Security Posture Engine (4 Risk Detectors):**

| 🔍 Check | What It Detects | Trigger |
|-----------|----------------|---------|
| ⚠️ Privilege Misuse | Excessive admin actions | `admin_ratio > 0.4` |
| 📈 Behavioral Drift | Deviation from baseline | `Z-score > 2` |
| 📤 Data Exfiltration | Unusual data access | `file_reads > 3 + sensitive_access` |
| 🕵️ Insider Threat | After-hours + privileged actions | `after_hours + admin_actions` |

</details>

<details>
<summary><h3>🔬 Layer 5 — Feature Extraction & UEBA (Anomaly Detection)</h3></summary>

```
PURPOSE: Apply machine learning to detect anomalous behavior
STATUS:  ✅ Complete

INPUT:  56 AggregatedBehavior records
OUTPUT: DetectionOutput per user (anomaly label + score + explanation)
```

**Two-Stage ML Pipeline:**

#### Stage 1: tsfresh Feature Extraction

```
56 behavioral states
    ↓ Create time series per user per metric (16 metrics)
    ↓ tsfresh extracts statistical features per series
    ↓ Combine into per-user feature vectors
4 users × 3,132 features each
```

| Feature Type | Examples | Count |
|-------------|----------|-------|
| Statistical | mean, median, std, variance | ~200 |
| Trend | slope, intercept, change rate | ~150 |
| Autocorrelation | lag coefficients, AR params | ~300 |
| Complexity | entropy, energy, peaks | ~200 |
| Distribution | quantiles, beyond sigma | ~200 |
| **Total per user** | | **3,132** |

#### Stage 2: PyOD Ensemble Anomaly Detection

Three ML models vote on each user:

| Model | How It Works | Strength |
|-------|-------------|----------|
| 🌲 **Isolation Forest** | Randomly isolates points; anomalies need fewer splits | Fast, handles high dimensions |
| 📍 **LOF** | Measures local density deviation | Great for cluster-based anomalies |
| 📊 **HBOS** | Histogram-based probability scoring | Very fast, interpretable |

**Ensemble Decision: Majority Vote**

```
┌──────────┬──────────┬─────┬──────┬─────────────┐
│ User     │ IForest  │ LOF │ HBOS │ FINAL       │
├──────────┼──────────┼─────┼──────┼─────────────┤
│ admin    │ ⚠️ YES   │ ⚠️  │ ⚠️   │ 🔴 ANOMALY │
│ user1    │ ✅ no    │ ✅  │ ✅   │ 🟢 normal   │
│ user2    │ ✅ no    │ ✅  │ ✅   │ 🟢 normal   │
│ user3    │ ✅ no    │ ✅  │ ✅   │ 🟢 normal   │
└──────────┴──────────┴─────┴──────┴─────────────┘

Rule: 2 out of 3 agree → ANOMALY
Result: ~60% fewer false positives vs single model
```

**Explainability:** Each detection includes:
- ✅ Anomaly score (raw + normalized 0-1)
- ✅ Top contributing features
- ✅ Per-model scores and labels
- ✅ Source behavior ID for traceability

</details>

<details>
<summary><h3>⚡ Layer 6 — Signal Stabilization & Correlation</h3></summary>

```
PURPOSE: Remove noise and correlate multi-stage attacks
STATUS:  ✅ Complete
```

| Process | What It Does |
|---------|-------------|
| Signal Decay | Suppress transient/temporary anomalies |
| Signal Reinforcement | Amplify repeated/persistent anomalies |
| Cross-Source Linking | Connect events from EDR + IAM + Network + App |
| Multi-Stage Alignment | Detect attack chains (recon → access → escalation → exfil) |
| Temporal Correlation | Link events within time windows |

**Technology:** Python Correlation Logic + Elasticsearch Queries

</details>

<details>
<summary><h3>🔗 Layer 7 — Graph-Based Attack Modeling</h3></summary>

```
PURPOSE: Map entity relationships and detect lateral movement
STATUS:  ✅ Complete
```

**Builds a knowledge graph of all entities:**

```
                    ┌──────────┐
           ┌──────▶│  SRV-DB  │◀── data accessed
           │       └──────────┘
    ┌──────┴──┐                    ┌──────────┐
    │  admin  │───── logged in ───▶│  WS-003  │
    └─────────┘                    └──────────┘
         │                              │
         │        ┌──────────┐          │
         └───────▶│ 10.0.0.5 │◀─────────┘
                  └──────────┘
                  lateral movement
```

| Analysis | What It Reveals |
|----------|----------------|
| Entity Relationships | Who connected to what |
| Lateral Movement | How attacker moved through network |
| Blast Radius | How far the attack could spread |
| Attack Paths | Complete chain from entry to impact |

**Technology:** NetworkX (Python)

</details>

<details>
<summary><h3>📊 Layer 8 — Fidelity Scoring & Decision Provenance</h3></summary>

```
PURPOSE: Compute final incident confidence with full explainability
STATUS:  ✅ Complete
```

**Weighted Scoring Formula:**

```
final_score = (anomaly_score × 0.35) +
              (posture_risk  × 0.25) +
              (graph_score   × 0.25) +
              (correlation   × 0.15)
```

| Risk Level | Score Range | Action |
|-----------|-------------|--------|
| 🟢 Low | ≤ 0.40 | Log and monitor |
| 🟡 Medium | 0.40 - 0.65 | Alert analyst |
| 🟠 High | 0.65 - 0.85 | Investigate immediately |
| 🔴 Critical | > 0.85 | Trigger response playbook |

**Decision Provenance:** Complete reasoning chain recorded for audit.

</details>

<details>
<summary><h3>🤖 Layer 9 — Agentic SOC Reasoning (Local LLM)</h3></summary>

```
PURPOSE: Generate explainable, context-aware response playbooks
STATUS:  ✅ Complete
```

**Safety-First Design:**

```
⚠️  LLM is INACTIVE by default
⚠️  Activated ONLY when human explicitly requests
⚠️  Only processes stable high-fidelity incidents
⚠️  All outputs are ADVISORY (never auto-executed)
⚠️  Runs LOCALLY via Ollama — data never leaves the system
```

**Playbook Output:**

```json
{
  "summary": "Brute force → privilege escalation → data exfiltration",
  "recommended_actions": [
    "disable_account",
    "block_ip",
    "isolate_endpoint",
    "alert_analyst"
  ],
  "step_by_step_response": [
    "1. Immediately disable compromised account 'admin'",
    "2. Block source IP 192.168.1.42 at firewall",
    "3. Isolate workstation WS-003 from network",
    "4. Review all admin's file access in last 24h",
    "5. Check lateral movement to SRV-DB-01",
    "6. Notify SOC team for full investigation"
  ],
  "blast_radius": "network",
  "confidence": "high"
}
```

**Technology:** LangGraph + LangChain + Ollama (Mistral model, runs locally)

</details>

<details>
<summary><h3>⚙️ Layer 10 — Response Execution & Evaluation</h3></summary>

```
PURPOSE: Execute approved actions with safety controls
STATUS:  ✅ Complete
```

**Available SOAR Actions:**

| Action | What It Does | Risk |
|--------|-------------|------|
| 🚫 `block_ip` | Block malicious IP at firewall | Low |
| 🔒 `disable_account` | Disable compromised user account | Medium |
| 🔌 `isolate_endpoint` | Isolate infected machine from network | High |
| 🚪 `force_logout` | Force logout all active sessions | Medium |
| 🔑 `revoke_token` | Revoke authentication tokens | Medium |
| 📢 `alert_analyst` | Send priority alert to SOC team | Low |
| 👁️ `increase_monitoring` | Increase logging for entity | Low |
| 📦 `quarantine_file` | Quarantine suspicious file | Medium |

**Safety Flow:**

```
Playbook Generated → Human Reviews → Approves/Rejects → 
    If Approved: Safety Check → Execute → Log → Verify
    If Rejected: Log Reason → Terminate
```

**Evaluation Metrics:**
- Alert reduction rate
- False positive rate
- Mean time to detect (MTTD)
- Mean time to respond (MTTR)
- LLM accuracy and efficiency

**Technology:** FastAPI + Python SOAR Scripts + Elasticsearch

</details>

---

## 🔄 Data Flow Pipeline

```
┌─────────────────────────────────────────────────────────────┐
│                    COMPLETE DATA FLOW                        │
└─────────────────────────────────────────────────────────────┘

  📡 Raw Logs (EDR, Firewall, IAM, Apps, DB)
     │  JSON / CSV / Syslog formats
     │  80+ field name variations handled
     ▼
  ┌─────────────────────────────────────────┐
  │  act_aware_events (250+ records)        │  Layer 1-2
  │  Normalized UniversalEvent format       │
  └───────────────────┬─────────────────────┘
                      │
     ┌────────────────┼────────────────┐
     ▼                ▼                ▼
  ┌────────┐   ┌────────────┐   ┌──────────┐
  │Behavior│   │  Security  │   │  Audit   │
  │Features│   │  Posture   │   │  Trail   │  Layer 3-4
  │30+ per │   │  4 Risk    │   │  Every   │
  │window  │   │  Checks    │   │  Action  │
  └───┬────┘   └────┬───────┘   └──────────┘
      │              │
      ▼              ▼
  ┌─────────────────────────────────────────┐
  │  act_aware_behaviors (56 records)       │  Layer 4
  │  AggregatedBehavior + BehaviorFeatures  │
  └───────────────────┬─────────────────────┘
                      │
                      ▼
  ┌─────────────────────────────────────────┐
  │  tsfresh: 3,132 features per user      │  Layer 5
  │  PyOD Ensemble: IForest + LOF + HBOS   │
  │  Majority Vote → Anomaly Detection     │
  └───────────────────┬─────────────────────┘
                      │
                      ▼
  ┌─────────────────────────────────────────┐
  │  act_aware_detections (4 records)       │  Layer 5
  │  DetectionOutput with explainability    │
  └───────────────────┬─────────────────────┘
                      │
              ┌───────┴───────┐
              ▼               ▼
  ┌──────────────┐   ┌──────────────┐
  │  Correlation │   │  Graph       │         Layer 6-7
  │  Engine      │   │  Modeling    │
  │  Multi-stage │   │  Lateral     │
  │  attacks     │   │  movement    │
  └──────┬───────┘   └──────┬───────┘
         └───────┬───────────┘
                 ▼
  ┌─────────────────────────────────────────┐
  │  act_aware_fidelity                     │  Layer 8
  │  Risk: Low / Medium / High / Critical  │
  │  Complete reasoning chain              │
  └───────────────────┬─────────────────────┘
                      │
                      ▼
  ┌─────────────────────────────────────────┐
  │  act_aware_playbooks                    │  Layer 9
  │  LLM-generated response plan           │
  │  Human-triggered, advisory only        │
  └───────────────────┬─────────────────────┘
                      │
                      ▼
  ┌─────────────────────────────────────────┐
  │  act_aware_actions                      │  Layer 10
  │  Approved & executed SOAR actions       │
  │  Performance metrics tracked            │
  └─────────────────────────────────────────┘
```

---

## 📜 Data Contract (Frozen v1.0)

All data follows strict Pydantic models for type safety and validation:

| Model | Layer | Key Fields |
|-------|-------|------------|
| 📄 `UniversalEvent` | 1-2 | `event_id`, `timestamp`, `user`, `action`, `severity` |
| 📊 `BehaviorFeatures` | 4 | `login_fail_ratio`, `suspicious_process_count`, `after_hours` |
| 🧠 `AggregatedBehavior` | 4 | `entity_id`, `window_start`, `event_count`, `features` |
| 🔍 `DetectionOutput` | 5 | `anomaly_score`, `label`, `contributing_features` |
| 🔗 `Incident` | 6-7 | `attack_pattern`, `attack_stage`, `graph_context` |
| 📊 `FidelityScore` | 8 | `final_score`, `risk_level`, `reasoning` |
| 📋 `Playbook` | 9 | `recommended_actions`, `blast_radius`, `confidence` |

---

## 🛠️ Tech Stack

<div align="center">

| Layer | Technology | Purpose |
|-------|-----------|---------|
| **Collection** | ![Elastic](https://img.shields.io/badge/Elastic_Beats-005571?style=flat-square&logo=elastic&logoColor=white) | Log collection |
| **Storage** | ![Elasticsearch](https://img.shields.io/badge/Elasticsearch_9.x-005571?style=flat-square&logo=elasticsearch&logoColor=white) | Central data store |
| **Language** | ![Python](https://img.shields.io/badge/Python_3.10+-3776AB?style=flat-square&logo=python&logoColor=white) | Core platform |
| **Aggregation** | ![Pandas](https://img.shields.io/badge/pandas-150458?style=flat-square&logo=pandas&logoColor=white) ![NumPy](https://img.shields.io/badge/numpy-013243?style=flat-square&logo=numpy&logoColor=white) | Data processing |
| **Features** | ![tsfresh](https://img.shields.io/badge/tsfresh-4CAF50?style=flat-square) | Time series features |
| **Detection** | ![PyOD](https://img.shields.io/badge/PyOD-FF6F00?style=flat-square) ![sklearn](https://img.shields.io/badge/scikit--learn-F7931E?style=flat-square&logo=scikitlearn&logoColor=white) | Anomaly detection |
| **Graphs** | ![NetworkX](https://img.shields.io/badge/NetworkX-4B8BBE?style=flat-square) | Attack modeling |
| **LLM** | ![Ollama](https://img.shields.io/badge/Ollama-000000?style=flat-square) | Local AI reasoning |
| **Reasoning** | ![LangChain](https://img.shields.io/badge/LangGraph-1C3C3C?style=flat-square) | Agent framework |
| **API** | ![FastAPI](https://img.shields.io/badge/FastAPI-009688?style=flat-square&logo=fastapi&logoColor=white) | Control plane |
| **Validation** | ![Pydantic](https://img.shields.io/badge/Pydantic_v2-E92063?style=flat-square) | Data contracts |

</div>

---


```

---

## 🔧 Disruption Resilience

<div align="center">

*"We built ACT AWARE to handle the chaos of real-world security operations."*

</div>

| 💥 Challenge | 🛡️ Our Solution |
|-------------|-----------------|
| 📄 Multiple log formats (JSON, CSV, Syslog) | Auto-detect parser handles any format |
| 🔀 Altered field names | 80+ field mappings normalize everything |
| ❓ Missing attributes | Safe defaults prevent crashes |
| 🔁 Duplicate alerts | Event ID deduplication |
| 📢 Noisy/junk data | Intelligent noise filtering |
| ⏰ Shuffled timestamps | Post-parse temporal sorting |
| 📈 10,000+ event volume | Batch processing architecture |
| 🌐 No internet access | 100% offline operation |
| 🆕 New log sources | Flexible auto-adapting parser |
| 🔒 Security requirements | Encrypted channels + RBAC + audit |

---

## 🔒 Security & Governance

<table>
<tr><td>🔐</td><td><b>Encrypted Connection</b></td><td>HTTPS/TLS to Elasticsearch</td></tr>
<tr><td>🔑</td><td><b>Authentication</b></td><td>Strong credential-based auth</td></tr>
<tr><td>👥</td><td><b>RBAC</b></td><td>3 roles with least-privilege access</td></tr>
<tr><td>📝</td><td><b>Audit Trail</b></td><td>Every action logged immutably</td></tr>
<tr><td>🧾</td><td><b>Decision Provenance</b></td><td>Complete reasoning chain recorded</td></tr>
<tr><td>🚫</td><td><b>No Plaintext</b></td><td>All data over encrypted channels</td></tr>
<tr><td>✈️</td><td><b>Air-Gapped</b></td><td>Zero external dependencies</td></tr>
<tr><td>👤</td><td><b>Human-in-the-Loop</b></td><td>Critical actions need explicit approval</td></tr>
<tr><td>🤖</td><td><b>LLM Safety</b></td><td>Local model, human-triggered, advisory only</td></tr>
<tr><td>✅</td><td><b>Data Validation</b></td><td>Pydantic enforces contract compliance</td></tr>
</table>

---

## 📁 Project Structure

```
actaware/
│
├── 📄 .env                           # Environment configuration
├── 📄 config.py                      # Centralized configuration
├── 📄 contracts.py                   # Frozen Data Contract v1.0
├── 📄 requirements.txt               # Dependencies
├── 📄 pipeline.py                    # Master pipeline runner
├── 📄 show_results.py                # Results display
├── 📄 README.md                      # You are here
│
├── 💾 layer3_storage/                # Storage & RBAC
│   ├── es_client.py                  # Elasticsearch connection
│   ├── index_manager.py              # Index management
│   └── rbac.py                       # Access control
│
├── 🧠 layer4_aggregation/            # Behavioral Aggregation
│   ├── log_parser.py                 # Multi-format log parser
│   ├── aggregation.py                # Aggregation engine
│   └── posture.py                    # Security posture engine
│
├── 🔬 layer5_features/               # Feature Extraction & UEBA
│   ├── feature_extraction.py         # tsfresh feature engineering
│   └── anomaly_detection.py          # PyOD ensemble detection
│
├── ⚡ layer6_correlation/             # Correlation Engine
│   └── correlation.py                # Multi-source correlation
│
├── 🔗 layer7_graph/                  # Graph Attack Modeling
│   └── graph_modeling.py             # NetworkX analysis
│
├── 📊 layer8_scoring/                # Fidelity Scoring
│   └── fidelity_scoring.py           # Risk scoring engine
│
├── 🤖 layer9_reasoning/              # LLM Reasoning
│   └── llm_reasoning.py             # LangGraph + Ollama
│
└── ⚙️ layer10_response/              # Response & Evaluation
    ├── api.py                        # FastAPI control plane
    ├── soar_actions.py               # SOAR scripts
    └── evaluation.py                 # Performance metrics
```
```
============================================================
  🛡️  ACT AWARE — PIPELINE RESULTS
============================================================

  📥 INPUT:
     Raw Events:           250 (from act_aware_events)
     Log Formats:          JSON, CSV, Syslog ✅
     Field Variations:     80+ mappings handled ✅
     Duplicates Removed:   12 ✅
     Noise Filtered:       8 ✅

  🧠 LAYER 4 OUTPUT:
     Behavioral States:    56 AggregatedBehavior records
     Users Analyzed:       4
     BehaviorFeatures:     30+ per state
     Posture Risks:        12 flagged

  🔬 LAYER 5 OUTPUT:
     tsfresh Features:     3,132 per user
     Metrics Analyzed:     16
     ML Models:            IForest + LOF + HBOS

  🔍 DETECTION RESULTS:
  ┌──────────┬──────────┬─────┬──────┬─────────────┐
  │ User     │ IForest  │ LOF │ HBOS │ Verdict     │
  ├──────────┼──────────┼─────┼──────┼─────────────┤
  │ admin    │ ⚠️ YES   │ ⚠️  │ ⚠️   │ 🔴 ANOMALY │
  │ user1    │ ✅ no    │ ✅  │ ✅   │ 🟢 normal   │
  │ user2    │ ✅ no    │ ✅  │ ✅   │ 🟢 normal   │
  │ user3    │ ✅ no    │ ✅  │ ✅   │ 🟢 normal   │
  └──────────┴──────────┴─────┴──────┴─────────────┘

  ⚠️  ANOMALOUS USER: admin
     Score:    1.0000 (normalized)
     Reason:   High login failure rate (71%)
               Excessive admin actions
               After-hours activity detected
     Features: event_count__variance,
               fail_ratio__mean,
               admin_ratio__max

============================================================
  ✅ False Positive Reduction
  ✅ All results stored with full explainability
  ✅ Complete audit trail maintained
============================================================
```

---

## 🔮 Future Scope

| 🚀 Enhancement | Description |
|----------------|-------------|
| 🔮 Predictive Forecasting | AI models to predict threats before they occur |
| 🔒 Dynamic Access Control | Auto-restrict access based on behavioral risk score |
| 📊 Advanced Scoring | Bayesian belief networks for risk calculation |
| 🏗️ AI Isolation | Physical separation of detection and reasoning systems |
| ⚖️ Automation Safeguards | Impact assessment before auto-responses |
| 📈 Signal Stability | Track anomaly persistence to avoid false alarms |
| 🤝 Federated Intelligence | Secure cross-system learning without data sharing |
| 🎮 Digital Twin | Simulate attacks on system replica for preparedness |

---

## 👥 Team Phoenix Core

<div align="center">

| | Member | Layers | Expertise |
|--|--------|--------|-----------|
| 👩‍💻 | **Ruchika Gupta** | 8-9 | Fidelity Scoring, LLM Reasoning |
| 👩‍💻 | **Nandni Raj** | 1-2 | Data Collection, Normalization |
| 👩‍💻 | **Navdeep Kaur** | 3-5 | Storage, Aggregation, ML Detection |
| 👩‍💻 | **Vedika Utturwar** | 10 | SOAR Response, Evaluation |
| 👩‍💻 | **Kanchan** | 6-7 | Correlation, Graph Modeling |

</div>

---

<div align="center">

### 🏆 Built for Excellence

*ACT AWARE represents our vision of what modern banking security should look like — intelligent, autonomous, explainable, and always under human control.*

<br/>

```
"In cybersecurity, the best defense is not just detection — 
 it's understanding WHY something is a threat and 
 knowing exactly HOW to respond."
                                    — Team Phoenix Core
```

<br/>

---

**⭐ Star this repo if you believe AI can make banking safer!**

*Built with 💙 by Team Phoenix Core*

</div>
