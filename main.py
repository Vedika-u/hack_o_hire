"""
main.py
ACT AWARE — Live SOC Dashboard
Layers 6-7: Detection, Correlation & Graph Attack Modeling
Team: Phoenix Core | Kanchan
Follows: config/schemas.py v1.1.0

✅ Automatic source selection:
  1. First try to connect to Nandni's Elasticsearch for REAL production logs
  2. If ES unavailable → automatically fall back to local banking log simulator
✅ Runs fully offline if needed
✅ 100% real time processing

Run:   python main.py
Open:  http://localhost:8001
"""

import sys
sys.path.insert(0, '.')

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import threading
import time
import random
import numpy as np
from datetime import datetime, timezone, timedelta
from uuid import uuid4
import os
import json
from dotenv import load_dotenv
from elasticsearch import Elasticsearch

from config.schemas import UniversalEvent, utc_now
from log_simulator import start_simulator, get_buffered_events
from detection import aggregate_events, run_ensemble_detection
from correlation import correlate_events, merge_related_incidents
from graph_attack import analyze_all_incidents, build_entity_graph

load_dotenv()

# ── Elasticsearch Connection ──────────────────
es_client = None
ES_INDEX = os.getenv("INDEX_NAME", "soc-logs")
USING_ELASTICSEARCH = False

try:
    ES_HOST = os.getenv("ES_HOST", "")
    ES_USER = os.getenv("ES_USERNAME", "elastic")
    ES_PASS = os.getenv("ES_PASSWORD", "")
    ES_CERT = os.getenv("ES_CA_CERT", "")

    if ES_HOST:
        if ES_CERT and os.path.exists(ES_CERT):
            es_client = Elasticsearch(ES_HOST, basic_auth=(ES_USER, ES_PASS),
                                      ca_certs=ES_CERT, verify_certs=True)
        else:
            es_client = Elasticsearch(ES_HOST, basic_auth=(ES_USER, ES_PASS),
                                      verify_certs=False)
        if es_client.ping():
            USING_ELASTICSEARCH = True
            print(f"[ES] ✅ Connected to Nandni's Elasticsearch at {ES_HOST}")
            print(f"[ES] ✅ Reading real time logs from `{ES_INDEX}` index")
        else:
            es_client = None
            USING_ELASTICSEARCH = False
            print(f"[ES] ❌ Ping failed, falling back to local log simulator")
except Exception as e:
    print(f"[ES] ❌ Connection failed ({e}), falling back to local log simulator")
    es_client = None
    USING_ELASTICSEARCH = False


# ── FastAPI App ───────────────────────────────
app = FastAPI(title="ACT AWARE Layer 6-7")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# ── Global State ──────────────────────────────
live_incidents = []
live_logs = []
graph_reports = []
pipeline_counter = 0
stats = {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "logs": 0,
         "lateral": 0, "max_blast": 0, "pipeline_runs": 0}


def fetch_events_from_elasticsearch(limit=200):
   def fetch_events_from_elasticsearch(limit=200):
    """Fetch real time logs - supports BOTH Nandni's format AND test data format"""
    if not es_client:
        return []
    try:
        resp = es_client.search(index=ES_INDEX, body={
            "size": limit,
            "sort": [{"@timestamp": {"order": "desc", "unmapped_type": "date"}}],
            "query": {"match_all": {}}
        })
        events = []
        for hit in resp["hits"]["hits"]:
            s = hit["_source"]
            try:
                # Handle timestamp - both formats
                ts = s.get("@timestamp") or s.get("timestamp", "")
                if isinstance(ts, str):
                    ts = ts.replace("Z", "+00:00")
                    ts = datetime.fromisoformat(ts)
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)

                # Handle user - both formats
                user_val = None
                if isinstance(s.get("user"), dict):
                    user_val = s["user"].get("name")
                elif isinstance(s.get("user"), str):
                    user_val = s.get("user")

                # Handle host - both formats
                host_val = None
                if isinstance(s.get("host"), dict):
                    host_val = s["host"].get("name")
                elif isinstance(s.get("host"), str):
                    host_val = s.get("host")

                # Handle source IP - both formats
                ip_val = None
                if isinstance(s.get("source"), dict):
                    ip_val = s["source"].get("ip")
                elif isinstance(s.get("ip"), str):
                    ip_val = s.get("ip")

                # Handle destination IP
                dest_ip = None
                if isinstance(s.get("destination"), dict):
                    dest_ip = s["destination"].get("ip")
                elif isinstance(s.get("destination_ip"), str):
                    dest_ip = s.get("destination_ip")

                # Handle event type - both formats
                event_type_val = "login"
                if isinstance(s.get("event"), dict):
                    raw_type = s["event"].get("type") or s["event"].get("category", "login")
                    raw_action = s["event"].get("action", "success")
                else:
                    raw_type = s.get("event_type", "login")
                    raw_action = s.get("action", "success")

                # Map to valid event types
                type_map = {
                    "login": "login", "logout": "login",
                    "authentication": "login",
                    "read": "file", "write": "file", "delete": "file",
                    "file": "file",
                    "network": "network", "connect": "network", "disconnect": "network",
                    "process": "process", "exec": "process",
                    "database": "database", "query": "database",
                    "escalate": "privilege", "privilege": "privilege",
                    "dns": "dns",
                    "api_call": "api_call"
                }
                event_type_val = type_map.get(raw_type, "login")

                # Map to valid actions
                action_map = {
                    "login": "success", "logout": "disconnect",
                    "read": "read", "write": "write", "delete": "delete",
                    "success": "success", "failure": "failure",
                    "escalate": "escalate", "connect": "connect",
                    "exec": "exec", "disconnect": "disconnect"
                }
                action_val = action_map.get(raw_action, "success")

                # Handle outcome as action override
                if isinstance(s.get("event"), dict):
                    outcome = s["event"].get("outcome", "")
                    if outcome == "failure":
                        action_val = "failure"
                    elif outcome == "success":
                        action_val = "success"

                # Handle severity - both formats
                severity_val = "low"
                if isinstance(s.get("event"), dict):
                    sev_num = s["event"].get("severity", 1)
                    if isinstance(sev_num, int):
                        if sev_num >= 4: severity_val = "critical"
                        elif sev_num >= 3: severity_val = "high"
                        elif sev_num >= 2: severity_val = "medium"
                        else: severity_val = "low"
                else:
                    severity_val = s.get("severity", "low")
                    if severity_val not in ("low", "medium", "high", "critical"):
                        severity_val = "low"

                events.append(UniversalEvent(
                    event_id=s.get("event_id", hit["_id"]),
                    timestamp=ts,
                    source="custom",
                    event_type=event_type_val,
                    action=action_val,
                    severity=severity_val,
                    user=user_val,
                    host=host_val,
                    ip=ip_val,
                    destination_ip=dest_ip,
                    pipeline_id=s.get("pipeline_id", str(uuid4()))
                ))
            except Exception as e:
                continue
        print(f"[ES] Fetched {len(events)} real logs from {ES_INDEX}")
        return events
    except Exception as e:
        global USING_ELASTICSEARCH
        USING_ELASTICSEARCH = False
        print(f"[ES] Fetch failed: {e} → falling back to simulator")
        return []

# ── Detection Pipeline ────────────────────────
def detection_pipeline():
    global live_incidents, live_logs, graph_reports, stats, pipeline_counter, USING_ELASTICSEARCH

    while True:
        try:
            pipeline_counter += 1
            pipeline_id = f"pipeline_{pipeline_counter}"

            # 🟢 Automatic source selection
            if USING_ELASTICSEARCH:
                events = fetch_events_from_elasticsearch(limit=200)
                # If ES returns empty, fall back to simulator for this cycle
                if not events:
                    events = get_buffered_events(limit=200)
            else:
                events = get_buffered_events(limit=200)

            if not events:
                time.sleep(8)
                continue

            # Update log feed
            for e in events[-40:]:
                live_logs.append({
                    "time": e.timestamp.strftime("%H:%M:%S"),
                    "entity": e.user or e.host or e.ip or "unknown",
                    "source": e.source,
                    "event": f"{e.event_type}.{e.action}",
                    "severity": e.severity,
                    "source_type": "elasticsearch" if USING_ELASTICSEARCH else "simulator",
                    "type": "attack" if e.severity in ("high", "critical") else "normal"
                })
            live_logs = live_logs[-150:]

            # Layer 6: Aggregate + Detect
            behaviors = aggregate_events(events, pipeline_id)
            detections = run_ensemble_detection(behaviors, pipeline_id)

            # Layer 6: Correlate
            incidents = correlate_events(detections, events)
            incidents = merge_related_incidents(incidents)

            # Layer 7: Graph Analysis
            enriched, reports = analyze_all_incidents(incidents, events)

            # Update dashboard state
            for inc, report in zip(enriched, reports):
                severity_str = inc.severity.upper()
                chain_events = [f"{t.action}" for t in inc.timeline[:6]]
                chain_str = " → ".join(chain_events) if chain_events else "N/A"

                sources = list(set(e.source for e in events
                                   if (e.user or e.host or e.ip) == inc.primary_entity))

                incident_display = {
                    "id": f"INC-{stats['total']:04d}",
                    "entity": inc.primary_entity,
                    "attack": inc.pattern.replace("_", " ").title(),
                    "stage": inc.attack_stage.replace("_", " ").title(),
                    "severity": severity_str,
                    "score": round(max(
                        (d.anomaly_score for d in detections if d.entity_id == inc.primary_entity),
                        default=0.5
                    ), 4),
                    "chain": chain_str,
                    "sources": ", ".join(sources) if sources else "multi-source",
                    "blast_radius": report["blast_radius"],
                    "lateral": report["lateral_movement"],
                    "hosts_reached": report["hosts_reached"],
                    "pivot": report.get("pivot_entity", "N/A"),
                    "duration": inc.duration_minutes,
                    "event_count": len(inc.source_event_ids),
                    "time": inc.created_at.strftime("%H:%M:%S"),
                    "graph_nodes": report["total_nodes"],
                    "graph_edges": report["total_edges"],
                    "log_source": "Elasticsearch (Real)" if USING_ELASTICSEARCH else "Local Simulator"
                }

                live_incidents.insert(0, incident_display)
                stats["total"] += 1
                stats[inc.severity] += 1

                if report["lateral_movement"]:
                    stats["lateral"] += 1
                if report["blast_radius"] > stats["max_blast"]:
                    stats["max_blast"] = report["blast_radius"]

            live_incidents = live_incidents[:60]
            stats["logs"] = len(live_logs)
            stats["pipeline_runs"] = pipeline_counter

            anomaly_count = sum(1 for d in detections if d.label == "anomaly")
            source_label = "📥 REAL ES LOGS" if USING_ELASTICSEARCH else "💾 SIMULATOR LOGS"
            print(f"[Pipeline #{pipeline_counter}] {source_label} | {len(events)} events → "
                  f"{len(behaviors)} entities → {anomaly_count} anomalies → "
                  f"{len(enriched)} incidents")

        except Exception as e:
            print(f"[Pipeline] Error: {e}")
            import traceback
            traceback.print_exc()

        time.sleep(8)


# ── Dashboard HTML ────────────────────────────
DASHBOARD = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>ACT AWARE — SOC Dashboard</title>
<style>
:root{--bg:#060a14;--surface:#0c1222;--card:#111827;--border:#1e3048;--text:#e2e8f0;--muted:#64748b;--blue:#3b82f6;--red:#ef4444;--amber:#f59e0b;--green:#22c55e;--purple:#a855f7;--cyan:#06b6d4;--pink:#ec4899}
*{margin:0;padding:0;box-sizing:border-box}
body{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif;min-height:100vh}

.topbar{background:var(--surface);border-bottom:1px solid var(--border);padding:12px 24px;display:flex;justify-content:space-between;align-items:center;position:sticky;top:0;z-index:100}
.brand{display:flex;align-items:center;gap:12px}
.shield{width:40px;height:40px;background:linear-gradient(135deg,#1d4ed8,#7c3aed);border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:20px;box-shadow:0 0 20px rgba(59,130,246,0.3)}
.brand-name{font-size:20px;font-weight:800;background:linear-gradient(90deg,#38bdf8,#818cf8,#c084fc);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.brand-sub{font-size:10px;color:var(--muted);letter-spacing:0.5px}
.topright{display:flex;align-items:center;gap:14px}
.live-pill{background:#052e16;border:1px solid #16a34a;border-radius:99px;padding:4px 12px;display:flex;align-items:center;gap:6px;font-size:11px;color:#4ade80;font-weight:700}
.dot{width:7px;height:7px;background:#4ade80;border-radius:50%;animation:blink 1.2s ease-in-out infinite}
@keyframes blink{0%,100%{opacity:1}50%{opacity:.2}}
.es-badge{font-size:10px;padding:3px 8px;border-radius:6px;font-weight:600}
.es-on{background:#064e3b;color:#22c55e;border:1px solid #16a34a}
.es-off{background:#082f49;color:#22d3ee;border:1px solid #0891b2}
.clock{font-size:11px;color:var(--muted);font-family:'Cascadia Code',monospace}

.stats{display:grid;grid-template-columns:repeat(8,1fr);gap:10px;padding:16px 24px}
.stat{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:14px;position:relative;overflow:hidden;transition:transform .15s}
.stat:hover{transform:translateY(-2px)}
.stat-glow{position:absolute;top:0;left:0;right:0;height:2px}
.stat-num{font-size:26px;font-weight:800;margin-bottom:2px}
.stat-label{font-size:9px;color:var(--muted);text-transform:uppercase;letter-spacing:.7px}

.main{display:grid;grid-template-columns:1fr 340px;gap:14px;padding:0 24px 24px}
.panel{background:var(--card);border:1px solid var(--border);border-radius:12px;overflow:hidden}
.panel-header{padding:12px 16px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center}
.panel-title{font-size:13px;font-weight:600;color:#93c5fd}

.table-wrap{overflow-x:auto;max-height:520px;overflow-y:auto}
table{width:100%;border-collapse:collapse;font-size:11px}
th{padding:8px 12px;text-align:left;font-size:9px;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:.5px;background:var(--surface);position:sticky;top:0;z-index:10}
td{padding:8px 12px;border-bottom:1px solid rgba(30,48,72,.5)}
tr:hover td{background:rgba(59,130,246,.04)}

.badge{padding:2px 8px;border-radius:99px;font-size:9px;font-weight:700;letter-spacing:.3px}
.CRITICAL{background:#4a0519;color:#fb7185;border:1px solid #881337}
.HIGH{background:#450a0a;color:#f87171;border:1px solid #7f1d1d}
.MEDIUM{background:#431407;color:#fb923c;border:1px solid #7c2d12}
.LOW{background:#052e16;color:#4ade80;border:1px solid #14532d}

.chain{font-family:'Cascadia Code',monospace;font-size:9px;color:#94a3b8;max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.score-bar{height:3px;border-radius:2px;margin-top:3px;transition:width .5s}

.side{display:flex;flex-direction:column;gap:14px}
.feed{height:220px;overflow-y:auto;padding:10px 14px}
.feed-item{display:flex;gap:8px;padding:4px 0;border-bottom:1px solid rgba(30,48,72,.3);animation:fadeIn .3s ease}
@keyframes fadeIn{from{opacity:0;transform:translateX(-6px)}to{opacity:1;transform:none}}
.feed-time{font-family:monospace;font-size:9px;color:var(--muted);white-space:nowrap;min-width:55px}
.feed-text{font-size:10px}
.feed-attack{color:#fca5a5}
.feed-normal{color:#86efac}
.feed-src{display:inline-block;background:var(--border);color:#93c5fd;font-size:8px;padding:1px 5px;border-radius:3px;margin-right:3px}

.graph-stats{padding:12px 16px}
.gs-row{display:flex;justify-content:space-between;align-items:center;padding:6px 0;border-bottom:1px solid rgba(30,48,72,.3)}
.gs-row:last-child{border:none}
.gs-label{font-size:11px;color:var(--muted)}
.gs-value{font-size:13px;font-weight:700}

.alert-banner{display:none;position:fixed;top:60px;right:20px;background:linear-gradient(135deg,#450a0a,#4a0519);border:1px solid #ef4444;border-radius:12px;padding:14px 18px;max-width:340px;z-index:999;animation:slideIn .3s ease;box-shadow:0 10px 40px rgba(239,68,68,0.3)}
@keyframes slideIn{from{transform:translateX(120%);opacity:0}to{transform:none;opacity:1}}
.alert-banner.show{display:block}
.alert-title{color:#f87171;font-weight:700;font-size:12px;margin-bottom:4px}
.alert-body{font-size:11px;color:#fca5a5}
.alert-close{position:absolute;top:8px;right:10px;cursor:pointer;color:var(--muted);font-size:14px}

::-webkit-scrollbar{width:3px;height:3px}
::-webkit-scrollbar-track{background:var(--surface)}
::-webkit-scrollbar-thumb{background:var(--border);border-radius:2px}
</style>
</head>
<body>

<div class="topbar">
  <div class="brand">
    <div class="shield">🛡</div>
    <div>
      <div class="brand-name">ACT AWARE</div>
      <div class="brand-sub">Layer 6–7: Detection, Correlation & Graph Attack Modeling · Phoenix Core · Kanchan</div>
    </div>
  </div>
  <div class="topright">
    <span class="es-badge" id="sourceBadge">Loading...</span>
    <div class="live-pill"><div class="dot"></div>LIVE</div>
    <div class="clock" id="clock">--:--:--</div>
  </div>
</div>

<div class="alert-banner" id="alertBanner">
  <span class="alert-close" onclick="this.parentElement.classList.remove('show')">&times;</span>
  <div class="alert-title">🚨 CRITICAL / HIGH SEVERITY</div>
  <div class="alert-body" id="alertBody">New incident detected</div>
</div>

<div class="stats">
  <div class="stat"><div class="stat-glow" style="background:#fb7185"></div><div class="stat-num" id="s-critical" style="color:#fb7185">0</div><div class="stat-label">Critical</div></div>
  <div class="stat"><div class="stat-glow" style="background:var(--red)"></div><div class="stat-num" id="s-high" style="color:var(--red)">0</div><div class="stat-label">High</div></div>
  <div class="stat"><div class="stat-glow" style="background:var(--amber)"></div><div class="stat-num" id="s-medium" style="color:var(--amber)">0</div><div class="stat-label">Medium</div></div>
  <div class="stat"><div class="stat-glow" style="background:var(--green)"></div><div class="stat-num" id="s-low" style="color:var(--green)">0</div><div class="stat-label">Low</div></div>
  <div class="stat"><div class="stat-glow" style="background:var(--blue)"></div><div class="stat-num" id="s-total" style="color:var(--blue)">0</div><div class="stat-label">Total</div></div>
  <div class="stat"><div class="stat-glow" style="background:var(--purple)"></div><div class="stat-num" id="s-logs" style="color:var(--purple)">0</div><div class="stat-label">Log Events</div></div>
  <div class="stat"><div class="stat-glow" style="background:var(--cyan)"></div><div class="stat-num" id="s-lateral" style="color:var(--cyan)">0</div><div class="stat-label">Lateral Moves</div></div>
  <div class="stat"><div class="stat-glow" style="background:var(--pink)"></div><div class="stat-num" id="s-blast" style="color:var(--pink)">0</div><div class="stat-label">Max Blast</div></div>
</div>

<div class="main">
  <div class="panel">
    <div class="panel-header">
      <span class="panel-title">🔍 Live Incident Detection — Layer 6 & 7</span>
      <span style="font-size:10px;color:var(--muted)" id="pipeInfo">PyOD Ensemble · Correlation · Graph Modeling</span>
    </div>
    <div class="table-wrap">
      <table>
        <thead><tr>
          <th>ID</th><th>Entity</th><th>Attack Pattern</th><th>Stage</th>
          <th>Severity</th><th>Score</th><th>Attack Chain</th>
          <th>Sources</th><th>Blast</th><th>Lateral</th><th>Log Source</th><th>Time</th>
        </tr></thead>
        <tbody id="incidentTable">
          <tr><td colspan="12" style="text-align:center;color:var(--muted);padding:50px">
            ⏳ Connecting to Elasticsearch... first results in ~10 seconds
          </td></tr>
        </tbody>
      </table>
    </div>
  </div>

  <div class="side">
    <div class="panel">
      <div class="panel-header">
        <span class="panel-title">📡 Live Log Feed</span>
        <span id="feedCount" style="font-size:10px;color:var(--muted)">0</span>
      </div>
      <div class="feed" id="logFeed">
        <div style="text-align:center;color:var(--muted);padding:20px;font-size:11px">Waiting for logs...</div>
      </div>
    </div>

    <div class="panel">
      <div class="panel-header">
        <span class="panel-title">🕸 Graph Analysis</span>
      </div>
      <div class="graph-stats" id="graphStats">
        <div class="gs-row"><span class="gs-label">Lateral Movements</span><span class="gs-value" style="color:var(--cyan)" id="g-lateral">0</span></div>
        <div class="gs-row"><span class="gs-label">Max Blast Radius</span><span class="gs-value" style="color:var(--pink)" id="g-blast">0</span></div>
        <div class="gs-row"><span class="gs-label">Pipeline Runs</span><span class="gs-value" style="color:var(--blue)" id="g-runs">0</span></div>
        <div class="gs-row"><span class="gs-label">Total Incidents</span><span class="gs-value" style="color:var(--amber)" id="g-total">0</span></div>
      </div>
    </div>

    <div class="panel">
      <div class="panel-header">
        <span class="panel-title">📊 Attack Distribution</span>
      </div>
      <div style="padding:10px 16px" id="distPanel">
        <div style="text-align:center;color:var(--muted);padding:15px;font-size:11px">Collecting...</div>
      </div>
    </div>
  </div>
</div>

<script>
function tick(){document.getElementById('clock').textContent=new Date().toLocaleTimeString('en-GB');}
tick();setInterval(tick,1000);
let lastAlertId=null;

async function update(){
  try{
    const r=await fetch('/api/state');
    const d=await r.json();
    const s=d.stats;

    document.getElementById('s-critical').textContent=s.critical;
    document.getElementById('s-high').textContent=s.high;
    document.getElementById('s-medium').textContent=s.medium;
    document.getElementById('s-low').textContent=s.low;
    document.getElementById('s-total').textContent=s.total;
    document.getElementById('s-logs').textContent=s.logs;
    document.getElementById('s-lateral').textContent=s.lateral;
    document.getElementById('s-blast').textContent=s.max_blast;

    document.getElementById('g-lateral').textContent=s.lateral;
    document.getElementById('g-blast').textContent=s.max_blast;
    document.getElementById('g-runs').textContent=s.pipeline_runs;
    document.getElementById('g-total').textContent=s.total;

    const sb = document.getElementById('sourceBadge');
    if(d.es_connected){
        sb.className='es-badge es-on';
        sb.textContent = '✅ ES Connected - Real Logs';
    } else {
        sb.className='es-badge es-off';
        sb.textContent = '🔌 Simulator - Fallback Mode';
    }

    document.getElementById('pipeInfo').textContent=
      'Pipeline #'+s.pipeline_runs+' · '+s.total+' incidents · PyOD + Correlation + Graph';

    if(d.incidents.length>0){
      document.getElementById('incidentTable').innerHTML=d.incidents.slice(0,25).map(i=>{
        const sc=i.severity==='CRITICAL'?'#fb7185':i.severity==='HIGH'?'#f87171':i.severity==='MEDIUM'?'#fb923c':'#4ade80';
        return '<tr>'+
          '<td style="font-family:monospace;font-size:9px;color:var(--muted)">'+i.id+'</td>'+
          '<td style="font-size:10px;font-family:monospace;color:#93c5fd">'+i.entity+'</td>'+
          '<td style="color:'+sc+';font-weight:600;font-size:10px">'+i.attack+'</td>'+
          '<td style="font-size:9px;color:var(--muted)">'+i.stage+'</td>'+
          '<td><span class="badge '+i.severity+'">'+i.severity+'</span></td>'+
          '<td><div style="font-weight:700;font-size:11px">'+i.score+'</div><div class="score-bar" style="width:'+Math.round(i.score*100)+'%;background:'+sc+'"></div></td>'+
          '<td class="chain" title="'+i.chain+'">'+i.chain+'</td>'+
          '<td style="font-size:9px;color:var(--muted)">'+i.sources+'</td>'+
          '<td style="text-align:center;font-weight:700;color:var(--pink)">'+i.blast_radius+'</td>'+
          '<td style="text-align:center">'+(i.lateral?'<span style="color:var(--cyan);font-weight:700">YES</span>':'<span style="color:var(--muted)">—</span>')+'</td>'+
          '<td style="font-size:8px;color:'+(i.log_source.includes('Elastic') ? '#22c55e' : '#f59e0b')+'">'+i.log_source+'</td>'+
          '<td style="font-family:monospace;font-size:9px;color:var(--muted)">'+i.time+'</td>'+
        '</tr>';}).join('');

      const alert=d.incidents.find(i=>i.severity==='CRITICAL'||i.severity==='HIGH');
      if(alert&&alert.id!==lastAlertId){
        lastAlertId=alert.id;
        document.getElementById('alertBody').textContent=
          alert.attack+' detected on '+alert.entity+' — Score: '+alert.score+
          ' — Blast: '+alert.blast_radius+(alert.lateral?' — Lateral Movement!':'');
        const b=document.getElementById('alertBanner');
        b.classList.add('show');
        setTimeout(()=>b.classList.remove('show'),7000);
      }

      let counts={};
      d.incidents.forEach(i=>{counts[i.attack]=(counts[i.attack]||0)+1;});
      const maxC=Math.max(...Object.values(counts),1);
      const colors={'Brute Force':'#ef4444','Lateral Movement':'#06b6d4','Data Exfiltration':'#a855f7',
                    'Ransomware':'#f59e0b','Insider Threat':'#ec4899','Privilege Escalation':'#22c55e','Unknown':'#64748b'};
      document.getElementById('distPanel').innerHTML=Object.entries(counts)
        .sort((a,b)=>b[1]-a[1]).map(([n,c])=>
        '<div style="display:flex;align-items:center;gap:8px;padding:5px 0;border-bottom:1px solid rgba(30,48,72,.3)">'+
          '<div style="width:8px;height:8px;border-radius:50%;background:'+(colors[n]||'#64748b')+'"></div>'+
          '<div style="flex:1;font-size:11px">'+n+'</div>'+
          '<div style="width:70px;height:3px;background:var(--border);border-radius:2px;overflow:hidden">'+
            '<div style="height:100%;width:'+(c/maxC*100)+'%;background:'+(colors[n]||'#64748b')+';border-radius:2px"></div>'+
          '</div>'+
          '<div style="min-width:20px;text-align:right;font-size:11px;font-weight:700;color:'+(colors[n]||'#64748b')+'">'+c+'</div>'+
        '</div>').join('');
    }

    document.getElementById('feedCount').textContent=d.logs.length+' events';
    if(d.logs.length>0){
      document.getElementById('logFeed').innerHTML=d.logs.slice(-35).reverse().map(l=>
        '<div class="feed-item">'+
          '<div class="feed-time">'+l.time+'</div>'+
          '<div class="feed-text '+(l.type==='attack'?'feed-attack':'feed-normal')+'">'+
            '<span class="feed-src">'+l.source+'</span>'+l.entity+' → '+l.event+
          '</div>'+
        '</div>').join('');
    }
  }catch(e){console.error(e);}
}
update();setInterval(update,5000);
</script>
</body>
</html>"""


# ── API Routes ────────────────────────────────
@app.get("/", response_class=HTMLResponse)
def dashboard():
    return DASHBOARD


@app.get("/api/state")
def api_state():
    return JSONResponse({
        "incidents": live_incidents,
        "logs": live_logs[-50:],
        "stats": stats,
        "es_connected": USING_ELASTICSEARCH
    })


@app.get("/api/incidents")
def api_incidents():
    return JSONResponse(live_incidents)


@app.get("/api/logs")
def api_logs():
    return JSONResponse(live_logs[-80:])


@app.get("/health")
def health():
    return {
        "status": "running",
        "team": "Phoenix Core",
        "member": "Kanchan",
        "layer": "6-7: Detection, Correlation & Graph Attack Modeling",
        "schema_version": "1.1.0",
        "elasticsearch_connected": USING_ELASTICSEARCH,
        "pipeline_runs": pipeline_counter,
        "total_incidents": stats["total"]
    }


# ── Startup ───────────────────────────────────
@app.on_event("startup")
def startup():
    # Start simulator as fallback even if ES is connected
    start_simulator(interval_seconds=8)

    # Start detection pipeline
    t = threading.Thread(target=detection_pipeline, daemon=True)
    t.start()

    source_status = "✅ Connected to Elasticsearch (Real Logs)" if USING_ELASTICSEARCH else "⚠️ ES Unavailable → Using Local Simulator"
    print("\n" + "=" * 70)
    print("  ╔═══════════════════════════════════════════════════════════╗")
    print("  ║          🛡 ACT AWARE - SOC DASHBOARD RUNNING            ║")
    print("  ╚═══════════════════════════════════════════════════════════╝")
    print(f"  Team:           Phoenix Core")
    print(f"  Member:         Kanchan")
    print(f"  Layer:          6-7 Detection & Graph Modeling")
    print(f"  Schema:         v1.1.0")
    print(f"  📥 Log Source:   {source_status}")
    print(f"  Dashboard:      http://localhost:8001")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8002, log_level="info")

# ── Write Results Back to ES ──────────────────

def write_detection_to_es(detection):
    """Write Layer 6 detection result to ES"""
    if not es_client:
        return
    try:
        doc = {
            "@timestamp": detection.detected_at.isoformat(),
            "detection_id": detection.detection_id,
            "pipeline_id": detection.pipeline_id,
            "entity_id": detection.entity_id,
            "entity_type": detection.entity_type,
            "model": detection.model,
            "anomaly_score": detection.anomaly_score,
            "threshold_used": detection.threshold_used,
            "label": detection.label,
            "severity": detection.severity,
            "top_features": detection.top_contributing_features,
            "model_scores": detection.features_used,
            "layer": "6-detection",
            "team_member": "kanchan"
        }
        es_client.index(index="soc-detections", body=doc)
    except Exception as e:
        print(f"[ES Write] Detection failed: {e}")


def write_incident_to_es(incident, report):
    """Write Layer 6-7 correlated incident to ES"""
    if not es_client:
        return
    try:
        doc = {
            "@timestamp": incident.created_at.isoformat(),
            "incident_id": incident.incident_id,
            "pipeline_id": incident.pipeline_id,
            "primary_entity": incident.primary_entity,
            "entities": incident.entities,
            "pattern": incident.pattern,
            "attack_stage": incident.attack_stage,
            "severity": incident.severity,
            "duration_minutes": incident.duration_minutes,
            "event_count": len(incident.source_event_ids),
            "timeline_steps": len(incident.timeline),
            "attack_chain": " → ".join(
                [t.action for t in incident.timeline[:8]]
            ),
            "graph": {
                "blast_radius": report["blast_radius"],
                "lateral_movement": report["lateral_movement"],
                "hosts_reached": report["hosts_reached"],
                "pivot_entity": report.get("pivot_entity"),
                "total_nodes": report["total_nodes"],
                "total_edges": report["total_edges"]
            },
            "layer": "6-7-incident",
            "team_member": "kanchan"
        }
        es_client.index(index="soc-incidents", body=doc)
    except Exception as e:
        print(f"[ES Write] Incident failed: {e}")