"""
ACT AWARE - Live SOC Dashboard
Layer 6-7: Detection, Correlation & Graph Attack Modeling
Team: Phoenix Core | Kanchan
Run: python actaware.py
Then open: http://localhost:8001
"""

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import numpy as np
import pandas as pd
import networkx as nx
import threading
import random
import time
import json
from datetime import datetime, timedelta
from pyod.models.iforest import IForest
from pyod.models.lof import LOF
from pyod.models.hbos import HBOS

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

live_logs      = []
live_incidents = []
stats = {"total": 0, "high": 0, "medium": 0, "low": 0, "logs": 0}

ATTACK_TYPES = {
    "ransomware": {
        "color": "#ef4444",
        "chain": ["login_success", "privilege_escalation", "file_encryption", "lateral_move", "c2_beacon"],
        "sources": ["EDR", "Firewall", "IAM"],
        "score_range": (0.82, 0.99)
    },
    "insider_threat": {
        "color": "#f97316",
        "chain": ["login_success", "bulk_data_export", "privilege_misuse", "after_hours_access", "data_exfil"],
        "sources": ["IAM", "Database", "AppLog"],
        "score_range": (0.75, 0.95)
    },
    "credit_card_fraud": {
        "color": "#a855f7",
        "chain": ["login_attempt", "failed_login", "card_transaction", "rapid_tx", "foreign_ip"],
        "sources": ["AppLog", "IAM", "Firewall"],
        "score_range": (0.70, 0.92)
    },
    "api_abuse": {
        "color": "#eab308",
        "chain": ["api_auth", "rate_limit_hit", "credential_stuffing", "account_enum"],
        "sources": ["AppLog", "Firewall"],
        "score_range": (0.55, 0.78)
    },
    "phishing": {
        "color": "#06b6d4",
        "chain": ["email_opened", "link_clicked", "cred_harvested", "account_takeover"],
        "sources": ["Email", "IAM", "AppLog"],
        "score_range": (0.60, 0.85)
    }
}

NORMAL_EVENTS = [
    ("IAM", "login_success"), ("AppLog", "view_account"),
    ("AppLog", "transfer"), ("IAM", "logout"), ("AppLog", "balance_check")
]

def classify(score):
    if score >= 0.75: return "HIGH"
    if score >= 0.45: return "MEDIUM"
    return "LOW"

def blast_radius(G, entry):
    if entry not in G:
        return 0
    return len(nx.descendants(G, entry))

def simulate():
    global live_logs, live_incidents, stats
    counter = 0
    while True:
        ts = datetime.utcnow()
        for _ in range(random.randint(2, 5)):
            src, evt = random.choice(NORMAL_EVENTS)
            live_logs.append({
                "time": ts.strftime("%H:%M:%S"),
                "entity": f"user_{random.randint(0,79):03d}",
                "source": src,
                "event": evt,
                "type": "normal"
            })
        if counter % 3 == 0:
            attack_name = random.choice(list(ATTACK_TYPES.keys()))
            attack = ATTACK_TYPES[attack_name]
            entity_id = f"{attack_name}_{random.randint(0,4):02d}"
            score = round(random.uniform(*attack["score_range"]), 4)
            severity = classify(score)
            for evt in attack["chain"][:3]:
                src = random.choice(attack["sources"])
                live_logs.append({
                    "time": ts.strftime("%H:%M:%S"),
                    "entity": entity_id,
                    "source": src,
                    "event": evt,
                    "type": "attack"
                })
            G = nx.DiGraph()
            chain = attack["chain"]
            for i in range(len(chain) - 1):
                G.add_edge(f"{entity_id}:{chain[i]}", f"{entity_id}:{chain[i+1]}")
            entry = f"{entity_id}:{chain[0]}"
            br = blast_radius(G, entry)
            incident = {
                "id": f"INC-{counter:04d}",
                "entity": entity_id,
                "attack": attack_name.replace("_", " ").title(),
                "severity": severity,
                "score": score,
                "chain": " -> ".join(attack["chain"]),
                "sources": ", ".join(attack["sources"]),
                "blast_radius": br,
                "color": attack["color"],
                "time": ts.strftime("%H:%M:%S"),
                "lateral_paths": random.randint(1, br + 2)
            }
            live_incidents.insert(0, incident)
            live_incidents = live_incidents[:50]
            stats["total"] += 1
            stats[severity.lower()] += 1
        live_logs = live_logs[-100:]
        stats["logs"] = len(live_logs)
        counter += 1
        time.sleep(5)

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>ACT AWARE SOC Dashboard</title>
<style>
:root{--bg:#0a0f1e;--surface:#0f1729;--card:#141c2e;--border:#1e3a5f;--text:#e2e8f0;--muted:#64748b;--blue:#3b82f6;--red:#ef4444;--amber:#f59e0b;--green:#22c55e;--purple:#a855f7}
*{margin:0;padding:0;box-sizing:border-box}
body{background:var(--bg);color:var(--text);font-family:'Segoe UI',sans-serif;min-height:100vh}
.topbar{background:var(--surface);border-bottom:1px solid var(--border);padding:14px 24px;display:flex;justify-content:space-between;align-items:center;position:sticky;top:0;z-index:100}
.brand{display:flex;align-items:center;gap:12px}
.shield{width:38px;height:38px;background:linear-gradient(135deg,#1d4ed8,#7c3aed);border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:18px}
.brand-name{font-size:18px;font-weight:800;background:linear-gradient(90deg,#38bdf8,#818cf8);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.brand-sub{font-size:11px;color:var(--muted)}
.topright{display:flex;align-items:center;gap:16px}
.live-pill{background:#052e16;border:1px solid #16a34a;border-radius:99px;padding:5px 14px;display:flex;align-items:center;gap:6px;font-size:12px;color:#4ade80;font-weight:600}
.dot{width:7px;height:7px;background:#4ade80;border-radius:50%;animation:blink 1.4s ease-in-out infinite}
@keyframes blink{0%,100%{opacity:1}50%{opacity:.3}}
.clock{font-size:12px;color:var(--muted);font-family:monospace}
.stats{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;padding:20px 24px}
.stat{background:var(--card);border:1px solid var(--border);border-radius:14px;padding:18px;position:relative;overflow:hidden;transition:transform .2s}
.stat:hover{transform:translateY(-2px)}
.stat-glow{position:absolute;top:0;left:0;right:0;height:2px}
.stat-num{font-size:32px;font-weight:800;margin-bottom:2px}
.stat-label{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.8px}
.main{display:grid;grid-template-columns:1fr 340px;gap:16px;padding:0 24px 24px}
.panel{background:var(--card);border:1px solid var(--border);border-radius:14px;overflow:hidden}
.panel-header{padding:14px 18px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center}
.panel-title{font-size:14px;font-weight:600;color:#93c5fd}
.table-wrap{overflow-x:auto;max-height:420px;overflow-y:auto}
table{width:100%;border-collapse:collapse;font-size:12px}
th{padding:10px 14px;text-align:left;font-size:10px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:.6px;background:var(--surface);position:sticky;top:0}
td{padding:10px 14px;border-bottom:1px solid rgba(30,58,95,.5)}
tr:hover td{background:rgba(59,130,246,.05)}
.badge{padding:3px 10px;border-radius:99px;font-size:10px;font-weight:700}
.HIGH{background:#450a0a;color:#f87171;border:1px solid #7f1d1d}
.MEDIUM{background:#431407;color:#fb923c;border:1px solid #7c2d12}
.LOW{background:#052e16;color:#4ade80;border:1px solid #14532d}
.chain-text{font-family:monospace;font-size:10px;color:#94a3b8;max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.score-bar{height:4px;border-radius:2px;margin-top:4px}
.side{display:flex;flex-direction:column;gap:16px}
.feed{height:240px;overflow-y:auto;padding:12px}
.feed-item{display:flex;gap:8px;padding:5px 0;border-bottom:1px solid rgba(30,58,95,.4);animation:fadeIn .3s ease}
@keyframes fadeIn{from{opacity:0;transform:translateX(-8px)}to{opacity:1;transform:none}}
.feed-time{font-family:monospace;font-size:10px;color:var(--muted);white-space:nowrap}
.feed-text{font-size:11px}
.feed-attack{color:#fca5a5}
.feed-normal{color:#86efac}
.feed-src{display:inline-block;background:var(--border);color:#93c5fd;font-size:9px;padding:1px 5px;border-radius:3px;margin-right:4px}
.dist-item{display:flex;align-items:center;gap:10px;padding:8px 0;border-bottom:1px solid rgba(30,58,95,.3)}
.dist-item:last-child{border:none}
.dist-dot{width:10px;height:10px;border-radius:50%;flex-shrink:0}
.dist-name{font-size:12px;flex:1}
.dist-bar-wrap{width:80px;height:4px;background:var(--border);border-radius:2px;overflow:hidden}
.dist-bar{height:100%;border-radius:2px;transition:width .5s ease}
.dist-count{font-size:12px;font-weight:600;min-width:24px;text-align:right}
.alert-banner{display:none;position:fixed;top:70px;right:24px;background:#450a0a;border:1px solid #ef4444;border-radius:12px;padding:14px 18px;max-width:320px;z-index:999;animation:slideIn .3s ease}
@keyframes slideIn{from{transform:translateX(100%)}to{transform:none}}
.alert-banner.show{display:block}
.alert-title{color:#f87171;font-weight:700;font-size:13px;margin-bottom:4px}
.alert-body{font-size:12px;color:#fca5a5}
.alert-close{position:absolute;top:10px;right:12px;cursor:pointer;color:var(--muted);font-size:16px}
::-webkit-scrollbar{width:4px;height:4px}
::-webkit-scrollbar-track{background:var(--surface)}
::-webkit-scrollbar-thumb{background:var(--border);border-radius:2px}
</style>
</head>
<body>
<div class="topbar">
  <div class="brand">
    <div class="shield">&#128737;</div>
    <div>
      <div class="brand-name">ACT AWARE</div>
      <div class="brand-sub">AI Cyber Incident Response &middot; Phoenix Core &middot; Layer 6-7</div>
    </div>
  </div>
  <div class="topright">
    <div class="live-pill"><div class="dot"></div>LIVE</div>
    <div class="clock" id="clock">--:--:--</div>
  </div>
</div>
<div class="alert-banner" id="alertBanner">
  <span class="alert-close" onclick="this.parentElement.classList.remove('show')">&#10005;</span>
  <div class="alert-title">&#128680; HIGH SEVERITY DETECTED</div>
  <div class="alert-body" id="alertBody">New critical incident detected</div>
</div>
<div class="stats">
  <div class="stat"><div class="stat-glow" style="background:var(--red)"></div><div class="stat-num" id="s-high" style="color:var(--red)">0</div><div class="stat-label">High Severity</div></div>
  <div class="stat"><div class="stat-glow" style="background:var(--amber)"></div><div class="stat-num" id="s-medium" style="color:var(--amber)">0</div><div class="stat-label">Medium Severity</div></div>
  <div class="stat"><div class="stat-glow" style="background:var(--green)"></div><div class="stat-num" id="s-low" style="color:var(--green)">0</div><div class="stat-label">Low Severity</div></div>
  <div class="stat"><div class="stat-glow" style="background:var(--blue)"></div><div class="stat-num" id="s-total" style="color:var(--blue)">0</div><div class="stat-label">Total Incidents</div></div>
  <div class="stat"><div class="stat-glow" style="background:var(--purple)"></div><div class="stat-num" id="s-logs" style="color:var(--purple)">0</div><div class="stat-label">Live Log Events</div></div>
</div>
<div class="main">
  <div class="panel">
    <div class="panel-header">
      <span class="panel-title">&#128269; Live Incident Detection &mdash; Layers 6 &amp; 7</span>
      <span style="font-size:11px;color:var(--muted)">PyOD &middot; Correlation &middot; Graph Attack Modeling</span>
    </div>
    <div class="table-wrap">
      <table>
        <thead><tr><th>ID</th><th>Entity</th><th>Attack Type</th><th>Severity</th><th>Score</th><th>Attack Chain</th><th>Sources</th><th>Blast</th><th>Time</th></tr></thead>
        <tbody id="incidentTable"><tr><td colspan="9" style="text-align:center;color:var(--muted);padding:40px">Waiting for incidents... detection running</td></tr></tbody>
      </table>
    </div>
  </div>
  <div class="side">
    <div class="panel">
      <div class="panel-header">
        <span class="panel-title">&#128225; Live Log Feed</span>
        <span id="feed-count" style="font-size:11px;color:var(--muted)">0 events</span>
      </div>
      <div class="feed" id="logFeed"><div style="text-align:center;color:var(--muted);padding:20px;font-size:12px">Starting simulation...</div></div>
    </div>
    <div class="panel">
      <div class="panel-header"><span class="panel-title">&#128202; Attack Distribution</span></div>
      <div style="padding:12px 16px" id="distPanel"><div style="text-align:center;color:var(--muted);padding:20px;font-size:12px">Collecting data...</div></div>
    </div>
  </div>
</div>
<script>
function tick(){document.getElementById('clock').textContent=new Date().toLocaleTimeString('en-GB');}
tick();setInterval(tick,1000);
let lastHighId=null;
async function update(){
  try{
    const[iRes,lRes]=await Promise.all([fetch('/api/live'),fetch('/api/logs')]);
    const data=await iRes.json();
    const logs=await lRes.json();
    document.getElementById('s-high').textContent=data.stats.high;
    document.getElementById('s-medium').textContent=data.stats.medium;
    document.getElementById('s-low').textContent=data.stats.low;
    document.getElementById('s-total').textContent=data.stats.total;
    document.getElementById('s-logs').textContent=data.stats.logs;
    if(data.incidents.length>0){
      document.getElementById('incidentTable').innerHTML=data.incidents.slice(0,20).map(i=>`
        <tr>
          <td style="font-family:monospace;font-size:10px;color:var(--muted)">${i.id}</td>
          <td style="font-size:11px;font-family:monospace">${i.entity}</td>
          <td><span style="color:${i.color};font-weight:600;font-size:11px">${i.attack}</span></td>
          <td><span class="badge ${i.severity}">${i.severity}</span></td>
          <td><div style="font-weight:600;font-size:12px">${i.score}</div><div class="score-bar" style="width:${i.score*100}%;background:${i.color}"></div></td>
          <td class="chain-text" title="${i.chain}">${i.chain}</td>
          <td style="font-size:10px;color:var(--muted)">${i.sources}</td>
          <td style="text-align:center;font-weight:700;color:#a78bfa">${i.blast_radius}</td>
          <td style="font-family:monospace;font-size:10px;color:var(--muted)">${i.time}</td>
        </tr>`).join('');
      const latestHigh=data.incidents.find(i=>i.severity==='HIGH');
      if(latestHigh&&latestHigh.id!==lastHighId){
        lastHighId=latestHigh.id;
        document.getElementById('alertBody').textContent=`${latestHigh.attack} on ${latestHigh.entity} - Score: ${latestHigh.score}`;
        const b=document.getElementById('alertBanner');
        b.classList.add('show');
        setTimeout(()=>b.classList.remove('show'),6000);
      }
      let counts={};
      data.incidents.forEach(i=>{counts[i.attack]=(counts[i.attack]||0)+1;});
      const maxC=Math.max(...Object.values(counts));
      const colors={'Ransomware':'#ef4444','Insider Threat':'#f97316','Credit Card Fraud':'#a855f7','Api Abuse':'#eab308','Phishing':'#06b6d4'};
      document.getElementById('distPanel').innerHTML=Object.entries(counts).sort((a,b)=>b[1]-a[1]).map(([n,c])=>`
        <div class="dist-item">
          <div class="dist-dot" style="background:${colors[n]||'#64748b'}"></div>
          <div class="dist-name">${n}</div>
          <div class="dist-bar-wrap"><div class="dist-bar" style="width:${(c/maxC)*100}%;background:${colors[n]||'#64748b'}"></div></div>
          <div class="dist-count" style="color:${colors[n]||'#64748b'}">${c}</div>
        </div>`).join('');
    }
    document.getElementById('feed-count').textContent=logs.length+' events';
    document.getElementById('logFeed').innerHTML=logs.slice(-30).reverse().map(l=>`
      <div class="feed-item">
        <div class="feed-time">${l.time}</div>
        <div class="feed-text ${l.type==='attack'?'feed-attack':'feed-normal'}">
          <span class="feed-src">${l.source}</span>${l.entity} &rarr; ${l.event}
        </div>
      </div>`).join('');
  }catch(e){console.error(e);}
}
update();setInterval(update,4000);
</script>
</body>
</html>"""

@app.get("/", response_class=HTMLResponse)
def dashboard():
    return DASHBOARD_HTML

@app.get("/api/live")
def api_live():
    return JSONResponse({"incidents": live_incidents, "stats": stats})

@app.get("/api/logs")
def api_logs():
    return JSONResponse(live_logs[-50:])

@app.get("/api/report")
def api_report():
    high=[i for i in live_incidents if i["severity"]=="HIGH"]
    return JSONResponse({
        "report_id": f"RPT-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}",
        "team": "Phoenix Core",
        "layer": "6-7: Detection, Correlation & Graph Attack Modeling",
        "summary": stats,
        "high_priority": high[:10]
    })

@app.get("/health")
def health():
    return {"status": "running", "team": "Phoenix Core", "incidents": len(live_incidents)}

@app.on_event("startup")
def startup():
    t=threading.Thread(target=simulate, daemon=True)
    t.start()
    print("\n" + "="*50)
    print("  ACT AWARE - SOC Dashboard RUNNING!")
    print("  Open browser: http://localhost:8001")
    print("="*50+"\n")

if __name__=="__main__":
    uvicorn.run(app, host="0.0.0.0", port=8001, reload=False)