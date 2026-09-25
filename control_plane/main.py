# control_plane/main.py
"""
FastAPI Control Plane — Main Application
Layer 9-10 of the ACT AWARE pipeline.

Endpoints:
  /api/v1/auth      - Login and get JWT token
  /api/v1/incidents - View incidents from Elasticsearch
  /api/v1/playbooks - Review, approve, reject, execute playbooks
  /api/v1/metrics   - System performance dashboard
  /api/v1/feedback  - Submit analyst feedback
  /api/v1/audit     - View immutable audit trail
  /docs             - Swagger UI (interactive testing)
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, HTMLResponse
import os
import logging

from control_plane.routes.auth_routes import router as auth_router
from control_plane.routes.incidents import router as incidents_router
from control_plane.routes.playbooks import router as playbooks_router
from control_plane.routes.metrics import router as metrics_router
from control_plane.routes.feedback import router as feedback_router
from control_plane.routes.audit_routes import router as audit_router
from control_plane.routes.disruption_routes import router as disruption_router

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s"
)

app = FastAPI(
    title="ACT AWARE — Control & Governance Plane",
    description="Layer 9-10: Human-in-the-loop approval, SOAR execution, metrics.",
    version="1.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register all routers
app.include_router(auth_router)
app.include_router(incidents_router)
app.include_router(playbooks_router)
app.include_router(metrics_router)
app.include_router(feedback_router)
app.include_router(audit_router)
app.include_router(disruption_router)

# Mount static folder
STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
INDEX_PATH = os.path.join(STATIC_DIR, "index.html")

if os.path.exists(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/health", tags=["System"])
async def health_check():
    """Check if the system is running."""
    from datetime import datetime, timezone
    return {
        "status": "healthy",
        "system": "ACT AWARE Banking SOC Platform",
        "layer": "9-10: Control, Response, Governance & Evaluation",
        "air_gapped_mode": True,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/", tags=["Dashboard"])
async def root():
    """Serves the Banking SOC Command Center Visual Dashboard."""
    if os.path.exists(INDEX_PATH):
        return FileResponse(INDEX_PATH)
    return {
        "system": "ACT AWARE",
        "layer": "Control & Governance Plane",
        "docs": "/docs",
        "health": "/health",
    }