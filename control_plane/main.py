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

from control_plane.routes.auth_routes import router as auth_router
from control_plane.routes.incidents import router as incidents_router
from control_plane.routes.playbooks import router as playbooks_router
from control_plane.routes.metrics import router as metrics_router
from control_plane.routes.feedback import router as feedback_router
from control_plane.routes.audit_routes import router as audit_router

import logging

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


@app.get("/health", tags=["System"])
async def health_check():
    """Check if the system is running."""
    from datetime import datetime, timezone
    return {
        "status": "healthy",
        "layer": "9-10: Control, Response, Governance & Evaluation",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/", tags=["System"])
async def root():
    return {
        "system": "ACT AWARE",
        "layer": "Control & Governance Plane",
        "docs": "/docs",
        "health": "/health",
    }