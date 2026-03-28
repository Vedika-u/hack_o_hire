# run.py
"""
Start the ACT AWARE Control Plane server.
Run this file to start the API.
"""

import uvicorn

if __name__ == "__main__":
    uvicorn.run(
        "control_plane.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info",
    )