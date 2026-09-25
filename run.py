# run.py
"""
Start the ACT AWARE Control Plane server.
Run this file to start the API: python run.py
"""

import uvicorn

if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("   ACT AWARE — BANKING CYBER INCIDENT RESPONSE PLATFORM    ")
    print("   Team: PHEONIX CORE | 100% Air-Gapped SOC Command Center ")
    print("=" * 60)
    print("Open in Browser:")
    print("  👉 Web SOC Dashboard : http://127.0.0.1:8000/")
    print("  👉 Interactive Docs  : http://127.0.0.1:8000/docs")
    print("=" * 60 + "\n")

    uvicorn.run(
        "control_plane.main:app",
        host="127.0.0.1",
        port=8000,
        reload=False,
        log_level="info",
    )