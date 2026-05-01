"""
FastAPI Server — Bridge between Chrome Extension and the Agent Mesh
====================================================================
Runs locally on http://localhost:8765
The extension connects here via fetch() calls.

Start with:  python server.py
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import uuid
from typing import Any, Dict, List, Optional

import uvicorn
from dotenv import load_dotenv
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from pydantic import BaseModel

load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Adversarial Cognitive Mesh API", version="1.0.0")

# Allow extension to call this server
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── In-memory state ────────────────────────────────────────────────────────────

class ServerState:
    def __init__(self):
        self.status = "idle"          # idle | scanning | complete | error
        self.current_url = ""
        self.pipeline: Dict[str, Any] = {
            "sentinel":  {"status": "idle", "message": "—"},
            "triage":    {"status": "idle", "message": "—"},
            "red":       {"status": "idle", "message": "—"},
            "blue":      {"status": "idle", "message": "—"},
            "deception": {"status": "idle", "message": "—"},
            "memory":    {"status": "idle", "message": "—"},
        }
        self.stats = {"incidents": 0, "blocked": 0, "warnings": 0, "dna_learned": 0}
        self.threats: List[Dict] = []
        self.activity: List[Dict] = []
        self.last_report: Optional[Dict] = None
        self.ws_clients: List[WebSocket] = []

    def add_activity(self, msg: str, level: str = "info"):
        import datetime
        self.activity.insert(0, {
            "time": datetime.datetime.now().strftime("%H:%M:%S"),
            "message": msg,
            "level": level,
        })
        self.activity = self.activity[:50]  # keep last 50

    async def broadcast(self, data: dict):
        dead = []
        for ws in self.ws_clients:
            try:
                await ws.send_json(data)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.ws_clients.remove(ws)

state = ServerState()


# ── Request models ─────────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    url: str
    scenario: Optional[str] = None   # ransomware | apt_intrusion | cryptominer


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.get("/")
def root():
    return {
        "name": "Adversarial Cognitive Mesh",
        "status": "running",
        "version": "1.0.0",
        "message": "Server is online. Install the Chrome extension to use the dashboard.",
        "endpoints": ["/api/ping", "/api/status", "/api/threats", "/api/scan", "/ws"]
    }

@app.get("/api/ping")
def ping():
    return {"status": "ok", "version": "1.0.0"}


@app.get("/api/status")
def get_status():
    return {
        "status": state.status,
        "url": state.current_url,
        "pipeline": state.pipeline,
        "stats": state.stats,
        "activity": state.activity[:15],
    }


@app.get("/api/threats")
def get_threats():
    return {"threats": state.threats}


@app.get("/api/report")
def get_report():
    return {"report": state.last_report}


@app.get("/api/report/pdf")
def download_pdf():
    """Generate and return the last incident report as a PDF."""
    if not state.last_report:
        return {"error": "No report available. Run a scan first."}
    from reports.pdf_generator import generate_pdf
    pdf_bytes = generate_pdf(state.last_report)
    filename = f"acm_report_{state.last_report.get('id','report')[:8]}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.post("/api/scan")
async def start_scan(req: ScanRequest):
    if state.status == "scanning":
        return {"error": "Scan already in progress"}

    state.current_url = req.url
    state.status = "scanning"
    state.add_activity(f"New scan: {req.url}", "info")

    # Reset pipeline
    for agent in state.pipeline:
        state.pipeline[agent] = {"status": "idle", "message": "—"}

    asyncio.create_task(_run_scan(req.url, req.scenario))
    return {"ok": True, "message": "Scan started"}


@app.post("/api/reset")
async def reset():
    state.status = "idle"
    state.current_url = ""
    for agent in state.pipeline:
        state.pipeline[agent] = {"status": "idle", "message": "—"}
    await state.broadcast({"type": "reset"})
    return {"ok": True}


@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    state.ws_clients.append(ws)
    # Send current state immediately
    await ws.send_json({"type": "state", "data": {
        "status": state.status,
        "pipeline": state.pipeline,
        "stats": state.stats,
        "activity": state.activity[:15],
    }})
    try:
        while True:
            await ws.receive_text()   # keep alive
    except WebSocketDisconnect:
        if ws in state.ws_clients:
            state.ws_clients.remove(ws)


# ── Scan pipeline ──────────────────────────────────────────────────────────────

async def _update_agent(agent: str, status: str, message: str):
    state.pipeline[agent] = {"status": status, "message": message}
    state.add_activity(f"[{agent.upper()}] {message}", "info" if status != "error" else "error")
    await state.broadcast({
        "type": "agent_update",
        "agent": agent,
        "status": status,
        "message": message,
    })


async def _run_scan(url: str, scenario: Optional[str]):
    """Run the full 6-layer agent pipeline."""
    try:
        from agents.sentinel_mesh import SentinelMesh, DEMO_SCENARIOS
        from core.event_bus import Topic, event_bus
        from core.orchestrator import Orchestrator

        import random
        chosen = scenario or random.choice(list(DEMO_SCENARIOS.keys()))

        # ── Sentinel ──────────────────────────────────────────────────────────
        await _update_agent("sentinel", "thinking", f"Scanning {url}…")
        await asyncio.sleep(1.5)
        await _update_agent("sentinel", "complete", f"5 threat events detected ({chosen})")
        state.stats["incidents"] += 1

        # Patch orchestrator to broadcast to WS
        orch = Orchestrator()
        orch.set_scenario(chosen)

        # Track pipeline stages via event bus
        original_status = orch._status.__func__ if hasattr(orch._status, '__func__') else None

        async def ws_status(agent_role, status, message, incident_id):
            role_map = {
                "triage": "triage", "red": "red", "blue": "blue",
                "deception": "deception", "memory": "memory",
            }
            agent_key = role_map.get(agent_role.value, agent_role.value)
            st = "thinking" if status == "thinking" else "complete"
            await _update_agent(agent_key, st, message)

        orch._status = ws_status

        # Wire report callback
        result = {}
        def on_done(report):
            result["report"] = report

        orch.on_report_complete = on_done

        # Subscribe to events
        event_bus.subscribe(Topic.THREAT_EVENT, orch.on_threat_event)

        # Start event bus
        bus_task = asyncio.create_task(event_bus.start())

        # Inject demo events
        sentinel = SentinelMesh(demo_mode=True, scenario=chosen)
        await sentinel.start()

        # Wait for completion (max 120s)
        for _ in range(600):  # 5 minutes max pour Llama
            await asyncio.sleep(0.5)
            if "report" in result:
                break

        bus_task.cancel()
        try:
            await bus_task
        except asyncio.CancelledError:
            pass

        # Process report
        if "report" in result:
            report = result["report"]
            _save_report(report, url, chosen)
            state.status = "complete"
            state.stats["blocked"] += len(report.blue_response.countermeasures) if report.blue_response else 0
            state.stats["warnings"] += len(report.deception_plan.assets) if report.deception_plan else 0
            state.stats["dna_learned"] += 1
            state.add_activity(f"Scan complete — {chosen} resolved", "success")
            await state.broadcast({"type": "complete", "stats": state.stats})
        else:
            state.status = "error"
            state.add_activity("Scan timed out", "error")
            await state.broadcast({"type": "error", "message": "Timeout"})

    except Exception as exc:
        logger.exception("Scan failed: %s", exc)
        state.status = "error"
        state.add_activity(f"Error: {exc}", "error")
        await state.broadcast({"type": "error", "message": str(exc)})


def _save_report(report, url: str, scenario: str):
    """Convert IncidentReport to JSON-serializable dict and store."""
    import datetime

    def blue_actions():
        if not report.blue_response:
            return []
        return [
            {"type": a.action_type, "target": a.target, "priority": a.priority}
            for a in report.blue_response.countermeasures[:5]
        ]

    def deception_assets():
        if not report.deception_plan:
            return []
        return [
            {"type": a.asset_type, "location": a.deployment_location, "purpose": a.lure_description}
            for a in report.deception_plan.assets[:5]
        ]

    threat = {
        "id": report.incident.id,
        "url": url,
        "scenario": scenario,
        "severity": report.incident.severity,
        "timestamp": datetime.datetime.now().isoformat(),
        "summary": report.narrative.summary if report.narrative else "",
        "kill_chain_stage": report.narrative.kill_chain_stage if report.narrative else "",
        "countermeasures": blue_actions(),
        "deception_assets": deception_assets(),
        "duration": round(report.duration_seconds, 1) if report.duration_seconds else 0,
        "dna": report.threat_dna.fingerprint_hash if report.threat_dna else "",
    }
    state.threats.insert(0, threat)
    state.threats = state.threats[:20]
    state.last_report = threat


# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n  Adversarial Cognitive Mesh — API Server")
    print("  Running on http://localhost:8765")
    print("  Install the Chrome extension and click the icon\n")
    uvicorn.run(app, host="127.0.0.1", port=8765, log_level="warning")
