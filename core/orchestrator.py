"""
Main Orchestrator
==================
The conductor of the mesh. It:

  1. Buffers ThreatEvents from the Sentinel Mesh.
  2. Decides when enough evidence warrants forming a ThreatIncident.
  3. Calls the Triage Agent to produce a narrative.
  4. Checks the Memory library for known similar threats (fast path).
  5. Runs Red Agent + Deception Weaver in PARALLEL (both need the narrative).
  6. Runs Blue Agent after Red Agent completes (Blue reads the simulation).
  7. Calls the Memory Crystallizer to close the learning loop.
  8. Publishes status updates to the dashboard at every step.

The orchestrator is intentionally NOT an AI agent itself — it is a
deterministic workflow coordinator. The intelligence lives in the agents.
"""
from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime
from typing import Dict, List, Optional

from core.event_bus import Topic, event_bus
from core.models import (
    AgentStatus, AgentRole, IncidentReport, IncidentStatus,
    SeverityLevel, ThreatEvent, ThreatIncident,
)

logger = logging.getLogger(__name__)

# Thresholds
MIN_EVENTS_FOR_INCIDENT = 2      # How many events before we escalate
HIGH_CONFIDENCE_THRESHOLD = 0.75 # A single event above this triggers immediately
EVENT_CORRELATION_WINDOW = 10.0  # Seconds to wait for correlated events


class Orchestrator:

    def __init__(self) -> None:
        # Agents (lazy-initialised to avoid import-time API key check in tests)
        self._triage: Optional[TriageAgent] = None
        self._red: Optional[RedAgent] = None
        self._blue: Optional[BlueAgent] = None
        self._deception: Optional[DeceptionWeaver] = None
        self._memory: Optional[MemoryCrystallizer] = None

        # State
        self._pending_events: List[ThreatEvent] = []
        self._active_incidents: Dict[str, IncidentReport] = {}
        self._last_event_time: float = 0.0
        self._escalating: bool = False
        self._scenario_name: str = "unknown"
        self.on_report_complete = None   # Callback for dashboard

    def _agents(self):
        if self._triage is None:
            # Lazy imports — anthropic SDK only loaded when actually running
            from agents.triage_agent import TriageAgent
            from agents.red_agent import RedAgent
            from agents.blue_agent import BlueAgent
            from agents.deception_weaver import DeceptionWeaver
            from agents.memory_crystallizer import MemoryCrystallizer
            self._triage   = TriageAgent()
            self._red      = RedAgent()
            self._blue     = BlueAgent()
            self._deception = DeceptionWeaver()
            self._memory   = MemoryCrystallizer()

    # ── Event ingestion ───────────────────────────────────────────────────────

    def set_scenario(self, name: str) -> None:
        self._scenario_name = name

    async def on_threat_event(self, event: ThreatEvent) -> None:
        """Called by the event bus when the Sentinel Mesh emits a new event."""
        self._pending_events.append(event)
        self._last_event_time = time.monotonic()

        await event_bus.publish(Topic.DASHBOARD_UPDATE, {
            "type": "new_event",
            "event": event,
        })

        logger.info(
            "[ORC] Event #%d received: [%s] %s",
            len(self._pending_events), event.sensor_type.upper(), event.description[:80],
        )

        # If pipeline already running, just buffer the event
        if self._escalating:
            return

        # Immediate escalation for very high-confidence events
        if event.confidence >= HIGH_CONFIDENCE_THRESHOLD:
            await self._escalate()
            return

        # Accumulate if we have enough events
        if len(self._pending_events) >= MIN_EVENTS_FOR_INCIDENT:
            await self._escalate()

    # ── Escalation → full pipeline ────────────────────────────────────────────

    async def _escalate(self) -> None:
        self._escalating = True
        self._agents()

        events = list(self._pending_events)
        self._pending_events.clear()

        incident = ThreatIncident(
            events=events,
            status=IncidentStatus.DETECTING,
            scenario_name=self._scenario_name,
        )
        report = IncidentReport(incident=incident)
        self._active_incidents[incident.id] = report
        start_time = time.monotonic()

        await event_bus.publish(Topic.INCIDENT_CREATED, incident)
        await event_bus.publish(Topic.DASHBOARD_UPDATE, {
            "type": "incident_created",
            "incident": incident,
        })

        logger.info("[ORC] Incident %s opened with %d events.", incident.id, len(events))

        try:
            await self._run_pipeline(report, start_time)
        except Exception as exc:
            logger.exception("[ORC] Pipeline failed for %s: %s", incident.id, exc)
        finally:
            self._escalating = False

    async def _run_pipeline(self, report: IncidentReport, start_time: float) -> None:
        incident = report.incident

        # ── Stage 1: Check memory for fast-path ──────────────────────────────
        all_iocs = [ind for ev in incident.events for ind in ev.indicators]
        similar = self._memory.find_similar(all_iocs, [])
        if similar:
            logger.info(
                "[ORC] Memory hit! %d similar past threats found for %s",
                len(similar), incident.id,
            )
            await event_bus.publish(Topic.DASHBOARD_UPDATE, {
                "type": "memory_hit",
                "similar": [s.scenario_name for s in similar],
                "incident_id": incident.id,
            })

        # ── Stage 2: Triage ───────────────────────────────────────────────────
        incident.status = IncidentStatus.TRIAGING
        await self._status(AgentRole.TRIAGE, "thinking", "Analysing events and mapping to MITRE ATT&CK…", incident.id)

        narrative = await self._triage.run(incident)
        report.narrative = narrative
        incident.severity = narrative.severity

        await event_bus.publish(Topic.TRIAGE_COMPLETE, narrative)
        await event_bus.publish(Topic.DASHBOARD_UPDATE, {
            "type": "triage_complete",
            "narrative": narrative,
            "incident_id": incident.id,
        })

        # ── Stage 3: Red Agent + Deception Weaver in parallel ────────────────
        incident.status = IncidentStatus.SIMULATING
        await self._status(AgentRole.RED, "thinking", "Simulating attacker kill chain…", incident.id)
        await self._status(AgentRole.DECEPTION, "thinking", "Designing deception assets…", incident.id)

        simulation, deception_plan = await asyncio.gather(
            self._red.run(narrative),
            self._deception.run(narrative, _stub_simulation(narrative)),
        )
        report.simulation = simulation
        report.deception_plan = deception_plan

        await event_bus.publish(Topic.SIMULATION_COMPLETE, simulation)
        await event_bus.publish(Topic.DECEPTION_DEPLOYED, deception_plan)
        await event_bus.publish(Topic.DASHBOARD_UPDATE, {
            "type": "simulation_complete",
            "simulation": simulation,
            "deception": deception_plan,
            "incident_id": incident.id,
        })

        # ── Stage 4: Blue Agent ───────────────────────────────────────────────
        incident.status = IncidentStatus.RESPONDING
        await self._status(AgentRole.BLUE, "thinking", "Composing countermeasures from Red simulation…", incident.id)

        blue_response = await self._blue.run(narrative, simulation)
        report.blue_response = blue_response

        await event_bus.publish(Topic.COUNTERMEASURES_READY, blue_response)
        await event_bus.publish(Topic.DASHBOARD_UPDATE, {
            "type": "countermeasures_ready",
            "response": blue_response,
            "incident_id": incident.id,
        })

        # ── Stage 5: Memory Crystallizer ─────────────────────────────────────
        incident.status = IncidentStatus.LEARNING
        await self._status(AgentRole.MEMORY, "thinking", "Crystallizing Threat DNA…", incident.id)

        report.duration_seconds = time.monotonic() - start_time
        report.resolved_at = datetime.utcnow()

        threat_dna = await self._memory.run(report)
        report.threat_dna = threat_dna

        # ── Stage 6: Resolution ───────────────────────────────────────────────
        incident.status = IncidentStatus.RESOLVED
        await event_bus.publish(Topic.INCIDENT_RESOLVED, report)
        await event_bus.publish(Topic.DASHBOARD_UPDATE, {
            "type": "incident_resolved",
            "report": report,
            "incident_id": incident.id,
        })

        logger.info(
            "[ORC] Incident %s RESOLVED in %.1fs | Severity: %s | DNA: %s",
            incident.id,
            report.duration_seconds,
            incident.severity.upper(),
            threat_dna.fingerprint_hash,
        )

        if self.on_report_complete:
            self.on_report_complete(report)

    # ── Helpers ───────────────────────────────────────────────────────────────

    async def _status(
        self, agent: AgentRole, status: str, message: str, incident_id: str
    ) -> None:
        await event_bus.publish(
            Topic.AGENT_STATUS,
            AgentStatus(
                agent=agent,
                status=status,
                message=message,
                incident_id=incident_id,
            ),
        )

    def get_report(self, incident_id: str) -> Optional[IncidentReport]:
        return self._active_incidents.get(incident_id)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _stub_simulation(narrative):
    """
    Minimal stub passed to DeceptionWeaver when the real Red simulation
    hasn't completed yet (they run in parallel).
    The Deception Weaver only needs the narrative's first few predicted
    next steps, which are already available.
    """
    from core.models import AttackSimulation, KillChainStep
    return AttackSimulation(
        incident_id=narrative.incident_id,
        threat_actor_profile="Unknown — profiling in progress",
        kill_chain=[
            KillChainStep(
                stage=step,
                technique_id="T????",
                technique_name="Predicted",
                description=step,
                target="Unknown",
                time_offset="T+soon",
            )
            for step in narrative.predicted_next_steps[:4]
        ],
        predicted_targets=narrative.predicted_next_steps[:3],
        vulnerabilities_exploited=[],
        estimated_impact="Under assessment",
        time_to_completion="Unknown",
        confidence=0.5,
    )
