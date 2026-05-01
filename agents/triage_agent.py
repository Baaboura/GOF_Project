"""
Layer 2 — Cognitive Triage Agent
==================================
Receives a ThreatIncident (aggregated sensor events), maps the indicators
to MITRE ATT&CK, and produces a ThreatNarrative: the strategic story of
what the attacker is doing, where they are in the kill chain, and what
they will likely do next.

Unlike a simple alert, the narrative gives downstream agents (Red, Blue,
Deception) the *intent* — not just the symptoms.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, List

from agents.base_agent import BaseAgent
from core.models import (
    AgentRole, MITRETechnique, SeverityLevel, ThreatIncident, ThreatNarrative,
)
from knowledge.mitre_attack import build_context_for_triage

logger = logging.getLogger(__name__)

# ── Output schema (used as a forced tool call) ───────────────────────────────

TRIAGE_TOOL = {
    "name": "produce_threat_narrative",
    "description": (
        "Produce a structured threat narrative from the observed security events. "
        "This is your sole output — fill every field with precise analysis."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "summary": {
                "type": "string",
                "description": "2-3 sentence executive summary of the threat.",
            },
            "attacker_intent": {
                "type": "string",
                "description": "What is the adversary ultimately trying to achieve?",
            },
            "kill_chain_stage": {
                "type": "string",
                "description": (
                    "Current Cyber Kill Chain stage: Reconnaissance | Weaponization | "
                    "Delivery | Exploitation | Installation | Command & Control | "
                    "Actions on Objectives"
                ),
            },
            "current_tactic": {
                "type": "string",
                "description": "The primary MITRE ATT&CK tactic active right now (e.g. 'Credential Access').",
            },
            "mitre_techniques": {
                "type": "array",
                "description": "MITRE ATT&CK techniques observed or inferred.",
                "items": {
                    "type": "object",
                    "properties": {
                        "id":          {"type": "string"},
                        "name":        {"type": "string"},
                        "tactic":      {"type": "string"},
                        "tactic_id":   {"type": "string"},
                        "description": {"type": "string"},
                        "confidence":  {"type": "number"},
                    },
                    "required": ["id", "name", "tactic", "tactic_id", "description", "confidence"],
                },
            },
            "predicted_next_steps": {
                "type": "array",
                "items": {"type": "string"},
                "description": "What will the attacker most likely do next (3-5 steps)?",
            },
            "severity": {
                "type": "string",
                "enum": ["low", "medium", "high", "critical"],
                "description": "Overall severity of the incident.",
            },
            "confidence": {
                "type": "number",
                "description": "Analyst confidence in this assessment, 0.0–1.0.",
            },
            "iocs": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Key Indicators of Compromise extracted from the events.",
            },
        },
        "required": [
            "summary", "attacker_intent", "kill_chain_stage", "current_tactic",
            "mitre_techniques", "predicted_next_steps", "severity", "confidence", "iocs",
        ],
    },
}

SYSTEM_PROMPT = """You are the Cognitive Triage Agent of an advanced cybersecurity mesh.

Your task: given a set of raw sensor events and matched MITRE ATT&CK indicators,
produce a precise, actionable ThreatNarrative.

Rules:
- Reason like a senior threat intelligence analyst with 15+ years experience.
- Map every cluster of indicators to the most specific MITRE technique possible.
- Identify the current kill chain stage, not just individual techniques.
- Predict next steps based on known attack patterns for this threat type.
- Be concise but thorough. No filler text.
- Severity = critical when ransomware encryption or active data exfiltration is confirmed.
"""


class TriageAgent(BaseAgent):
    role = AgentRole.TRIAGE

    def __init__(self) -> None:
        super().__init__("TriageAgent", SYSTEM_PROMPT)

    async def run(self, incident: ThreatIncident) -> ThreatNarrative:
        await self._thinking(incident.id)

        # Aggregate all indicators across events
        all_indicators: List[str] = []
        event_descriptions: List[str] = []
        for event in incident.events:
            all_indicators.extend(event.indicators)
            event_descriptions.append(
                f"[{event.timestamp.strftime('%H:%M:%S')}] "
                f"Sensor={event.sensor_type.upper()} "
                f"Confidence={event.confidence:.0%} — {event.description}"
            )

        mitre_context = build_context_for_triage(all_indicators)

        user_message = f"""Analyse the following security incident and produce the threat narrative.

INCIDENT ID: {incident.id}
SCENARIO: {incident.scenario_name}

=== SENSOR EVENTS ({len(incident.events)} total) ===
{chr(10).join(event_descriptions)}

=== INDICATORS OF COMPROMISE OBSERVED ===
{chr(10).join(f'• {ind}' for ind in set(all_indicators))}

=== MITRE ATT&CK CONTEXT ===
{mitre_context}

Produce a complete ThreatNarrative now."""

        raw = await self._structured_call(
            user_message=user_message,
            output_tool=TRIAGE_TOOL,
        )

        # Parse MITRE techniques from raw dict
        techniques = [
            MITRETechnique(
                id=t["id"],
                name=t["name"],
                tactic=t["tactic"],
                tactic_id=t["tactic_id"],
                description=t["description"],
                confidence=t.get("confidence", 0.8),
            )
            for t in raw.get("mitre_techniques", [])
        ]

        narrative = ThreatNarrative(
            incident_id=incident.id,
            summary=raw["summary"],
            attacker_intent=raw["attacker_intent"],
            kill_chain_stage=raw["kill_chain_stage"],
            current_tactic=raw["current_tactic"],
            mitre_techniques=techniques,
            predicted_next_steps=self._to_list(raw.get("predicted_next_steps", [])),
            severity=SeverityLevel(raw["severity"]),
            confidence=raw["confidence"],
            iocs=self._to_list(raw.get("iocs", [])),
        )

        await self._complete(
            f"Narrative ready — Stage: {narrative.kill_chain_stage} | "
            f"Severity: {narrative.severity.upper()} | "
            f"{len(techniques)} techniques mapped",
            incident.id,
        )
        logger.info("[TRIAGE] %s — %s", incident.id, narrative.summary[:100])
        return narrative
