"""
Layer 3 — Red Agent (Adversarial Simulator)
=============================================
The most novel component in the mesh.

The Red Agent role-plays as the attacker. It takes the ThreatNarrative
produced by the Triage Agent and simulates the attack's FULL kill chain
inside an analytical sandbox — revealing what the malware WOULD do next
before it actually happens.

This gives the Blue Agent and Deception Weaver a head start:
they respond to the *predicted* end-state, not just the current symptoms.

Analogy: an immune system that builds antibodies while the virus is still
in transit, not after it has replicated.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List

from agents.base_agent import BaseAgent
from core.models import AgentRole, AttackSimulation, KillChainStep, ThreatNarrative

logger = logging.getLogger(__name__)

# ── Output schema ─────────────────────────────────────────────────────────────

RED_TOOL = {
    "name": "simulate_attack",
    "description": (
        "Simulate the attacker's complete kill chain and predict every step "
        "they will take from the current position to their final objective. "
        "Think like the attacker — be specific, technical, and realistic."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "threat_actor_profile": {
                "type": "string",
                "description": (
                    "Brief profile: sophistication level (nation-state, criminal group, "
                    "script kiddie), motivation, and likely toolset."
                ),
            },
            "kill_chain": {
                "type": "array",
                "description": "Complete predicted kill chain from current position to objective.",
                "items": {
                    "type": "object",
                    "properties": {
                        "stage":          {"type": "string"},
                        "technique_id":   {"type": "string"},
                        "technique_name": {"type": "string"},
                        "description":    {"type": "string"},
                        "target":         {"type": "string"},
                        "time_offset":    {"type": "string", "description": "e.g. T+5min, T+2h"},
                    },
                    "required": ["stage", "technique_id", "technique_name", "description", "target", "time_offset"],
                },
            },
            "predicted_targets": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Specific systems, files, or accounts the attacker will target.",
            },
            "vulnerabilities_exploited": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Specific weaknesses the attacker is leveraging.",
            },
            "estimated_impact": {
                "type": "string",
                "description": "Worst-case business impact if this attack completes uninterrupted.",
            },
            "time_to_completion": {
                "type": "string",
                "description": "Estimated time for the attacker to reach their final objective.",
            },
            "confidence": {
                "type": "number",
                "description": "Confidence in this simulation, 0.0–1.0.",
            },
        },
        "required": [
            "threat_actor_profile", "kill_chain", "predicted_targets",
            "vulnerabilities_exploited", "estimated_impact", "time_to_completion", "confidence",
        ],
    },
}

SYSTEM_PROMPT = """You are the Red Agent of an advanced cybersecurity mesh.

Your role: simulate adversarial behavior analytically — think and reason as the attacker.
You are in a controlled sandbox. Your output is used by defensive agents to pre-empt the attack.

Rules:
- Adopt the attacker's perspective completely. Reason about what THEY would do, not what defenders want.
- Use real attack tools, techniques, and sequences (Cobalt Strike, Mimikatz, BloodHound, etc.).
- Be technically precise: name specific techniques, tools, commands, and targets.
- The kill chain should start from the attacker's CURRENT confirmed position.
- Each step in the kill chain must be a concrete, executable action.
- Time offsets should be realistic for this type of actor.
- The simulation informs defenses — the more accurate, the better the protection.
"""


class RedAgent(BaseAgent):
    role = AgentRole.RED

    def __init__(self) -> None:
        super().__init__("RedAgent", SYSTEM_PROMPT)

    async def run(self, narrative: ThreatNarrative) -> AttackSimulation:
        await self._thinking(narrative.incident_id)

        techniques_context = "\n".join(
            f"  [{t.id}] {t.name} ({t.tactic}) — confidence {t.confidence:.0%}"
            for t in narrative.mitre_techniques
        )

        user_message = f"""You are simulating an adversary that has already been partially detected.

CURRENT THREAT NARRATIVE:
  Incident ID    : {narrative.incident_id}
  Kill Chain Stage: {narrative.kill_chain_stage}
  Active Tactic  : {narrative.current_tactic}
  Attacker Intent: {narrative.attacker_intent}
  Severity       : {narrative.severity.upper()}

CONFIRMED MITRE TECHNIQUES:
{techniques_context}

PREDICTED NEXT STEPS (from triage):
{chr(10).join(f'  {i+1}. {step}' for i, step in enumerate(narrative.predicted_next_steps))}

KEY IOCs:
{chr(10).join(f'  • {ioc}' for ioc in narrative.iocs)}

SIMULATION TASK:
You are NOW at the position described above. Simulate the COMPLETE remaining kill chain
from this point to the final objective. For each step, specify the technique, tool, target,
and realistic time offset.

Be the attacker. Think like them. Reveal everything they would do next."""

        raw = await self._structured_call(
            user_message=user_message,
            output_tool=RED_TOOL,
        )

        steps = [
            KillChainStep(
                stage=s["stage"],
                technique_id=s["technique_id"],
                technique_name=s["technique_name"],
                description=s["description"],
                target=s["target"],
                time_offset=s["time_offset"],
            )
            for s in raw.get("kill_chain", [])
        ]

        simulation = AttackSimulation(
            incident_id=narrative.incident_id,
            threat_actor_profile=raw["threat_actor_profile"],
            kill_chain=steps,
            predicted_targets=raw["predicted_targets"],
            vulnerabilities_exploited=raw["vulnerabilities_exploited"],
            estimated_impact=raw["estimated_impact"],
            time_to_completion=raw["time_to_completion"],
            confidence=raw["confidence"],
        )

        await self._complete(
            f"Simulation complete — {len(steps)} kill chain steps predicted | "
            f"Est. completion: {simulation.time_to_completion}",
            narrative.incident_id,
        )
        logger.info(
            "[RED] Simulated %d steps | Impact: %s",
            len(steps), simulation.estimated_impact[:80],
        )
        return simulation
