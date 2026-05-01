"""
Layer 4 — Blue Agent (Countermeasure Composer)
===============================================
Reads BOTH the ThreatNarrative (what is confirmed) AND the Red Agent's
AttackSimulation (what will happen next) to generate countermeasures that
block the attack's FUTURE steps, not just react to the current state.

This is the key advantage of the Red→Blue handoff:
  - Classical SOC: responds to alert #1, then alert #2, always one step behind.
  - This mesh: responds to what the attacker will do in steps 2–7 before they do it.

Output is a prioritised action plan with reversibility metadata so
operators can execute quickly with confidence.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List

from agents.base_agent import BaseAgent
from core.models import (
    AgentRole, AttackSimulation, BlueAgentResponse,
    CountermeasureAction, ThreatNarrative,
)

logger = logging.getLogger(__name__)

# ── Output schema ─────────────────────────────────────────────────────────────

BLUE_TOOL = {
    "name": "compose_countermeasures",
    "description": (
        "Produce a prioritised defensive response plan that blocks both the current "
        "attack activity and the attacker's predicted future steps."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "overall_strategy": {
                "type": "string",
                "description": (
                    "1-2 sentence strategic framing: are we containing, eradicating, "
                    "or buying time for deception/intelligence gathering?"
                ),
            },
            "countermeasures": {
                "type": "array",
                "description": "Ordered list of concrete defensive actions, priority 1 = most urgent.",
                "items": {
                    "type": "object",
                    "properties": {
                        "action_type": {
                            "type": "string",
                            "enum": [
                                "block_ip", "kill_process", "isolate_host",
                                "revoke_credentials", "patch_vulnerability",
                                "enable_mfa", "quarantine_file",
                                "firewall_rule", "alert_soc", "disable_account",
                            ],
                        },
                        "target":                    {"type": "string"},
                        "description":               {"type": "string"},
                        "priority":                  {"type": "integer", "minimum": 1, "maximum": 10},
                        "impact":                    {"type": "string"},
                        "reversible":                {"type": "boolean"},
                        "mitre_technique_blocked":   {"type": "string"},
                    },
                    "required": [
                        "action_type", "target", "description", "priority",
                        "impact", "reversible",
                    ],
                },
            },
            "expected_outcome": {
                "type": "string",
                "description": "What state are we in after these countermeasures are applied?",
            },
            "residual_risk": {
                "type": "string",
                "description": "What risk remains even after all countermeasures are applied?",
            },
        },
        "required": ["overall_strategy", "countermeasures", "expected_outcome", "residual_risk"],
    },
}

SYSTEM_PROMPT = """You are the Blue Agent of an advanced cybersecurity mesh.

Your task: given a confirmed threat narrative AND a Red Agent simulation of the attack's
future steps, compose a prioritised countermeasure plan.

Rules:
- Address BOTH the current confirmed activity AND the predicted future steps.
- Each countermeasure must be specific and immediately actionable (no vague recommendations).
- Prioritise by urgency: what stops the most damage fastest?
- Mark irreversible actions (isolating a host, revoking credentials) clearly.
- Be technically precise: name specific firewall rules, commands, or tools to use.
- Minimise blast radius — prefer surgical over scorched-earth.
- Do NOT recommend measures that would help the attacker (e.g., drawing attention).
- Tag each countermeasure with the MITRE technique it blocks.
"""


class BlueAgent(BaseAgent):
    role = AgentRole.BLUE

    def __init__(self) -> None:
        super().__init__("BlueAgent", SYSTEM_PROMPT)

    async def run(
        self,
        narrative: ThreatNarrative,
        simulation: AttackSimulation,
    ) -> BlueAgentResponse:
        await self._thinking(narrative.incident_id)

        confirmed_techniques = "\n".join(
            f"  [{t.id}] {t.name} — {t.tactic}" for t in narrative.mitre_techniques
        )

        predicted_steps = "\n".join(
            f"  Step {i+1} [{s.technique_id}] {s.technique_name} | Target: {s.target} | {s.time_offset}"
            for i, s in enumerate(simulation.kill_chain)
        )

        user_message = f"""Compose a countermeasure plan for the following active incident.

=== CONFIRMED THREAT (from Triage) ===
  Incident ID     : {narrative.incident_id}
  Kill Chain Stage: {narrative.kill_chain_stage}
  Attacker Intent : {narrative.attacker_intent}
  Severity        : {narrative.severity.upper()}

Confirmed MITRE techniques:
{confirmed_techniques}

Key IOCs:
{chr(10).join(f'  • {ioc}' for ioc in narrative.iocs)}

=== RED AGENT SIMULATION (predicted attack progression) ===
  Threat Actor  : {simulation.threat_actor_profile}
  Est. Completion: {simulation.time_to_completion}
  Est. Impact    : {simulation.estimated_impact}

Predicted kill chain (what the attacker will do next):
{predicted_steps}

Predicted targets:
{chr(10).join(f'  • {t}' for t in simulation.predicted_targets)}

Vulnerabilities being exploited:
{chr(10).join(f'  • {v}' for v in simulation.vulnerabilities_exploited)}

=== YOUR TASK ===
Generate a countermeasure plan that:
1. Stops the CURRENT attack activity immediately.
2. Pre-emptively blocks the attacker's NEXT 3-5 predicted steps.
3. Preserves forensic evidence where possible.
4. Minimises business disruption.

Order by priority (1 = act NOW)."""

        raw = await self._structured_call(
            user_message=user_message,
            output_tool=BLUE_TOOL,
        )

        actions = [
            CountermeasureAction(
                action_type=a["action_type"],
                target=a["target"],
                description=a["description"],
                priority=a["priority"],
                impact=a["impact"],
                reversible=a["reversible"],
                mitre_technique_blocked=a.get("mitre_technique_blocked"),
            )
            for a in raw.get("countermeasures", [])
        ]
        # Sort by priority ascending (1 = highest)
        actions.sort(key=lambda x: x.priority)

        response = BlueAgentResponse(
            incident_id=narrative.incident_id,
            overall_strategy=raw["overall_strategy"],
            countermeasures=actions,
            expected_outcome=raw["expected_outcome"],
            residual_risk=raw["residual_risk"],
        )

        await self._complete(
            f"{len(actions)} countermeasures ready | "
            f"Top action: [{actions[0].action_type}] {actions[0].target}" if actions else "No actions.",
            narrative.incident_id,
        )
        logger.info("[BLUE] %d countermeasures | Strategy: %s", len(actions), response.overall_strategy[:80])
        return response
