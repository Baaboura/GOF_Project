"""
Layer 5 — Deception Weaver
============================
Runs in parallel with the Blue Agent.

Instead of immediately blocking the attacker (which telegraphs detection),
the Deception Weaver deploys tailored decoys — honeypot files, fake
credentials, canary tokens, decoy servers — specifically designed around
what THIS attacker appears to want.

Benefits:
  1. Buys time for Blue Agent countermeasures to be applied.
  2. Lures the attacker into a controlled environment.
  3. Reveals the attacker's real target priorities.
  4. Gathers additional TTPs (tactics, techniques, procedures) for the
     Memory Crystallizer to learn from.

The deception layer is non-destructive and does not alert the attacker
to the fact that they've been detected.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List

from agents.base_agent import BaseAgent
from core.models import (
    AgentRole, AttackSimulation, DeceptionAsset, DeceptionPlan, ThreatNarrative,
)

logger = logging.getLogger(__name__)

# ── Output schema ─────────────────────────────────────────────────────────────

DECEPTION_TOOL = {
    "name": "design_deception_plan",
    "description": (
        "Design a tailored deception deployment plan. Every asset must be "
        "specifically chosen to attract THIS attacker based on their confirmed intent."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "strategy": {
                "type": "string",
                "description": (
                    "Overall deception strategy: what are we trying to achieve? "
                    "(delay, intelligence gathering, attribution, containment)"
                ),
            },
            "assets": {
                "type": "array",
                "description": "List of deception assets to deploy.",
                "items": {
                    "type": "object",
                    "properties": {
                        "asset_type": {
                            "type": "string",
                            "enum": [
                                "honeypot_file", "fake_credentials", "canary_token",
                                "decoy_server", "fake_database", "honey_share",
                                "fake_admin_account", "breadcrumb_trail",
                            ],
                        },
                        "lure_description": {
                            "type": "string",
                            "description": "What this asset pretends to be.",
                        },
                        "deployment_location": {
                            "type": "string",
                            "description": "Where to deploy this asset (path, network segment, etc.).",
                        },
                        "designed_to_attract": {
                            "type": "string",
                            "description": "Which specific attacker behavior or technique this attracts.",
                        },
                        "intelligence_value": {
                            "type": "string",
                            "description": "What we learn when the attacker interacts with this asset.",
                        },
                    },
                    "required": [
                        "asset_type", "lure_description", "deployment_location",
                        "designed_to_attract", "intelligence_value",
                    ],
                },
            },
            "expected_attacker_behavior": {
                "type": "string",
                "description": "How will the attacker interact with these decoys?",
            },
            "intelligence_goals": {
                "type": "array",
                "items": {"type": "string"},
                "description": "What specific intelligence do we want to gather from this deception?",
            },
            "time_window": {
                "type": "string",
                "description": "How long should these deception assets remain active?",
            },
        },
        "required": ["strategy", "assets", "expected_attacker_behavior", "intelligence_goals", "time_window"],
    },
}

SYSTEM_PROMPT = """You are the Deception Weaver of an advanced cybersecurity mesh.

Your role: design deception operations that mislead, delay, and gather intelligence on
an active attacker — without revealing that they have been detected.

Rules:
- Every deception asset must be highly specific to THIS attacker's profile and intent.
- Generic honeypots are not enough. A credential-harvesting attacker needs fake NTLM hashes.
  A ransomware operator needs fake high-value file shares. A miner needs a fake vulnerable server.
- Assets must be believable. An attacker who finds an obviously fake file will know they're burned.
- Prioritise intelligence gathering over containment — the Blue Agent handles containment.
- Canary tokens should be placed where the attacker is most likely to look next.
- Design breadcrumb trails that lead the attacker away from real assets and toward decoys.
- Never deploy deception that could cause harm to legitimate users.
"""


class DeceptionWeaver(BaseAgent):
    role = AgentRole.DECEPTION

    def __init__(self) -> None:
        super().__init__("DeceptionWeaver", SYSTEM_PROMPT)

    async def run(
        self,
        narrative: ThreatNarrative,
        simulation: AttackSimulation,
    ) -> DeceptionPlan:
        await self._thinking(narrative.incident_id)

        next_targets = "\n".join(f"  • {t}" for t in simulation.predicted_targets)
        kill_chain_preview = "\n".join(
            f"  [{s.technique_id}] {s.technique_name}: targeting {s.target} at {s.time_offset}"
            for s in simulation.kill_chain[:5]  # Focus on the nearest steps
        )

        user_message = f"""Design a deception operation for the following active threat.

=== ATTACKER PROFILE ===
  {simulation.threat_actor_profile}
  Intent: {narrative.attacker_intent}
  Current Stage: {narrative.kill_chain_stage}

=== PREDICTED NEXT MOVES (Red Agent Simulation) ===
{kill_chain_preview}

=== PREDICTED TARGETS ===
{next_targets}

=== KEY IOCS ===
{chr(10).join(f'  • {ioc}' for ioc in narrative.iocs)}

=== YOUR TASK ===
Design a deception plan with 4-6 specific assets that:
1. Lure the attacker toward decoys they WILL find believable for their goal.
2. Create false confidence — make them think they've found what they're looking for.
3. Gather intelligence about their tooling, targets, and exfiltration methods.
4. Buy time for the Blue Agent's countermeasures to take effect.

The attacker must NOT realise they've been detected."""

        raw = await self._structured_call(
            user_message=user_message,
            output_tool=DECEPTION_TOOL,
        )

        raw_assets = raw.get("assets", [])
        assets = []
        for a in raw_assets:
            # Claude sometimes returns strings instead of dicts — skip them
            if not isinstance(a, dict):
                continue
            try:
                assets.append(DeceptionAsset(
                    asset_type=a.get("asset_type", "honeypot_file"),
                    lure_description=a.get("lure_description", ""),
                    deployment_location=a.get("deployment_location", "unknown"),
                    designed_to_attract=a.get("designed_to_attract", ""),
                    intelligence_value=a.get("intelligence_value", ""),
                ))
            except Exception:
                continue

        plan = DeceptionPlan(
            incident_id=narrative.incident_id,
            strategy=raw["strategy"],
            assets=assets,
            expected_attacker_behavior=raw["expected_attacker_behavior"],
            intelligence_goals=self._to_list(raw.get("intelligence_goals", [])),
            time_window=raw["time_window"],
        )

        await self._complete(
            f"{len(assets)} deception assets designed | Window: {plan.time_window}",
            narrative.incident_id,
        )
        logger.info("[DECEPTION] %d assets | Strategy: %s", len(assets), plan.strategy[:80])
        return plan
