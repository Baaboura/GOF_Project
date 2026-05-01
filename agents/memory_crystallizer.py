"""
Layer 6 — Memory Crystallizer
================================
Called after an incident is resolved. It distills the full incident into a
"Threat DNA" fingerprint — a compact, searchable record of the attack's
unique characteristics.

On future incidents, the Orchestrator checks the Threat DNA library for
matches BEFORE running the full triage pipeline. If a match is found:
  - The triage narrative is pre-populated with historical context.
  - The Blue Agent knows which countermeasures worked last time.
  - The entire response cycle is dramatically faster.

This is the learning loop that makes the mesh smarter over time.
Storage is a simple JSON file — production systems would use a vector DB.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from agents.base_agent import BaseAgent
from core.models import (
    AgentRole, AttackSimulation, BlueAgentResponse,
    DeceptionPlan, IncidentReport, ThreatDNA, ThreatNarrative,
)

logger = logging.getLogger(__name__)

MEMORY_PATH = Path(os.getenv("THREAT_MEMORY_PATH", "data/threat_memory.json"))

# ── Output schema ─────────────────────────────────────────────────────────────

CRYSTALLIZE_TOOL = {
    "name": "crystallize_threat_dna",
    "description": (
        "Extract a compact, reusable Threat DNA fingerprint from a resolved incident. "
        "This fingerprint will be stored permanently and used to accelerate future responses."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "scenario_name": {
                "type": "string",
                "description": "Short name for this threat type (e.g. 'LockBit-variant', 'APT29-cred-harvest').",
            },
            "attack_vector": {
                "type": "string",
                "description": "Primary initial access vector.",
            },
            "payload_characteristics": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Technical characteristics that uniquely identify this payload.",
            },
            "behavioral_patterns": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Behavioral signatures — what this attacker does that distinguishes them.",
            },
            "countermeasures_applied": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Countermeasures that were applied and their outcome.",
            },
            "effectiveness_score": {
                "type": "number",
                "description": "How effective was our response? 0.0 (attacker succeeded) to 1.0 (fully blocked).",
            },
            "incident_summary": {
                "type": "string",
                "description": "2-3 sentence summary for future reference.",
            },
            "key_iocs": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Most important IOCs to watch for in future incidents.",
            },
            "prediction_for_variants": {
                "type": "string",
                "description": "How might this threat evolve? What variants should we watch for?",
            },
        },
        "required": [
            "scenario_name", "attack_vector", "payload_characteristics",
            "behavioral_patterns", "countermeasures_applied", "effectiveness_score",
            "incident_summary", "key_iocs", "prediction_for_variants",
        ],
    },
}

SYSTEM_PROMPT = """You are the Memory Crystallizer of an advanced cybersecurity mesh.

Your role: after an incident is resolved, extract a permanent, reusable Threat DNA
fingerprint that will help the mesh respond faster the next time this threat (or a
variant) appears.

Rules:
- Extract only what is UNIQUE and DISTINGUISHING about this threat — not generic observations.
- The behavioral_patterns must be specific enough to differentiate this threat family
  from all others (think: what would a Snort/Sigma rule catch?).
- The prediction_for_variants must be grounded in known threat evolution patterns.
- The effectiveness_score should be honest — if the attacker partially succeeded, say so.
- The key_iocs should be the most durable indicators (not ephemeral IPs, but TTPs and hashes).
"""


class MemoryCrystallizer(BaseAgent):
    role = AgentRole.MEMORY

    def __init__(self) -> None:
        super().__init__("MemoryCrystallizer", SYSTEM_PROMPT)
        self._memory: List[Dict] = self._load_memory()

    # ── Persistence ───────────────────────────────────────────────────────────

    def _load_memory(self) -> List[Dict]:
        if MEMORY_PATH.exists():
            try:
                with open(MEMORY_PATH, "r") as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                pass
        return []

    def _save_memory(self) -> None:
        MEMORY_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(MEMORY_PATH, "w") as f:
            json.dump(self._memory, f, indent=2, default=str)

    # ── Similarity search (simple keyword overlap) ────────────────────────────

    def find_similar(self, iocs: List[str], mitre_ids: List[str]) -> List[ThreatDNA]:
        """
        Naive similarity: overlap on MITRE technique IDs and key IOC terms.
        A vector DB would replace this in production.
        """
        candidates: List[tuple[float, ThreatDNA]] = []
        query_set = set(mitre_ids) | {ioc.lower() for ioc in iocs}

        for record in self._memory:
            stored_mitre = set(record.get("mitre_techniques", []))
            stored_iocs = {ioc.lower() for ioc in record.get("key_iocs", [])}
            stored_set = stored_mitre | stored_iocs
            if not stored_set:
                continue
            overlap = len(query_set & stored_set) / max(len(query_set | stored_set), 1)
            if overlap > 0.15:
                candidates.append((overlap, ThreatDNA(**record)))

        candidates.sort(key=lambda x: x[0], reverse=True)
        return [dna for _, dna in candidates[:3]]

    # ── Fingerprint hash ──────────────────────────────────────────────────────

    @staticmethod
    def _compute_fingerprint(mitre_ids: List[str], vector: str) -> str:
        raw = "|".join(sorted(mitre_ids)) + "|" + vector
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    # ── Main run ──────────────────────────────────────────────────────────────

    async def run(self, report: IncidentReport) -> ThreatDNA:
        await self._thinking(report.incident.id)

        narrative = report.narrative
        simulation = report.simulation
        blue = report.blue_response
        deception = report.deception_plan

        # Build compact incident summary for Claude
        countermeasure_outcomes = []
        if blue:
            for cm in blue.countermeasures[:5]:
                countermeasure_outcomes.append(
                    f"[{cm.action_type}] {cm.target} — {cm.description}"
                )

        deception_summary = ""
        if deception:
            deception_summary = f"\nDeception: {deception.strategy} ({len(deception.assets)} assets)"

        mitre_ids = [t.id for t in (narrative.mitre_techniques if narrative else [])]

        user_message = f"""Crystallize this resolved incident into a Threat DNA fingerprint.

=== INCIDENT SUMMARY ===
  ID       : {report.incident.id}
  Scenario : {report.incident.scenario_name}
  Duration : {report.duration_seconds:.1f}s
  Severity : {narrative.severity.upper() if narrative else 'UNKNOWN'}

=== THREAT NARRATIVE ===
  Intent  : {narrative.attacker_intent if narrative else 'N/A'}
  Stage   : {narrative.kill_chain_stage if narrative else 'N/A'}
  Summary : {narrative.summary if narrative else 'N/A'}

MITRE Techniques confirmed: {', '.join(mitre_ids) or 'None'}
Key IOCs: {', '.join(narrative.iocs[:8]) if narrative else 'None'}

=== RED AGENT FINDINGS ===
  Actor Profile: {simulation.threat_actor_profile if simulation else 'N/A'}
  Estimated Impact: {simulation.estimated_impact if simulation else 'N/A'}
  Kill Chain Steps: {len(simulation.kill_chain) if simulation else 0}

=== COUNTERMEASURES APPLIED ===
{chr(10).join(f'  • {c}' for c in countermeasure_outcomes) or '  None recorded'}

=== DECEPTION RESULTS ==={deception_summary or ' None'}

=== YOUR TASK ===
Extract a Threat DNA fingerprint that:
1. Captures what is UNIQUE about this threat family.
2. Would allow rapid re-identification if this threat reappears.
3. Records what worked so future responses start with proven countermeasures.
4. Predicts how this threat might evolve."""

        raw = await self._structured_call(
            user_message=user_message,
            output_tool=CRYSTALLIZE_TOOL,
        )

        fingerprint_hash = self._compute_fingerprint(
            mitre_ids, raw.get("attack_vector", "unknown")
        )

        # Find similar past threats
        similar = self.find_similar(
            raw.get("key_iocs", []),
            mitre_ids,
        )
        similar_ids = [s.id for s in similar]

        dna = ThreatDNA(
            scenario_name=raw["scenario_name"],
            fingerprint_hash=fingerprint_hash,
            mitre_techniques=mitre_ids,
            attack_vector=raw["attack_vector"],
            payload_characteristics=raw["payload_characteristics"],
            behavioral_patterns=raw["behavioral_patterns"],
            countermeasures_applied=raw["countermeasures_applied"],
            effectiveness_score=raw["effectiveness_score"],
            incident_summary=raw["incident_summary"],
            key_iocs=raw["key_iocs"],
            similar_dna_ids=similar_ids,
            prediction_for_variants=raw["prediction_for_variants"],
        )

        # Persist
        self._memory.append(json.loads(dna.model_dump_json()))
        self._save_memory()

        await self._complete(
            f"Threat DNA crystallized — hash {fingerprint_hash} | "
            f"Effectiveness: {dna.effectiveness_score:.0%} | "
            f"{len(similar)} similar past threats found",
            report.incident.id,
        )
        logger.info(
            "[MEMORY] DNA %s stored. Library: %d records. Similar: %s",
            fingerprint_hash, len(self._memory), similar_ids,
        )
        return dna
