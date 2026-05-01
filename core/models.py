"""
Core data models for the Adversarial Cognitive Mesh.
All inter-agent communication is typed through these models.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


# ──────────────────────────── Enumerations ──────────────────────────────────

class SeverityLevel(str, Enum):
    LOW      = "low"
    MEDIUM   = "medium"
    HIGH     = "high"
    CRITICAL = "critical"


class ThreatCategory(str, Enum):
    RECONNAISSANCE     = "reconnaissance"
    INITIAL_ACCESS     = "initial_access"
    EXECUTION          = "execution"
    PERSISTENCE        = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION    = "defense_evasion"
    CREDENTIAL_ACCESS  = "credential_access"
    DISCOVERY          = "discovery"
    LATERAL_MOVEMENT   = "lateral_movement"
    COLLECTION         = "collection"
    EXFILTRATION       = "exfiltration"
    COMMAND_AND_CONTROL = "command_and_control"
    IMPACT             = "impact"
    UNKNOWN            = "unknown"


class IncidentStatus(str, Enum):
    DETECTING   = "detecting"
    TRIAGING    = "triaging"
    SIMULATING  = "simulating"
    RESPONDING  = "responding"
    DECEIVING   = "deceiving"
    LEARNING    = "learning"
    RESOLVED    = "resolved"


class AgentRole(str, Enum):
    SENTINEL    = "sentinel"
    TRIAGE      = "triage"
    RED         = "red"
    BLUE        = "blue"
    DECEPTION   = "deception"
    MEMORY      = "memory"
    ORCHESTRATOR = "orchestrator"


# ──────────────────────────── Layer 1: Sentinel ──────────────────────────────

class ThreatEvent(BaseModel):
    """Raw event emitted by a sensor agent."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    sensor_type: str           # network | filesystem | process | api
    raw_data: Dict[str, Any]
    confidence: float = Field(ge=0.0, le=1.0)
    description: str
    indicators: List[str] = Field(default_factory=list)
    source_ip: Optional[str]   = None
    destination_ip: Optional[str] = None
    process_name: Optional[str] = None
    file_path: Optional[str]   = None


class ThreatIncident(BaseModel):
    """Aggregated collection of related ThreatEvents forming an incident."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    events: List[ThreatEvent] = Field(default_factory=list)
    status: IncidentStatus = IncidentStatus.DETECTING
    severity: SeverityLevel = SeverityLevel.MEDIUM
    scenario_name: str = "unknown"


# ──────────────────────────── Layer 2: Triage ────────────────────────────────

class MITRETechnique(BaseModel):
    id: str           # e.g. T1059
    name: str
    tactic: str
    tactic_id: str
    description: str
    confidence: float = 0.8


class ThreatNarrative(BaseModel):
    """Cognitive triage output: a strategic story of what the attacker is doing."""
    incident_id: str
    summary: str
    attacker_intent: str
    kill_chain_stage: str
    current_tactic: str
    mitre_techniques: List[MITRETechnique] = Field(default_factory=list)
    predicted_next_steps: List[str] = Field(default_factory=list)
    severity: SeverityLevel
    confidence: float
    iocs: List[str] = Field(default_factory=list)   # Indicators of Compromise


# ──────────────────────────── Layer 3: Red Agent ─────────────────────────────

class KillChainStep(BaseModel):
    stage: str
    technique_id: str
    technique_name: str
    description: str
    target: str
    time_offset: str     # e.g. "T+5min"


class AttackSimulation(BaseModel):
    """Red Agent output: full predicted kill chain run in a sandbox."""
    incident_id: str
    threat_actor_profile: str
    kill_chain: List[KillChainStep] = Field(default_factory=list)
    predicted_targets: List[str] = Field(default_factory=list)
    vulnerabilities_exploited: List[str] = Field(default_factory=list)
    estimated_impact: str
    time_to_completion: str
    confidence: float


# ──────────────────────────── Layer 4: Blue Agent ────────────────────────────

class CountermeasureAction(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    action_type: str    # block | isolate | patch | alert | quarantine | kill_process
    target: str
    description: str
    priority: int       # 1 = highest urgency
    impact: str
    reversible: bool
    mitre_technique_blocked: Optional[str] = None


class BlueAgentResponse(BaseModel):
    """Blue Agent output: prioritized countermeasure plan."""
    incident_id: str
    overall_strategy: str
    countermeasures: List[CountermeasureAction] = Field(default_factory=list)
    expected_outcome: str
    residual_risk: str


# ──────────────────────────── Layer 5: Deception ─────────────────────────────

class DeceptionAsset(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    asset_type: str     # honeypot_file | fake_credentials | decoy_server | canary_token
    lure_description: str
    deployment_location: str
    designed_to_attract: str
    intelligence_value: str
    active: bool = True
    interactions: List[str] = Field(default_factory=list)


class DeceptionPlan(BaseModel):
    """Deception Weaver output: tailored decoy deployment plan."""
    incident_id: str
    strategy: str
    assets: List[DeceptionAsset] = Field(default_factory=list)
    expected_attacker_behavior: str
    intelligence_goals: List[str] = Field(default_factory=list)
    time_window: str


# ──────────────────────────── Layer 6: Memory ────────────────────────────────

class ThreatDNA(BaseModel):
    """Crystallized fingerprint of a threat — the persistent memory of an incident."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    created_at: datetime = Field(default_factory=datetime.utcnow)
    scenario_name: str
    fingerprint_hash: str
    mitre_techniques: List[str] = Field(default_factory=list)
    attack_vector: str
    payload_characteristics: List[str] = Field(default_factory=list)
    behavioral_patterns: List[str] = Field(default_factory=list)
    countermeasures_applied: List[str] = Field(default_factory=list)
    effectiveness_score: float = Field(ge=0.0, le=1.0)
    incident_summary: str
    key_iocs: List[str] = Field(default_factory=list)
    similar_dna_ids: List[str] = Field(default_factory=list)
    prediction_for_variants: str = ""


# ──────────────────────────── Full Incident Report ───────────────────────────

class IncidentReport(BaseModel):
    """Complete incident report bundling all agent outputs."""
    incident: ThreatIncident
    narrative: Optional[ThreatNarrative]   = None
    simulation: Optional[AttackSimulation] = None
    blue_response: Optional[BlueAgentResponse] = None
    deception_plan: Optional[DeceptionPlan]    = None
    threat_dna: Optional[ThreatDNA]            = None
    duration_seconds: float = 0.0
    resolved_at: Optional[datetime] = None


# ──────────────────────────── Agent Status ───────────────────────────────────

class AgentStatus(BaseModel):
    """Broadcast by agents for dashboard updates."""
    agent: AgentRole
    status: str          # idle | thinking | complete | error
    message: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    incident_id: Optional[str] = None
