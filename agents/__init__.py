"""
Agents package.

Original:
  LearningAgent — ML classifier for alert labelling (agents/learning_agent.py)

New (Adversarial Cognitive Mesh):
  BaseAgent          — Base Claude agent
  SentinelMesh       — Layer 1: sensor network
  TriageAgent        — Layer 2: MITRE ATT&CK narrative
  RedAgent           — Layer 3: adversarial kill-chain simulation
  BlueAgent          — Layer 4: pre-emptive countermeasures
  DeceptionWeaver    — Layer 5: tailored honeypots
  MemoryCrystallizer — Layer 6: Threat DNA learning
"""

# Agents are imported lazily by consumers to avoid pulling in `anthropic`
# before the venv is set up.  Import directly from the submodules:
#
#   from agents.triage_agent import TriageAgent
#   from agents.red_agent    import RedAgent
#   …etc.

__all__ = [
    "BaseAgent",
    "SentinelMesh",
    "TriageAgent",
    "RedAgent",
    "BlueAgent",
    "DeceptionWeaver",
    "MemoryCrystallizer",
]
