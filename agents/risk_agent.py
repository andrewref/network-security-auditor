"""
Risk Assessment Agent.

Purely deterministic (no LLM call), risk scoring, MITRE mapping, and
recommendations all need to be reproducible and auditable, so they run
straight through the tools rather than through a model.
"""

from state import AuditState
from tools.mitre_mapper_tool import map_to_mitre
from tools.recommendation_tool import generate_recommendations
from tools.risk_calculator_tool import calculate_risk


def run(state: AuditState) -> AuditState:
    findings = state.get("findings", [])

    state["risk"] = calculate_risk.invoke({"findings": findings})
    state["mitre_mapping"] = map_to_mitre.invoke({"findings": findings})
    state["recommendations"] = generate_recommendations.invoke({"findings": findings})

    state.setdefault("completed_agents", []).append("risk_agent")
    return state
