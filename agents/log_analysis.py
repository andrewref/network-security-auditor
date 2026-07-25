"""
Log Analysis Agent.

Runs the Sigma detection tool over the collected logs. The tool emits one
enriched finding per device (Router-01, Router-02, ...), each carrying its own
device, attempt count, attacker IPs, usernames, timing, evidence, and breach
flag. BERTLog stays a placeholder for a trained anomaly model.
"""

from state import AuditState
from tools.log_analysis_tool import analyze_logs


def run(state: AuditState) -> AuditState:
    analysis = analyze_logs.invoke({"filtered_logs": state["filtered_logs"]})
    findings = analysis["sigma_results"] + analysis["bertlog_results"]

    state["findings"] = findings
    state.setdefault("completed_agents", []).append("log_analysis")
    return state
