"""
Orchestrator, Supervisor pattern, built with LangGraph.

Rule: this file stays a "dumb router." It only decides which agent runs
next and passes AuditState forward. No business logic lives here --
that all belongs inside the individual agent modules.

Two graphs, split around the human approval gate, same reasoning as
before: the graph can't safely auto-resolve a human approval, so the
Human Approval Gateway runs as a real blocking CLI/UI interaction
between `run_detection()` and `finish_run()`, not as a graph node.

    run_detection()  ->  human_approval_gateway()  ->  finish_run()
    (log_collection -> log_analysis -> configuration -> risk_agent)      (report)

There's also `route_intent()`, a separate one-shot LLM call that reads
a free-text user request and returns which agent it thinks should
handle it, useful as a front door if you want a chat-style entry
point instead of always running the full pipeline. It does NOT drive
the graph below; it's a standalone classifier.
"""

from langchain_core.messages import HumanMessage, SystemMessage
from langgraph.graph import END, StateGraph

from agents import configuration, log_analysis, log_collection, report, risk_agent
from config import llm
from state import AuditState

# --- Natural-language intent router (optional front door) -----------------

SINGLE_AGENT_SYSTEM = """
You are the Main Orchestrator of a Network Security Auditor system.

Your responsibility is NOT to solve the user's request.
Your responsibility is ONLY to decide which specialized agent should execute next.

Available agents:

1. log_collection
   - Collect logs from network devices.
   - Filter and normalize logs.

2. log_analysis
   - Analyze collected logs.
   - Detect anomalies and suspicious activities.
   - Produce security findings.

3. configuration
   - Collect and analyze device configurations.
   - Detect configuration weaknesses and misconfigurations.

4. correlation
   - Correlate findings from log analysis and configuration analysis.
   - Calculate risk score.
   - Generate security recommendations.

5. report
   - Generate the final audit report.

Rules:
- Never answer the user's networking question.
- Never explain the solution.
- Only decide which agent should run next.
- Return ONLY the agent name.
- If more information is required, choose the first logical agent.

Possible outputs:

log_collection
log_analysis
configuration
correlation
report
"""


def route_intent(question: str) -> str:
    msgs = [
        SystemMessage(content=SINGLE_AGENT_SYSTEM),
        HumanMessage(content=question),
    ]
    response = llm.invoke(msgs)
    return response.content.strip()


# --- LangGraph nodes: each just calls the pure agent function --------------

def _node_log_collection(state: AuditState) -> AuditState:
    return log_collection.run(state)


def _node_log_analysis(state: AuditState) -> AuditState:
    return log_analysis.run(state)


def _node_configuration(state: AuditState) -> AuditState:
    return configuration.run(state)


def _node_risk_agent(state: AuditState) -> AuditState:
    return risk_agent.run(state)


def _node_report(state: AuditState) -> AuditState:
    return report.run(state)


def build_detection_graph():
    """Detection + Reasoning layers. Stops right before human approval."""
    graph = StateGraph(AuditState)
    graph.add_node("log_collection", _node_log_collection)
    graph.add_node("log_analysis", _node_log_analysis)
    graph.add_node("configuration", _node_configuration)
    graph.add_node("risk_agent", _node_risk_agent)

    graph.set_entry_point("log_collection")
    graph.add_edge("log_collection", "log_analysis")
    graph.add_edge("log_analysis", "configuration")
    graph.add_edge("configuration", "risk_agent")
    graph.add_edge("risk_agent", END)

    return graph.compile()


def build_report_graph():
    """Control layer (human approval) has already happened by the time
    this runs, this just produces the final report node."""
    graph = StateGraph(AuditState)
    graph.add_node("report", _node_report)
    graph.set_entry_point("report")
    graph.add_edge("report", END)
    return graph.compile()


_detection_graph = build_detection_graph()
_report_graph = build_report_graph()


def run_detection(state: AuditState) -> AuditState:
    """Runs log_collection -> log_analysis -> configuration -> risk_agent."""
    return _detection_graph.invoke(state)


def finish_run(state: AuditState) -> AuditState:
    """Call after human approval has been resolved."""
    return _report_graph.invoke(state)
