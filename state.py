"""
Shared state passed between every agent in the graph.

Rule: agents only ever read fields they need and write the fields they
own. No agent should reach into another agent's field and mutate it
directly; that keeps the pipeline debuggable when something looks wrong.
"""

from typing import TypedDict


class AuditState(TypedDict, total=False):
    user_request: str

    devices: list[str]

    preloaded_logs: list[str]  # live-drained syslog for this cycle (optional)
    raw_logs: list[str]
    filtered_logs: list[str]

    configurations: list[dict]

    findings: list[dict]
    mitre_mapping: list[dict]

    risk: dict
    recommendations: list[str]

    report: str
    report_path: str

    receiver_email: str

    next_agent: str
    completed_agents: list[str]
    finished: bool

    messages: list

    human_approval: bool | None
    human_feedback: str
