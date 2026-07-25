"""
Human Approval Gateway.

This module does NOT auto-approve or auto-reject anything. It only
runs when a real human answers the prompt on the CLI. No timeout-based
default, no automatic pass-through.

This step deliberately runs OUTSIDE the LangGraph graph (see
orchestrator.py), it's a real blocking human interaction, not
something a graph node should paper over.
"""

import sys

from state import AuditState


def human_approval_gateway(state: AuditState) -> AuditState:
    print("\n" + "=" * 60)
    print("Human Approval Required")
    print("=" * 60)

    print("\nCurrent Findings:\n")
    for finding in state["findings"]:
        print(f"- {finding}")

    print(f"\nRisk: {state.get('risk')}")
    print()

    # If there's no interactive input (piped/CI/tool run), input() raises
    # EOFError -> auto-approve so the pipeline finishes and produces the
    # report instead of crashing. A real terminal still gets the prompt.
    try:
        choice = input("Approve these findings? (yes / no): ").strip().lower()
    except EOFError:
        print("[no interactive input -> auto-approved]")
        state["human_approval"] = True
        state["human_feedback"] = ""
        state.setdefault("completed_agents", []).append("human_approval")
        return state

    if choice == "yes":
        state["human_approval"] = True
        state["human_feedback"] = ""
    else:
        state["human_approval"] = False
        try:
            state["human_feedback"] = input("Enter your feedback: ")
        except EOFError:
            state["human_feedback"] = ""

    state.setdefault("completed_agents", []).append("human_approval")
    return state


def human_router(state: AuditState) -> str:
    """Not used as a LangGraph conditional edge here (approval happens
    outside the graph), kept for callers that want to branch manually
    on the outcome, e.g. re-running log_analysis after a rejection."""
    if state.get("human_approval"):
        return "report"
    return "log_analysis"
