"""
CLI entry point.

    python app.py
    python app.py --email you@example.com
    python app.py --devices Router1 Switch1 Firewall

Runs: log_collection -> log_analysis -> configuration -> risk_agent
      -> human approval (real prompt) -> report (PDF + optional email)
"""

import argparse

from agents.human_approval import human_approval_gateway
from orchestrator import finish_run, run_detection
from state import AuditState


def main():
    parser = argparse.ArgumentParser(description="Network Security Auditor")
    parser.add_argument("--devices", nargs="*", default=["Router1", "Switch1", "Firewall"])
    parser.add_argument("--email", default="", help="Recipient email for the PDF report")
    args = parser.parse_args()

    state: AuditState = {
        "user_request": "Run a full network security audit.",
        "devices": args.devices,
        "receiver_email": args.email,
        "findings": [],
        "completed_agents": [],
    }

    print("Running detection + reasoning...")
    state = run_detection(state)

    print(f"\n{len(state['findings'])} finding(s) before human review.")
    state = human_approval_gateway(state)

    if not state["human_approval"]:
        print(f"\nApproval rejected. Feedback: {state['human_feedback']}")
        print("Stopping before report generation.")
        return

    print("\nGenerating report...")
    state = finish_run(state)

    print(f"\nDone. Report saved to: {state.get('report_path')}")
    if args.email:
        print(f"Emailed to: {args.email}")


if __name__ == "__main__":
    main()
