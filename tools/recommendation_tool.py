from langchain_core.tools import tool

ACTIONS = {
    "Brute Force": "Enable account lockout policy.",
    "SSH Login": "Restrict SSH access using ACLs.",
    "Telnet Enabled": "Disable Telnet and enable SSH.",
    "Privilege Escalation": "Review and restrict user privilege assignments.",
    "Command Execution": "Enable command auditing and restrict shell access.",
    "Weak Password Policy": "Enforce a strong password policy (length + complexity).",
}


def recommend_for(title: str) -> str:
    """The recommended remediation for one finding title, what the human
    approves or rejects. Used by the UI to show a solution per finding."""
    return ACTIONS.get(title, "Manual review required.")


@tool
def generate_recommendations(findings: list) -> list:
    """
    Generate recommendations from findings.
    """
    recommendations = []
    unmatched = []

    for finding in findings:
        title = finding.get("title")
        if title in ACTIONS:
            recommendations.append(ACTIONS[title])
        else:
            unmatched.append(title)

    if unmatched:
        recommendations.append(f"Manual review required for: {', '.join(unmatched)}")

    return list(set(recommendations))
