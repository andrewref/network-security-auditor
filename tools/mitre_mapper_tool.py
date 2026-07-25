from langchain_core.tools import tool

# title -> (technique ID, technique name). Verify IDs against attack.mitre.org
# before adding new rows.
MITRE_MAPPING = {
    "Brute Force": ("T1110", "Brute Force"),
    "SSH Login": ("T1021", "Remote Services"),
    "Telnet Enabled": ("T1021", "Remote Services"),
    "Privilege Escalation": ("T1068", "Exploitation for Privilege Escalation"),
    "Command Execution": ("T1059", "Command and Scripting Interpreter"),
    "Weak Password Policy": ("T1078", "Valid Accounts"),
}


@tool
def map_to_mitre(findings: list) -> list:
    """
    Map findings to MITRE ATT&CK techniques (ID + name), keeping the device
    so the report can attribute each technique to the router it was seen on.
    """
    techniques = []

    for finding in findings:
        attack = finding.get("title")
        if attack in MITRE_MAPPING:
            tid, tname = MITRE_MAPPING[attack]
            techniques.append(
                {
                    "finding": attack,
                    "device": finding.get("device", ""),
                    "technique": tid,
                    "technique_name": tname,
                }
            )

    return techniques
