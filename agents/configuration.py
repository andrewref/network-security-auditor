"""
Configuration Agent.

The orchestrator prompt and AuditState both reference a "configuration"
step, but it wasn't implemented in the original notebook. This fills
that gap: it inspects `state["configurations"]` (device config dumps)
for known weaknesses and appends any it finds to `state["findings"]`
using the same title/impact/likelihood/description shape log_analysis
produces, so risk_agent can treat both sources uniformly.

`_collect_configurations` is the integration point for real config
pulls (e.g. `show running-config` over SSH/NETCONF). For now it returns
a fixed demo config set.
"""

from state import AuditState

CONFIG_RULES = {
    "Weak Password Policy": {
        "title": "Weak Password Policy",
        "impact": 3,
        "likelihood": 3,
        "description": "Device password policy does not enforce sufficient complexity/length.",
    },
    "Telnet Enabled": {
        "title": "Telnet Enabled",
        "impact": 3,
        "likelihood": 5,
        "description": "Insecure remote access service detected in device configuration.",
    },
}


def _collect_configurations(devices: list[str]) -> list[dict]:
    """
    Real configuration collection integration point (e.g. parse_running_config
    over SSH/NETCONF). Not wired to live device configs yet, so it returns
    nothing: the audit only reports findings backed by real data instead of
    injecting demo Firewall/Switch-1 weaknesses on every cycle.

    Real version:
        return [{"device": d, "issue": parse_running_config(d)} for d in devices]
    """
    return []


def run(state: AuditState) -> AuditState:
    # Use configs passed on state if present; otherwise collect (currently none).
    configurations = state.get("configurations")
    if configurations is None:
        configurations = _collect_configurations(state.get("devices", []))
    state["configurations"] = configurations

    # Copy, don't mutate the existing list in place: state is threaded through
    # the graph and reused, so appending to the shared list could duplicate
    # findings across invocations.
    findings = list(state.get("findings", []))
    for cfg in configurations:
        rule = CONFIG_RULES.get(cfg.get("issue"))
        if rule:
            findings.append({**rule, "device": cfg.get("device")})

    state["findings"] = findings
    state.setdefault("completed_agents", []).append("configuration")
    return state
