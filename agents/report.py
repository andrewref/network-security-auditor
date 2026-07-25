"""
Report Agent.

Deterministic and instant: the findings, risk, and recommendations are
already computed and sit in state, so the report is built straight from them
(PDF + text summary) with NO LLM call. This makes report generation fast and
unable to fail on a slow/garbled model tool call. Emails the PDF only if a
receiver_email is provided.
"""

from datetime import datetime
from pathlib import Path

from state import AuditState
from tools.pdf_tool import build_report
from tools.risk_calculator_tool import level_for as _level_for

# Reports are saved here with a unique timestamped name so each run is kept
# instead of overwriting the last.
REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"

# Email is optional, if the Google auth libs aren't installed, keep the
# report working (PDF only) instead of crashing the whole pipeline on import.
try:
    from tools.gmail_tool import send_email
    _HAS_EMAIL = True
except ImportError:
    _HAS_EMAIL = False


def _mitre_text(state: AuditState) -> str:
    """Readable MITRE ATT&CK lines: 'Brute Force on Router-01 -> T1110 (Brute Force)'."""
    mapping = state.get("mitre_mapping") or []
    if not mapping:
        return ""
    lines = []
    for m in mapping:
        dev = m.get("device", "")
        lines.append(f"{m.get('finding')}" + (f" on {dev}" if dev else "")
                     + f" -> {m.get('technique')} ({m.get('technique_name', '')})")
    return "\n".join(lines)


def _findings_text(state: AuditState) -> str:
    """Each finding rendered as a readable block (not a raw dict)."""
    findings = state.get("findings") or []
    risk = state.get("risk") or {}
    per_risk = risk.get("per_finding_risk", [])
    if not findings:
        return "No findings."

    blocks = []
    for i, f in enumerate(findings):
        rv = per_risk[i] if i < len(per_risk) else ""
        header = f"[{i+1}] {f.get('title')}" + (f" on {f.get('device')}" if f.get("device") else "")
        if rv != "":
            header += f"  (risk {rv}/25)"
        rows = [header]
        if f.get("breach"):
            rows.append(f"    BREACH: successful login as {', '.join(f.get('breached_users', []))}")
        if f.get("attempts") is not None:
            rows.append(f"    Attempts: {f.get('attempts')}")
            rows.append(f"    Source IP(s): {', '.join(f.get('source_ips') or []) or 'unknown'}")
            rows.append(f"    Usernames tried: {', '.join(f.get('usernames') or []) or 'unknown'}")
        if f.get("first_seen"):
            rows.append(f"    Window: {f.get('first_seen')} to {f.get('last_seen')}")
        if f.get("description"):
            rows.append(f"    Detail: {f.get('description')}")
        for ev in f.get("evidence", []):
            rows.append(f"    Evidence: {ev}")
        blocks.append("\n".join(rows))
    return "\n\n".join(blocks)


def _risk_text(state: AuditState) -> str:
    """Clean one-line risk summary instead of a raw dict."""
    risk = state.get("risk") or {}
    return (f"Overall risk score: {risk.get('score', 0)}/100 ({risk.get('level', 'Low')}). "
            f"Per-finding risk: {risk.get('per_finding_risk', [])}.")


def _summary(state: AuditState) -> str:
    """Plain-text executive summary built directly from state (no LLM)."""
    findings = state.get("findings") or []
    risk = state.get("risk") or {}
    recs = state.get("recommendations") or []

    lines = ["Network Security Audit Report", ""]
    lines.append(f"Generated: {datetime.now():%Y-%m-%d %H:%M:%S}")
    lines.append(f"Devices scanned: {', '.join(state.get('devices', [])) or 'none'}")
    lines.append(f"Findings: {len(findings)}")
    lines.append(f"Overall risk: {risk.get('score', 0)} ({risk.get('level', 'Low')})")

    # Breach alert up top if any brute force actually succeeded.
    breaches = [f for f in findings if f.get("breach")]
    if breaches:
        lines.append("")
        lines.append("*** BREACH ALERT: successful login(s) after brute force ***")
        for f in breaches:
            lines.append(f"    {f.get('device')}: account(s) {', '.join(f.get('breached_users', []))}")

    lines.append("")
    for f in findings:
        dev = f.get("device", "")
        lines.append(f"- {f.get('title')}" + (f" on {dev}" if dev else "")
                     + f": {f.get('description', '')}")
        # Forensic detail (real, parsed from the logs) for brute-force findings.
        if f.get("source_ips") is not None:
            if f.get("first_seen"):
                lines.append(f"    Window: {f.get('first_seen')} -> {f.get('last_seen')}")
            lines.append(f"    Attempts: {f.get('attempts')} | "
                         f"Source IP(s): {', '.join(f.get('source_ips') or []) or 'unknown'} | "
                         f"Users tried: {', '.join(f.get('usernames') or []) or 'unknown'}")
            for ev in f.get("evidence", []):
                lines.append(f"      evidence: {ev}")
    mitre = _mitre_text(state)
    if mitre:
        lines.append("")
        lines.append("MITRE ATT&CK techniques:")
        for ml in mitre.split("\n"):
            lines.append(f"- {ml}")
    if recs:
        lines.append("")
        lines.append("Recommended fixes:")
        for r in recs:
            lines.append(f"- {r}")
    return "\n".join(lines)


def _report_data(state: AuditState) -> dict:
    """Structured data the PDF builder turns into tables (no raw dicts)."""
    findings = state.get("findings") or []
    risk = state.get("risk") or {}
    per = risk.get("per_finding_risk", [])
    enriched = []
    for i, f in enumerate(findings):
        rv = per[i] if i < len(per) else 0
        enriched.append({**f, "risk_value": rv, "risk_level": _level_for(rv)})
    breaches = [f"{f.get('device')}: {', '.join(f.get('breached_users', []))}"
                for f in findings if f.get("breach")]
    return {
        "generated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "devices": state.get("devices", []),
        "risk": risk,
        "breaches": breaches,
        "findings": enriched,
        "mitre": state.get("mitre_mapping") or [],
        "recommendations": state.get("recommendations") or [],
    }


def run(state: AuditState) -> AuditState:
    # Build a structured PDF directly from state, no LLM, so this is instant
    # and can't fail on a slow or malformed model tool call. Unique timestamped
    # filename in reports/ so each run is kept, not overwritten.
    REPORTS_DIR.mkdir(exist_ok=True)
    filename = str(REPORTS_DIR / f"audit_report_{datetime.now():%Y-%m-%d_%H%M%S}.pdf")
    report_path = build_report(_report_data(state), filename)
    state["report"] = _summary(state)
    state["report_path"] = report_path

    # Email the PDF only if a recipient was provided and email is available.
    recipient = (state.get("receiver_email") or "").strip()
    if recipient and _HAS_EMAIL:
        try:
            send_email.invoke({"to": recipient, "attachment_path": report_path,
                               "subject": "Network Security Audit Report",
                               "body": state["report"]})
        except Exception as e:
            print(f"[report] email failed: {e}")

    state.setdefault("completed_agents", []).append("report")
    return state
