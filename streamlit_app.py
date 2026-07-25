"""
Live Network Security Auditor Streamlit UI.

Binds UDP:5514 and listens for REAL router syslog. Turn on "Live monitoring"
and attack the routers; findings appear on their own, no clicking. Each
finding gets its own Approve / Reject button.

    py -m streamlit run streamlit_app.py --server.fileWatcherType none
"""

import os
import time
from datetime import datetime

import streamlit as st

from agents import log_collection, risk_agent
from orchestrator import finish_run, run_detection
from tools.recommendation_tool import recommend_for
from tools.risk_calculator_tool import level_for

st.set_page_config(page_title="Network Security Auditor",
                   page_icon="🛡️", layout="wide")

# Bind the UDP:5514 listener on the first run so router packets are captured
# even before the first audit. Idempotent; re-spawns only if the thread died.
log_collection.ensure_listener()

# On FIRST load of this browser session, throw away any syslog that was
# buffered from earlier attacks. Otherwise the app "detects an attack" the
# moment you open it, from stale packets, we want it idle until YOU fire a
# fresh attack in PowerShell.
if "session_started" not in st.session_state:
    log_collection.drain_live()          # discard the backlog
    st.session_state.session_started = True
    st.session_state.phase = "watching"

st.title("🛡️ Network Security Auditor")
st.caption("Live threat detection for network devices, powered by a multi-agent pipeline")

st.markdown("🔴 **Live monitoring active.** Listening for attacks on your routers in real time.")


def _poll():
    """Drain whatever arrived since the last poll and accumulate it. Returns
    how many new lines came in this poll (0 = quiet)."""
    new = log_collection.drain_live()
    buf = st.session_state.setdefault("accum", [])
    buf.extend(new)
    return len(new)


def _present():
    """Analyze everything accumulated so far and show it for approval."""
    logs = st.session_state.get("accum", [])
    st.session_state.last_packets = len(logs)
    st.session_state.state = run_detection({
        "user_request": "Live network security audit.",
        "devices": [], "receiver_email": "", "findings": [], "completed_agents": [],
        "preloaded_logs": logs,
    })
    st.session_state.decisions = {}
    st.session_state.accum = []


# Explicit phase state machine so re-auditing never wipes what you're viewing:
#   "watching"  -> poll fast; accumulate an attack burst until it settles, then
#                  present findings (so a burst isn't split into partial cycles)
#   "reviewing" -> findings waiting on your approve/reject; DON'T re-audit
#   "reported"  -> report generated; show it + download; DON'T re-audit until
#                  you click "Start new cycle"
phase = st.session_state.get("phase", "watching")

if phase == "watching":
    got = _poll()
    accum_n = len(st.session_state.get("accum", []))
    if got > 0:
        # attack still arriving -> keep polling to gather the whole burst
        st.session_state.quiet_polls = 0
    else:
        st.session_state.quiet_polls = st.session_state.get("quiet_polls", 0) + 1

    # Present once we've gathered lines AND the burst has clearly finished.
    # Both routers are attacked in parallel and don't finish at the same instant,
    # so a single quiet poll (one 3s gap) can fire too early and capture only the
    # router that finished first. Require several consecutive quiet polls so BOTH
    # routers' traffic has settled before we present.
    SETTLE_QUIET_POLLS = 5   # ~15s of quiet => both routers' bursts are done
    if accum_n > 0 and st.session_state.get("quiet_polls", 0) >= SETTLE_QUIET_POLLS:
        _present()
        if st.session_state.state.get("findings"):
            st.session_state.phase = "reviewing"
            phase = "reviewing"

# --- Live feed status: proves the logs are REAL, from the routers.
_accum_now = len(st.session_state.get("accum", []))
packets = st.session_state.get("last_packets", 0)
if phase == "watching" and _accum_now > 0:
    st.info(f"⚡ Attack detected. Gathering ({_accum_now} lines so far, finalizing…)")
elif packets and phase != "watching":
    st.success(f"● LIVE: {packets} real syslog line(s) analyzed "
               f"(at {datetime.now().strftime('%H:%M:%S')})")
else:
    st.info("● Monitoring the routers on UDP 5514. No active threats detected. Any attack is picked up automatically.")

st.divider()

if "state" in st.session_state:
    state = st.session_state.state
    decisions = st.session_state.setdefault("decisions", {})

    m1, m2 = st.columns(2)
    m1.metric("Devices scanned", len(state.get("devices", [])))
    m2.metric("Findings", len(state["findings"]))

    if state.get("devices"):
        st.caption("Reporting routers: " + ", ".join(state["devices"]))

    st.divider()
    st.subheader("Pending approvals")
    findings = state["findings"]
    # Per-finding risk from the risk agent (parallel to findings by index).
    per_risk = (state.get("risk", {}) or {}).get("per_finding_risk", [])
    _color = {"Critical": "red", "High": "red", "Medium": "orange", "Low": "green"}
    if not findings:
        st.info("No high-severity findings this cycle.")
    for i, f in enumerate(findings):
        title = f.get("title", str(f)) if isinstance(f, dict) else str(f)
        desc = f.get("description", "") if isinstance(f, dict) else ""
        dev = f.get("device", "") if isinstance(f, dict) else ""
        solution = recommend_for(title)  # the fix the human approves/rejects
        risk_val = per_risk[i] if i < len(per_risk) else 0
        risk_level = level_for(risk_val)
        with st.container(border=True):
            c1, c2 = st.columns([4, 1])
            with c1:
                st.markdown(f"**{title}**" + (f" · `{dev}`" if dev else ""))
                st.markdown(f":{_color.get(risk_level, 'gray')}[**Risk: {risk_val}/25 · {risk_level}**]")
                if isinstance(f, dict) and f.get("breach"):
                    st.markdown(f":red[**⚠️ BREACH: successful login as "
                                f"{', '.join(f.get('breached_users', []))}**]")
                st.caption(desc)
                # Forensic detail parsed from the real logs.
                if isinstance(f, dict) and f.get("source_ips") is not None:
                    ips = ", ".join(f.get("source_ips") or []) or "unknown"
                    users = ", ".join(f.get("usernames") or []) or "unknown"
                    st.markdown(f"🌐 **Source IP(s):** {ips}  |  👤 **Users tried:** {users}")
                    if f.get("first_seen"):
                        st.markdown(f"🕐 **Window:** {f.get('first_seen')} → {f.get('last_seen')}  |  "
                                    f"**Attempts:** {f.get('attempts')}")
                    if f.get("evidence"):
                        with st.expander("Evidence (raw log lines)"):
                            for ev in f["evidence"]:
                                st.code(ev, language=None)
                st.markdown(f"🛠️ **Recommended fix:** {solution}")
                if i in decisions:
                    st.markdown("✅ **Fix approved**" if decisions[i] == "approved"
                                else "❌ **Fix rejected**")
            with c2:
                if i not in decisions:
                    b1, b2 = st.columns(2)
                    if b1.button("Approve", key=f"a{i}"):
                        decisions[i] = "approved"; st.rerun()
                    if b2.button("Reject", key=f"r{i}"):
                        decisions[i] = "rejected"; st.rerun()

    st.divider()
    st.subheader("Report")

    # PHASE: reviewing -> once every finding is decided, run the report agent
    # ONCE and move to the "reported" phase (which stops re-auditing).
    if phase == "reviewing" and findings and len(decisions) == len(findings):
        approved = [f for i, f in enumerate(findings) if decisions.get(i) == "approved"]
        st.session_state.rejected_count = len(findings) - len(approved)

        report_state = dict(state)
        report_state["findings"] = approved
        report_state["human_approval"] = bool(approved)
        if approved:
            # Re-score risk + recommendations over ONLY the approved findings.
            report_state = risk_agent.run(report_state)
            with st.spinner(f"{len(approved)} fix(es) approved. Report agent generating the report..."):
                st.session_state.state = finish_run(report_state)
        else:
            st.session_state.state = report_state  # all rejected -> no report
        st.session_state.phase = "reported"
        st.rerun()

    # PHASE: reported -> show the result + download; stay here until user resets.
    if phase == "reported":
        approved_n = len(st.session_state.state.get("findings", []))
        rejected_n = st.session_state.get("rejected_count", 0)
        if approved_n:
            rpath = st.session_state.state.get("report_path")
            st.success(f"✅ Report generated from {approved_n} approved finding(s)"
                       + (f", {rejected_n} rejected and excluded" if rejected_n else ""))
            st.caption(f"Saved to: {rpath}")
            if st.session_state.state.get("report"):
                st.text_area("Executive summary", st.session_state.state["report"], height=280)
            if rpath and os.path.exists(rpath):
                with open(rpath, "rb") as fh:
                    st.download_button("⬇️ Download PDF report", data=fh.read(),
                                       file_name=os.path.basename(rpath),
                                       mime="application/pdf")
        else:
            st.warning("All findings were rejected. No report generated.")

        if st.button("🔄 Start new cycle (resume live monitoring)"):
            st.session_state.phase = "watching"
            st.session_state.decisions = {}
            st.session_state.accum = []
            st.session_state.quiet_polls = 0
            st.rerun()
    elif phase == "reviewing":
        st.caption(f"Approve or reject each fix. The report generates on its own when done "
                   f"({len(decisions)}/{len(findings)} reviewed).")

# Live loop: while WATCHING, poll every few seconds so a fresh attack is caught
# almost immediately (not up to a minute later). The drain is cheap when the
# buffer is empty, so fast polling just means fast detection. In reviewing or
# reported phase we hold still so nothing you're looking at gets wiped.
POLL_SECONDS = 3
if st.session_state.get("phase", "watching") == "watching":
    time.sleep(POLL_SECONDS)
    st.rerun()
