# Network Security Auditor

A multi-agent network security auditor that ingests **real** router syslog,
detects attacks live, scores their risk, maps them to MITRE ATT&CK, and
generates a structured PDF audit report, with a human approval gate in the
middle. Built with **LangGraph**, driven from a live **Streamlit** dashboard,
and fed by a **two-router Docker lab** running genuine network services.

Every finding is backed by real data: real routers, real SSH brute-force
traffic, real syslog. Nothing is mocked.

---

## What it does

1. Two containerized routers forward their real syslog over UDP to the app.
2. When someone brute-forces a router (real failed SSH logins), the app
   detects it **live**, no clicking, findings appear on their own.
3. Each finding is enriched from the raw logs: attacker source IP(s),
   usernames tried, first/last-seen window, attempt count, sample evidence
   lines, and a **breach check** (did any login actually succeed?).
4. A human **approves or rejects** each finding's recommended fix.
5. Approved findings are compiled into a structured **PDF report** (risk table,
   MITRE ATT&CK mapping, recommendations, evidence appendix).

---

## The agents (LangGraph pipeline)

The pipeline is a supervisor-style LangGraph split around a human approval gate.
`orchestrator.py` wires the agents; each agent is a pure function
(`state in → state out`) sharing one `AuditState` object.

```
                       run_detection()  (LangGraph graph)
  live syslog ─────▶ ┌───────────────────────────────────┐
   (UDP 5514)        │  log_collection                   │  drain live syslog, filter noise,
                     │       │                           │  derive which routers reported
                     │       ▼                           │
                     │  log_analysis  ◀── log_analysis_tool.py
                     │       │            (Sigma rules; one enriched finding per
                     │       │             device: IPs, users, timing, evidence, breach)
                     │       ▼                           │
                     │  configuration                    │  device-config weakness checks
                     │       │                           │
                     │       ▼                           │
                     │  risk_agent   ◀── risk_calculator / mitre_mapper /
                     └───────┬───────────  recommendation tools
                             │
                             ▼
                 Human Approval  (Streamlit buttons, approve/reject per finding;
                             │    rejected findings are excluded from the report)
                             ▼
                       finish_run()  (LangGraph graph)
                     ┌───────────────────────────────────┐
                     │  report  ◀── pdf_tool (structured PDF),
                     │              gmail_tool (optional email)
                     └───────────────────────────────────┘
```

| Agent | Responsibility |
|-------|----------------|
| **log_collection** | Drains live router syslog from the UDP listener, filters noise, and derives which routers actually reported. |
| **log_analysis** | Runs Sigma-style detection. Produces **one finding per device per attack type**, enriched with attacker IPs, usernames, timing, attempt count, evidence lines, and a breach flag. |
| **configuration** | Checks device configuration for weaknesses (integration point for real `show running-config` pulls). |
| **risk_agent** | Deterministic risk scoring (Impact × Likelihood, NIST SP 800-30), MITRE ATT&CK mapping, and remediation recommendations. |
| **report** | Builds the structured PDF from state (no LLM, instant and reliable); optionally emails it. |

Detection/Reasoning and Report each run as their own small LangGraph graph.
**Human approval sits between them, outside the graph**, a graph node can't
stand in for a person clicking approve/reject, so this project doesn't pretend
it can.

---

## The two-router lab

`lab/` is a self-contained Docker lab producing genuine network-device syslog.
Two containers (`Router-01`, `Router-02`) each run **real, unmodified** services
on `debian:12-slim`:

- **FRRouting**: real routing daemons (makes them actual software routers)
- **OpenSSH**: real auth; wrong-password logins produce genuine `Failed password` events
- **rsyslog**: forwards every log to the app over **UDP 5514** (RFC3164)

Both routers are identical except for name and IP, and sit on an isolated
Docker network (`labnet`). They are two real Debian Linux machines running real
routing + SSH, packaged as containers, the way you test a security auditor
without physical Cisco gear. See [`lab/README.md`](lab/README.md) for details.

---

## Setup

**Prerequisites:** Python 3.11+, Docker Desktop, and an
[OpenRouter API key](https://openrouter.ai/keys).

```bash
python -m venv .venv
.venv\Scripts\activate            # Windows;  source .venv/bin/activate on Linux/Mac
pip install -r requirements.txt
```

Create a `.env` file in the project root with your key:

```
OPENROUTER_API_KEY=sk-or-...
OPENROUTER_MODEL=meta-llama/llama-3.3-70b-instruct
```

> Note: the report agent is fully deterministic (no LLM call), so the app runs
> even without a valid key, the key is only used by the optional
> `orchestrator.route_intent()` classifier.

---

## Running it (live dashboard)

Start the routers, then the app, then attack.

**1. Start the two routers** (from Git Bash; Windows passes the collector host):
```bash
cd lab
COLLECTOR_IP=host.docker.internal ./lab.sh up
```

**2. Start the Streamlit dashboard:**
```powershell
py -m streamlit run streamlit_app.py --server.fileWatcherType none
```
Open **http://localhost:8501**. It sits idle, listening on UDP 5514.

**3. Fire a real attack** (in another PowerShell window):
```powershell
powershell -File lab\attack.ps1              # small burst → 2 findings
powershell -File lab\attack.ps1 -Users 6 -Tries 3   # bigger
```

Within a few seconds the dashboard shows one **Brute Force** finding per
attacked router, with source IPs, usernames, timing, and evidence. Approve or
reject each fix; once all are decided, the **PDF report generates automatically**
into `reports/` with a download button.

### CLI mode (optional)

`app.py` runs the same pipeline once from the terminal with a text approval
prompt, generating `audit_report.pdf`:
```bash
py app.py
```

---

## Project layout

```
network_security_auditor/
├── streamlit_app.py         # live dashboard (primary UI)
├── app.py                   # CLI entry point (one-shot run)
├── orchestrator.py          # LangGraph wiring
├── config.py                # env + shared OpenRouter client
├── state.py                 # AuditState shared across agents
├── agents/
│   ├── log_collection.py    # UDP syslog listener + drain + filter
│   ├── log_analysis.py      # Sigma detection, per-device enriched findings
│   ├── configuration.py     # device config weakness checks
│   ├── risk_agent.py        # risk score + MITRE + recommendations
│   ├── human_approval.py    # CLI approval gate (Streamlit uses buttons)
│   └── report.py            # structured PDF (+ optional email)
├── tools/
│   ├── log_analysis_tool.py     # Sigma rules + forensic parsing
│   ├── risk_calculator_tool.py  # Impact × Likelihood scoring
│   ├── mitre_mapper_tool.py     # MITRE ATT&CK technique mapping
│   ├── recommendation_tool.py   # remediation recommendations
│   ├── pdf_tool.py              # structured PDF builder (reportlab tables)
│   └── gmail_tool.py            # optional email delivery
├── lab/                     # two-router Docker lab (see lab/README.md)
├── requirements.txt
└── .env                     # your OpenRouter key (git-ignored)
```

Generated at runtime (git-ignored): `reports/`, `lab_syslog.log`, `*.log`.

---

## What's real vs. placeholder

- **Real:** live UDP syslog ingestion, Sigma detection, per-device forensic
  enrichment (IPs/users/timing/evidence), breach detection, risk scoring, MITRE
  mapping, recommendations, and the structured PDF report.
- **Placeholder:** `configuration._collect_configurations` (returns nothing
  until wired to real device configs) and `log_analysis_tool._bertlog_predict`
  (the BERTLog anomaly model, drop in a trained model there).

---

## Optional: email delivery

The `send_email` tool uses the Gmail API. To enable it: create a Google Cloud
project, enable the Gmail API, download an OAuth Desktop client as
`credentials.json` in the project root (first run caches `token.json`). If you
don't need email, skip it, the PDF is still generated.
