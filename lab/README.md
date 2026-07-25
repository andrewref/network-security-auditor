# Router Lab

A self-contained Docker lab that produces **real** network-device syslog to
feed the security auditor. Two containerized "routers" run genuine, unmodified
services, no mocks:

- **OpenSSH**: real auth; failed logins become `Failed password` events (→ Brute Force finding)
- **FRRouting**: real routing daemons → genuine routing logs
- **rsyslog**: forwards everything over UDP to the collector in RFC3164 format

Both routers sit on an isolated Docker network `labnet` and forward syslog to
**UDP 5514** on the host.

## Files

| File | What it does |
|------|--------------|
| `Dockerfile` | Builds the router image on `debian:12-slim` with FRR, OpenSSH, rsyslog. Lab-only root password `R0uter-lab!` (override `--build-arg ROOT_PASSWORD=`). |
| `start-router.sh` | Container boot: writes rsyslog forward config to `COLLECTOR_IP:5514`, stamps the router name on every line, starts sshd + rsyslog + FRR, emits boot events. |
| `lab.sh` | Control script (see commands below). |
| `syslog_collector.py` | Host-side UDP listener on 5514; writes received lines to `../lab_syslog.log`, which the auditor reads. |

## Usage

Run `lab.sh` from Git Bash (or `bash lab.sh ...` from PowerShell).

```bash
# Windows/Mac: pass the host address the containers reach the collector on.
export COLLECTOR_IP=host.docker.internal

./lab.sh up        # build image + start Router-01 and Router-02
./lab.sh attack    # real failed-login brute-force against a router
./lab.sh logs      # each router's recent sshd auth log
./lab.sh reset     # restart routers to a clean baseline (no attacks)
./lab.sh down      # stop and remove the routers
```

### Full run against the auditor

```bash
# terminal 1, collector (from project root)
python lab/syslog_collector.py

# terminal 2
export COLLECTOR_IP=host.docker.internal
./lab.sh up
./lab.sh attack          # ATTACK_USERS=6 for a bigger burst (default 2 ≈ 10 findings)

# terminal 3, run the auditor; it reads lab_syslog.log
python app.py --devices Router-01 Router-02
```

## Notes

- On Windows, `hostname -I` (auto-detect) is Linux-only, so **pass
  `COLLECTOR_IP=host.docker.internal`**.
- Attack size is tunable: `ATTACK_USERS=6 ./lab.sh attack` (default 2 ≈ 10 findings).
- `reset` flips back to a clean "before" state between tests without a rebuild.
- The root password `R0uter-lab!` is throwaway/lab-only, never reuse it.
- The lab is independent of the app code: it just needs Docker running and the
  collector listening on 5514.
