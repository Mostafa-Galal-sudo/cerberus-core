# src/policy/

The single authorization gate for anything privileged (Checkpoint 3,
task C3-T01). Security invariant of the whole project: privileged actions route
only through Command -> Policy -> Execution. There is no bypass path.

Planned files:
- `allowlist.py` — the closed set of response/attack actions permitted
- `scope.py` — scope rules per agent/session (which devices, which topics)
- `ratelimit.py` — rate limiting per action type
- `audit.py` — append-only audit log (who, what, when, verdict, reason)

The attack agent, defense agent and response layer all go through `policy/`.
