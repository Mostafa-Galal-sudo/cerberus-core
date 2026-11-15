# src/response/

Automated, policy-bounded response actions (Checkpoint 3, task C3-T06).

Planned files:
- `isolate.py` — isolate a confirmed attacking device (simulated network
  namespace in Checkpoint 3; real AP/gateway action in Checkpoints 4-5)
- `registry.py` — isolation state per device + expiry/step-down logic

Only `policy/` can authorize an isolation; every action writes to the audit
log and produces a dashboard event.
