---
title: Cerberus‑V — Engineering Report & Execution Plan
author: Lead Engineer (Lethe)
updated: 2025-08-09
---

## 0. Executive Snapshot

- Mission: APT‑resilient firewall (eBPF+VPP) with LIVE/SIM, ≤120 µs P99, Fedora 42.
- Status: Backend API stable (SIM), preflight/rollback core in place (mock), GUI integrated, metrics exported, tests passing in user env. 
- Next Critical: harden preflight for LIVE, API contract tests, GUI build smoke, start/stop engine UX, reproducible builds.

## 1. Work Completed (high‑signal)

- Backend
  - Preflight manager with rule validation, shadow copy, rollback; baseline immutable rule.
  - FastAPI app; CORS fixed; WebSocket heartbeat; normalized status; datetime fixed; os import.
  - Prometheus exporter: `cerberus_uptime_seconds` + other gauges/counters.
- Control Plane (Go)
  - Simulation BPF Map Manager (safe for tests); unit tests added.
  - Prometheus exporter unit tests (fresh registry isolation).
- Frontend (React/Vite/Tailwind)
  - API service via fetch; Mode context; Live toggle; Analytics/NetworkStatus rewire to API.
  - Layout (Sidebar/TopBar) simplified; login demo; CSS baseline.
- Safety Harness (host)
  - Immutable logs (`audit.log`, `cerberus/current.log`), logrotate with postrotate `chattr` dance.
  - `panic.sh` emergency rollback.
- Tests
  - Integration tests adapted for non‑root; uptime metric check; Go unit tests green.

## 2. Current Risks / Pain Points

- LIVE mode preflight not fully hardened (BPF fs, ring limits, throttling, shadow‑swap).
- Editing root‑owned files (e.g., `/etc/logrotate.d/cerberus`) can race/require sudo; avoid direct IDE writes.
- GUI build path can drift; missing deps cause Vite failures.
- SELinux denials possible on BPF/VPP attach (needs policy entries).

## 3. Recommended Execution Order (minimal risk → maximal impact)

1) Testing & Contracts (safe)
   - API contract tests for rules/status/mode (JSON schema, invariants, baseline rule guard).
   - GUI build smoke test (CI: npm ci + vite build).

2) Preflight Hardening (medium)
   - BPF fs checks; ring buffer sizing; rate limiting; shadow map two‑phase commit (mock→wire).
   - Rollback on panic; watchdog glue.

3) Engine UX (medium)
   - Start/Stop Engine button; status reflect; errors bubbled to UI.

4) Import/Export Rules (medium)
   - JSON schema v1; download/upload; validate offline; audit log entries.

5) Packaging & Hardening (higher)
   - Systemd drop‑ins (limits/seccomp/landlock placeholders); SELinux policy; dev‑container; reproducible builds.

6) Performance Path (highest)
   - Real eBPF map manager; pinning; XDP attach; VPP path; perf harness.

## 4. Detailed Step‑by‑Step Plan

### A. Tests First
1. Add `tests/integration/test_api_contract.py`:
   - Validate endpoints: `/api/mode`, `/api/rules`, `/api/preflight`, `/api/rollback`, `/api/health`, `/api/system/status`.
   - Assert baseline rule immutable, preflight blocks unsafe, CORS headers present.
2. Add `tests/smoke/frontend_build.sh`:
   - `cd gui/frontend && npm ci && npm run build` (cache off), fail fast.

### B. Preflight LIVE Hardening
3. Add ringbuffer & BPF fs limits:
   - Verify `/sys/fs/bpf` mounted; ensure writable; `max_entries ≤ 1% RAM`.
4. Throttling:
   - Per‑second op limit for live apply; surface 429 to UI.
5. Shadow map two‑phase commit:
   - Prepare shadow; validate; atomic swap; rollback on failure.
6. Panic rollback hooks:
   - Watchdog for VPP/XDP detach; revert to SIM; restart services.

### C. Engine UX
7. Dashboard button `Start/Stop Engine`:
   - Calls backend start/stop; show spinner & result; audit log entry.

### D. Import/Export
8. Export: Download rules as JSON (schema v1, includes checksum).
9. Import: Upload → validate offline → preflight → staged apply.

### E. Packaging & CI
10. Systemd: finalize drop‑ins; `preflight-network.sh` guard; resource limits.
11. SELinux: add rules for BPF/VPP ops; CI `ausearch -ts boot` gating.
12. Dev‑container: pinned toolchain; reproducible build.

### F. Performance Bring‑up
13. Real BPF map manager (behind feature flag) with graceful fallback to SIM.
14. XDP attach/detach safe; VPP pipeline; perf tests (TREX harness ≥100 Gbps).

## 5. High‑Risk Areas & Safeguards

- BPF map exhaustion → cap `max_entries`; telemetry + alert.
- Human error (0.0.0.0/0 DROP) → immutable baseline; confirm dialogs; dry‑run.
- NIC reset / XDP detach → auto re‑attach + watchdog.
- Log flood → logrotate + gzip + size limits; immutable current log.
- SELinux blocks → ship `.te` updates; audit CI check.

## 6. Operational Commands (root‑safe patterns)

Edit root files safely (avoid IDE write errors):

```bash
# Preferred: use the installer script (writes atomically)
bash /home/outspoken/Cerberus-V/scripts/install-logrotate.sh
```

Diagnose save problems:

```bash
ls -l /etc/logrotate.d/cerberus
lsattr /etc/logrotate.d/cerberus || true
sudo chattr -i /etc/logrotate.d/cerberus 2>/dev/null || true
sudoedit /etc/logrotate.d/cerberus
```

## 7. Test Matrix (to run locally)

```bash
# Go unit tests
cd ctrl && go test ./...

# Python integration tests (user-mode)
bash tests/integration/run_tests.sh --pytest-only

# GUI smoke build
cd gui/frontend && npm ci && npm run build
```

## 8. Acceptance Criteria (gate)

- `go test` and `pytest` green; GUI build succeeds.
- Preflight blocks unsafe LIVE ops; rollback succeeds; audit logged.
- Start/Stop button reflects engine state; errors visible in UI.
- Immutable logs preserved post‑rotation; size bounds enforced.

## 9. Changelog (delta)

- Added Go tests for metrics and BPF sim.
- Stabilized integration tests; heartbeat WS; CORS fixes.


