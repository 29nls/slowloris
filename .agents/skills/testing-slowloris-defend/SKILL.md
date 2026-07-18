---
name: testing-slowloris-defend
description: Test the slowloris CLI end-to-end, especially the defensive slowloris-defend tool (detect/harden). Use when verifying changes to defense.py or slowloris.py.
---

# Testing slowloris / slowloris-defend

Python CLI project (single `slowloris.py` + `defense.py`). Two console scripts:
`slowloris` (attack/benchmark) and `slowloris-defend` (defensive detect/harden).

## Setup
```bash
python -m pip install --upgrade pip setuptools wheel   # local pip may be too old for PEP 660 editable installs
pip install -e ".[proxy,dev]"
pre-commit install
```
Checks (mirror CI): `ruff check .` · `ruff format --check .` · `mypy slowloris.py defense.py` · `pytest -q`.

## Testing approach
This is a CLI, so testing is **shell-only — do NOT record** (nothing visual). Build small
JSON/text fixtures in a scratch dir and run the console scripts, asserting on stdout + exit code.

### slowloris-defend detect
- Input: JSON array of connection objects
  `{client_ip, age_seconds, bytes_received, request_complete, idle_seconds}`.
- Key behavior to prove: **exits 1 when an attack is detected, 0 otherwise** (CI-gatable).
  A slowloris footprint = many old, incomplete, slow (low bytes/sec), idle connections from one IP.
- Prove thresholds are wired by flipping a flag (e.g. `--max-conns`) and showing the same
  input changes verdict. A test that doesn't change result when a flag changes is weak.

### slowloris-defend harden <nginx|apache|haproxy>
- Emits config text to stdout (or `--output`). Assert param values appear literally, e.g.
  `--header-timeout 8` → `client_header_timeout 8s;`, `--max-conns 15` (haproxy) → `sc0_conn_cur gt 15`.

## Gotchas / future-proofing
- The old system pip may reject editable installs ("missing build_editable hook"); upgrading
  pip/setuptools/wheel first fixes it. If that ever stops working, run tests against the module
  directly (`python -m pytest`) or `python defense.py ...` without installing.
- `detect` exiting non-zero on attack is intended, not a failure — don't treat exit 1 as broken.
- Verdict scoring lives in `_assess_ip` in `defense.py`; if thresholds change, update fixtures
  (e.g. connection count vs `max_connections_per_ip`) so they still cross the intended boundary.

## Devin Secrets Needed
- None. Testing is fully local; no external services or credentials.
