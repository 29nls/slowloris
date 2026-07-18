# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.0]

### Added
- **Adaptive benchmark mode (`--adaptive`)**: closed-loop search for a target's critical concurrency threshold. Grows concurrency exponentially until legitimate probes start failing, then binary-searches the bracket to converge (within `--tolerance` sockets) on the highest number of held connections the server still tolerates — far fewer trials than a dense static ramp.
- Options `--start`, `--max-sockets`, `--tolerance`, and `--min-capacity` (exit non-zero when the measured threshold is below a required capacity, for CI gating).
- Report includes `critical_sockets`, `first_degraded_at`, `converged`, and per-trial metrics.
- Public `AdaptiveBenchmark` class; shared `_measure_level` helper reused by both benchmark modes.

## [0.4.0]

### Added
- **Resilience benchmark mode (`--benchmark`)**: ramps concurrency through `--levels`, holds partial connections at each level while sending legitimate probe requests, and measures probe success rate + latency. Reports the level where the success rate drops below `--fail-under` (`degraded_at`).
- `--report` writes a structured JSON report (per-level metrics + target + threshold); prints to stdout otherwise.
- Benchmark exits non-zero when degradation is detected, so it can gate CI/authorized resilience tests.
- Public `probe()` helper and `Benchmark` runner; `Slowloris.start_workers()` / `stop_and_join()` extracted for reuse.

## [0.3.2]

### Fixed
- `-v/--verbose` now actually controls the log level (INFO by default, DEBUG with `-v`); previously INFO/DEBUG logs were silently suppressed.
- Non-blocking DNS resolution via `loop.getaddrinfo`; the synchronous `socket.getaddrinfo` used to block the event loop for every worker.
- `writer.drain()` calls (initial request and keep-alive loop) are wrapped in `asyncio.wait_for`, so a stalled socket can no longer hang a worker indefinitely.

### Added
- `--connect-timeout` option (default 10s) with validation, applied to connect and write operations.
- pytest test suite and GitHub Actions CI (Ruff, mypy, pytest on Python 3.10–3.13).
- pre-commit configuration (Ruff lint + format) and a `dev` extra.

### Changed
- Fail fast with a clear error when `--useproxy` is used without `python-socks` installed.
- Keep-alive header value uses `random` instead of `secrets` (no need for a cryptographic RNG).
- Packaging migrated from `setup.py` to PEP 621 `pyproject.toml`; minimum Python raised to 3.10; type hints modernized to PEP 585/604.
- Dependencies and browser user-agent strings updated to current releases.
