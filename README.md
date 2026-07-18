# slowloris.py - Low Bandwidth HTTP Denial of Service Tool

[![CI](https://github.com/29nls/slowloris/actions/workflows/ci.yml/badge.svg)](https://github.com/29nls/slowloris/actions/workflows/ci.yml)

## What is Slowloris?

Slowloris is an HTTP Denial of Service attack tool that affects threaded servers. It works by:

1. Opening multiple concurrent HTTP connections to the target server
2. Sending HTTP request headers slowly and periodically to keep connections alive
3. Maintaining connections without completing the request to exhaust the server's thread pool
4. Preventing the server from accepting new legitimate connections

This technique is particularly effective against servers with limited thread pools or connection limits.

## Security Disclaimer

**For authorized penetration testing and educational purposes only.**

Always ensure you have explicit written permission before testing any system you do not own. Unauthorized DoS attacks are illegal and unethical.

## Citation

If you found this work useful, please cite it as:

```bibtex
@software{maceng_slowloris,
  title = "Slowloris",
  author = "MACENG",
  year = "2025",
  url = "https://github.com/29nls/slowloris"
}
```

Original Slowloris concept by Gokberk Yaltirakli (gkbrk)

## Installation

Install slowloris using pip:

```bash
pip install slowloris
```

Or install from source:

```bash
git clone https://github.com/29nls/slowloris.git
cd slowloris
pip install -e .
```

### SOCKS5 Proxy Support

For SOCKS5 proxy support, install with the proxy extra:

```bash
pip install slowloris[proxy]
# or: pip install python-socks
```

## Configuration Options

All options can be passed as command-line arguments:

```bash
slowloris [OPTIONS] HOST
```

### Example Usage

```bash
# Basic usage
slowloris example.com

# Specify port (default: 80)
slowloris example.com -p 8080

# More concurrent connections
slowloris example.com -s 300

# Use HTTPS (port 443)
slowloris example.com --https -p 443

# Verbose logging
slowloris example.com -v

# Randomize user-agents per connection
slowloris example.com -ua

# Use SOCKS5 proxy
slowloris example.com -x --proxy-host 127.0.0.1 --proxy-port 9050

# Adjust keep-alive timing
slowloris example.com --sleeptime 20 --jitter 5
```

### Available Options

| Option | Short | Type | Default | Description |
|--------|-------|------|---------|-------------|
| `HOST` | - | string | required | Target hostname or IP address |
| `--port` | `-p` | integer | 80 | Target port (1-65535) |
| `--sockets` | `-s` | integer | 150 | Number of concurrent connections |
| `--verbose` | `-v` | flag | false | Enable verbose logging output |
| `--randuseragents` | `-ua` | flag | false | Randomize user-agent per connection |
| `--useproxy` | `-x` | flag | false | Use SOCKS5 proxy for connections |
| `--proxy-host` | - | string | 127.0.0.1 | SOCKS5 proxy host |
| `--proxy-port` | - | integer | 8080 | SOCKS5 proxy port |
| `--https` | - | flag | false | Use HTTPS instead of HTTP |
| `--sleeptime` | - | float | 15.0 | Seconds between keep-alive headers |
| `--jitter` | - | float | 3.0 | Random jitter for sleep time (±seconds) |
| `--connect-timeout` | - | float | 10.0 | Timeout for connecting and writing (seconds) |
| `--benchmark` | - | flag | false | Resilience benchmark mode (ramp + report) |
| `--levels` | - | string | 10,50,100,200 | Comma-separated concurrency levels for `--benchmark` |
| `--step-duration` | - | float | 5.0 | Seconds to probe at each benchmark level |
| `--fail-under` | - | float | 0.9 | Probe success-rate threshold for degradation |
| `--adaptive` | - | flag | false | Adaptive mode: closed-loop search for the critical threshold |
| `--start` | - | integer | 10 | Starting concurrency for `--adaptive` search |
| `--max-sockets` | - | integer | 1000 | Upper bound on concurrency for `--adaptive` search |
| `--tolerance` | - | integer | 5 | Stop `--adaptive` when the bracket is within this many sockets |
| `--min-capacity` | - | integer | none | Fail (exit 1) if `--adaptive` threshold is below this value |
| `--report` | - | path | stdout | Write benchmark report as JSON to this path |
| `--report-html` | - | path | none | Write a self-contained HTML report (table + chart) |
| `--report-prometheus` | - | path | none | Write Prometheus text-exposition metrics |
| `--version` | - | - | - | Show version information |

## Resilience benchmark mode

Instead of just flooding a target, `--benchmark` turns slowloris into a
measurement tool for systems **you own or are authorized to test**. It ramps
concurrency through `--levels`, holds partial connections at each level while
sending legitimate probe requests, and records the point where the server
starts refusing legitimate traffic.

```bash
slowloris 127.0.0.1 -p 8080 --benchmark \
    --levels 10,50,100,200 --step-duration 5 \
    --fail-under 0.9 --report report.json
```

The JSON report contains per-level probe success rate and latency plus
`degraded_at` (the first level below `--fail-under`, or `null`). The process
exits non-zero when degradation is detected, so it can gate a CI job.

### Adaptive mode

`--adaptive` is a closed-loop variant: instead of a fixed list of levels, it
reacts to the server's responsiveness. It grows concurrency exponentially until
legitimate probes start failing, then binary-searches the bracket to converge
(within `--tolerance` sockets) on the highest number of held connections the
server still tolerates — using far fewer trials than a dense ramp.

```bash
slowloris 127.0.0.1 -p 8080 --adaptive \
    --start 10 --max-sockets 1000 --tolerance 5 \
    --min-capacity 200 --report report.json
```

The report includes `critical_sockets` (the measured threshold),
`first_degraded_at`, `converged`, and per-trial metrics. With `--min-capacity`
the process exits non-zero when the measured threshold is below the required
value, so a CI job can assert "must sustain at least N concurrent connections".

### Observability outputs

Both benchmark modes can emit richer artifacts alongside (or instead of) the
JSON report:

- `--report-html report.html` — a self-contained HTML report (summary,
  per-level table, and an inline SVG success-rate chart; no external assets).
- `--report-prometheus metrics.prom` — Prometheus text-exposition metrics
  (`slowloris_probe_success_rate`, `slowloris_avg_latency_ms`, and
  `slowloris_critical_sockets` for adaptive runs), e.g. for a node_exporter
  textfile collector.

Each measured level also records a `timestamp`, giving a degradation timeline.

## Defensive tooling (`slowloris-defend`)

The package also ships a **defensive** counterpart. Where the benchmark modes
*measure* how a server you own tolerates slow-HTTP load, `slowloris-defend`
helps you *detect* and *mitigate* slow-HTTP / slowloris attacks server-side.

### Detect

Feed it a JSON snapshot of your server's in-progress connections. It groups
connections per client IP, scores slowloris signatures (many concurrent
connections, stalled/idle incomplete requests, abnormally slow transfer
rates), and classifies each IP as `ok`/`suspicious`/`malicious`.

```bash
# snapshot.json is an array of observed connections:
# [{"client_ip": "6.6.6.6", "age_seconds": 30, "bytes_received": 40,
#   "request_complete": false, "idle_seconds": 10}, ...]

slowloris-defend detect --input snapshot.json --report detection.json
```

It exits non-zero when an attack is detected, so it can gate a monitoring job.
Thresholds are tunable (`--min-age`, `--slow-bps`, `--max-conns`, `--max-idle`).
The snapshot is produced by *your* server/LB (access logs, `ss`/`netstat`, or
application middleware); the detector never opens connections itself.

### Harden

Generate ready-to-apply hardening configuration (request-read timeouts, per-IP
connection caps, and request-rate limiting) for common servers/proxies:

```bash
slowloris-defend harden nginx   --header-timeout 10 --max-conns 20 --rate-per-minute 120
slowloris-defend harden apache  --output apache-hardening.conf
slowloris-defend harden haproxy
```

### Detect volumetric & amplification attacks

Beyond slow-HTTP, `detect-flood` analyses a JSON snapshot of aggregated network
flows for volumetric signatures — **SYN floods** (high-rate SYNs with no
completed handshake), **UDP/ICMP floods**, and **reflection/amplification**
(large UDP responses from abused source ports: NTP `123`, DNS `53`, memcached
`11211`, SSDP `1900`, SNMP `161`, CLDAP `389`, chargen `19`).

```bash
# flows.json: [{"protocol": "udp", "src_ip": "6.6.6.6", "src_port": 11211,
#               "dst_port": 80, "packets": 5000, "bytes": 50000000,
#               "syn_only": false, "window_seconds": 1.0}, ...]

slowloris-defend detect-flood --input flows.json --report flood.json
```

It classifies each offending flow (`syn_flood`/`udp_flood`/`icmp_flood`/`amplification`)
with a severity and exits non-zero when an attack is found. Thresholds are
tunable (`--syn-pps`, `--udp-pps`, `--icmp-pps`, `--amp-bytes`, `--amp-pps`).
Flows come from your netflow/sflow/conntrack/`tcpdump` accounting.

### Harden the network layer

```bash
slowloris-defend harden-net linux-sysctl        # SYN cookies, backlog, rp_filter, ICMP
slowloris-defend harden-net iptables --syn-rate 25 --udp-rate 100 --icmp-rate 10
```

`linux-sysctl` emits `/etc/sysctl.d` kernel tuning (enables `tcp_syncookies`,
raises the SYN backlog, drops spoofed/martian packets); `iptables` emits
rate-limiting rules for SYN/UDP/ICMP plus blocking of amplifier source ports.

### Audit an existing config

`audit` checks a server config file you already run for the hardening
directives that matter against slow-HTTP attacks, and reports the gaps with
severity and remediation:

```bash
slowloris-defend audit nginx /etc/nginx/nginx.conf
slowloris-defend audit haproxy haproxy.cfg --fail-severity medium --report audit.json
```

It exits non-zero when any gap is at least `--fail-severity` (default `high`),
so it can gate CI/config review. The output generated by `harden <server>` is
guaranteed to pass `audit <server>` with zero gaps.

### Observability outputs

Both detectors can emit monitoring artifacts alongside (or instead of) the JSON
report, mirroring the benchmark modes:

```bash
slowloris-defend detect       --input snapshot.json --report-html detect.html \
                              --report-prometheus detect.prom
slowloris-defend detect-flood --input flows.json    --report-prometheus flood.prom
```

- `--report-html` — a self-contained HTML report (risk summary + per-IP / per-flow
  table, no external assets).
- `--report-prometheus` — Prometheus text-exposition metrics
  (`slowloris_defense_attack_detected`, `slowloris_defense_flagged_ips`,
  `slowloris_defense_ip_score`, `slowloris_defense_flood_by_type`,
  `slowloris_defense_flood_max_bps`, …) for a node_exporter textfile collector.

When only `--report-html`/`--report-prometheus` are given (no `--report`), the
JSON is not echoed to stdout; the non-zero exit-on-detection behaviour is unchanged.

## Features (v0.6.0)

- **Defensive tooling (`slowloris-defend`)**: server-side `detect` (score connection snapshots for slowloris signatures, CI-gatable exit code) and `harden` (generate nginx/Apache/HAProxy timeout, connection-cap and rate-limit config); plus `detect-flood` (SYN/UDP/ICMP flood + NTP/DNS/memcached amplification detection), `harden-net` (linux-sysctl/iptables kernel & firewall hardening), and `audit` (flag hardening gaps in an existing server config)
- **Observability outputs**: `--report-html` (self-contained HTML + SVG chart) and `--report-prometheus` (metrics) for both benchmark modes
- **Adaptive threshold search**: `--adaptive` closed-loop binary search for the critical concurrency the target tolerates (efficient, CI-gatable via `--min-capacity`)
- **Resilience benchmark**: `--benchmark` ramps load, probes with legitimate requests, and reports the degradation threshold (JSON + CI exit code)
- **Asyncio-based**: Uses Python asyncio for maximum concurrent connections
- **Non-blocking DNS**: Async name resolution via `loop.getaddrinfo` (never blocks the event loop)
- **Connection/write timeouts**: Configurable `--connect-timeout` guards connects and writes
- **Click CLI**: Modern command-line interface with Click framework
- **Structured logging**: Uses structlog; `-v/--verbose` toggles DEBUG (INFO by default)
- **Class-based architecture**: Clean OOP design without global state
- **No monkey-patching**: Proper async/await methods throughout
- **Type hints**: Full type annotation support (PEP 585/604)
- **Modern user agents**: Updated 2026 browser user-agent strings
- **IPv6 support**: Automatic IPv4/IPv6 detection via getaddrinfo
- **HTTPS/TLS 1.3**: Full TLS support with secure ciphers
- **Signal handling**: Graceful shutdown on Ctrl+C with cleanup
- **Jitter**: Configurable random variation in keep-alive timing
- **Exponential backoff**: Automatic retry with exponential backoff via Tenacity
- **Configuration validation**: Validated config with helpful error messages
- **Statistics tracking**: Tracks connection success/failure metrics
- **Tested & linted**: pytest suite with Ruff, mypy, and pre-commit in CI

## Requirements

- **Python**: 3.10 or higher
- **Core dependencies**:
  - `click` >= 8.1.8 (CLI framework)
  - `structlog` >= 25.4.0 (Structured logging)
  - `tenacity` >= 9.0.0 (Retry logic)

**Optional dependencies**:
- `python-socks` >= 2.5.0 (For SOCKS5 proxy support)

All dependencies are automatically installed via pip.

## Development

Install with the development extras and run the checks:

```bash
git clone https://github.com/29nls/slowloris.git
cd slowloris
pip install -e ".[proxy,dev]"

# Lint, format, type-check and test
ruff check .
ruff format --check .
mypy slowloris.py
pytest -q
```

Pre-commit hooks run Ruff (lint + format) automatically on commit:

```bash
pip install pre-commit
pre-commit install
```

## License

The code is licensed under the MIT License. See LICENSE file for details.
