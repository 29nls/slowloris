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

## Features (v0.5.0)

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
