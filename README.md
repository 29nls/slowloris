# slowloris.py - Low Bandwidth HTTP Denial of Service Tool

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
| `--version` | - | - | - | Show version information |

## Features (v0.3.1)

- **Asyncio-based**: Uses Python asyncio for maximum concurrent connections
- **Click CLI**: Modern command-line interface with Click framework
- **Structured logging**: Uses structlog for detailed, structured logging output
- **Class-based architecture**: Clean OOP design without global state
- **No monkey-patching**: Proper async/await methods throughout
- **Type hints**: Full type annotation support
- **Modern user agents**: Updated 2024 browser user-agent strings
- **IPv6 support**: Automatic IPv4/IPv6 detection via getaddrinfo
- **HTTPS/TLS 1.3**: Full TLS support with secure ciphers
- **Signal handling**: Graceful shutdown on Ctrl+C with cleanup
- **Jitter**: Configurable random variation in keep-alive timing
- **Exponential backoff**: Automatic retry with exponential backoff via Tenacity
- **Configuration validation**: Validated config with helpful error messages
- **Statistics tracking**: Tracks connection success/failure metrics

## Requirements

- **Python**: 3.8 or higher
- **Core dependencies**:
  - `click` >= 8.0.0 (CLI framework)
  - `structlog` >= 23.0.0 (Structured logging)
  - `tenacity` >= 8.0.0 (Retry logic)

**Optional dependencies**:
- `python-socks` >= 1.2.0 (For SOCKS5 proxy support)

All dependencies are automatically installed via pip.

## License

The code is licensed under the MIT License. See LICENSE file for details.
