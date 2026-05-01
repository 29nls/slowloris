# slowloris.py - Simple slowloris in Python

## What is Slowloris?

Slowloris is basically an HTTP Denial of Service attack that affects threaded servers. It works like this:

1. We start making lots of HTTP requests.
2. We send headers periodically (every ~15 seconds) to keep the connections open.
3. We never close the connection unless the server does so. If the server closes a connection, we create a new one keep doing the same thing.

This exhausts the servers thread pool and the server can't reply to other people.

## Security Disclaimer

**For authorized penetration testing and educational purposes only.** 

Always ensure you have explicit written permission before testing any system you do not own. Unauthorized DoS attacks are illegal and unethical.

## Citation

If you found this work useful, please cite it as

```bibtex
@article{gkbrkslowloris,
  title = "Slowloris",
  author = "Gokberk Yaltirakli",
  journal = "github.com",
  year = "2015",
  url = "https://github.com/gkbrk/slowloris"
}
```

## Installation

You can install using **pip** in a virtual environment:

```bash
# Create and activate virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install slowloris
pip install slowloris
```

Or install from source:

```bash
git clone https://github.com/gkbrk/slowloris.git
cd slowloris
pip install -e .
```

## Usage

```bash
# Basic usage
slowloris example.com

# Specify port (default: 80)
slowloris example.com -p 80

# More concurrent connections
slowloris example.com -s 300

# Use HTTPS
slowloris example.com --https

# Verbose mode
slowloris example.com -v

# Randomize user-agents
slowloris example.com -ua
```

### SOCKS5 Proxy Support

For SOCKS5 proxy support, install with the proxy extras:

```bash
pip install slowloris[proxy]
# or: pip install python-socks
```

Then use:

```bash
slowloris example.com -x --proxy-host 127.0.0.1 --proxy-port 8080
```

## Configuration Options

| Option | Description | Default |
|--------|-------------|---------|
| `host` | Target host | (required) |
| `-p, --port` | Target port | 80 |
| `-s, --sockets` | Number of concurrent connections | 150 |
| `-v, --verbose` | Enable verbose logging | false |
| `-ua, --randuseragents` | Randomize user-agent per connection | false |
| `-x, --useproxy` | Use SOCKS5 proxy | false |
| `--proxy-host` | SOCKS5 proxy host | 127.0.0.1 |
| `--proxy-port` | SOCKS5 proxy port | 8080 |
| `--https` | Use HTTPS | false |
| `--sleeptime` | Seconds between keep-alive headers | 15 |
| `--jitter` | Random jitter added to sleep time | 3 |
| `--version` | Show version | - |

## Changes in v0.3.0

- **Asyncio-based**: Uses Python asyncio for maximum concurrent connections
- **Class-based architecture**: Clean OOP design without global state
- **No monkey-patching**: Proper methods instead of socket patches
- **Type hints**: Full type annotation support
- **Modern user agents**: Updated browser strings (2024)
- **IPv6 support**: Uses getaddrinfo for dual-stack
- **Signal handling**: Graceful shutdown on Ctrl+C
- **Jitter**: Random sleep variation to avoid patterns
- **Exponential backoff**: Automatic reconnection with retries
- **Statistics**: Tracks connection success/failure

## Requirements

- Python 3.8+
- ssl (stdlib)
- socket (stdlib)

Optional:
- python-socks (for SOCKS5 proxy support)

## License

The code is licensed under the MIT License. See LICENSE file for details.
