"""Tests for the slowloris module."""

from __future__ import annotations

import asyncio
import ssl
from dataclasses import FrozenInstanceError

import pytest
from click.testing import CliRunner

import slowloris
from slowloris import USER_AGENTS, Config, Slowloris, main


class TestConfig:
    def test_valid_defaults(self):
        cfg = Config(host="example.com")
        assert cfg.host == "example.com"
        assert cfg.port == 80
        assert cfg.sockets == 150

    def test_empty_host_raises(self):
        with pytest.raises(ValueError, match="Host cannot be empty"):
            Config(host="")

    @pytest.mark.parametrize("port", [0, -1, 65536, 99999])
    def test_invalid_port_raises(self, port):
        with pytest.raises(ValueError, match="Port must be between"):
            Config(host="x", port=port)

    def test_zero_sockets_raises(self):
        with pytest.raises(ValueError, match="Sockets must be at least 1"):
            Config(host="x", sockets=0)

    @pytest.mark.parametrize("sleeptime", [0, -1.5])
    def test_non_positive_sleeptime_raises(self, sleeptime):
        with pytest.raises(ValueError, match="Sleeptime must be positive"):
            Config(host="x", sleeptime=sleeptime)

    def test_negative_jitter_raises(self):
        with pytest.raises(ValueError, match="Jitter must be non-negative"):
            Config(host="x", jitter=-0.1)

    def test_to_dict_round_trips_all_fields(self):
        cfg = Config(host="x", port=443, https=True)
        d = cfg.to_dict()
        assert d["host"] == "x"
        assert d["port"] == 443
        assert d["https"] is True
        assert set(d) == {
            "host", "port", "sockets", "verbose", "randuseragent",
            "useproxy", "proxy_host", "proxy_port", "https",
            "sleeptime", "jitter",
        }

    def test_frozen(self):
        cfg = Config(host="x")
        with pytest.raises(FrozenInstanceError):
            cfg.host = "y"  # type: ignore[misc]


class TestUserAgent:
    def test_returns_first_when_not_random(self):
        sl = Slowloris(Config(host="x", randuseragent=False))
        assert sl._get_user_agent() == USER_AGENTS[0]

    def test_returns_known_agent_when_random(self):
        sl = Slowloris(Config(host="x", randuseragent=True))
        for _ in range(20):
            assert sl._get_user_agent() in USER_AGENTS


class TestSSLContext:
    def test_no_ssl_context_for_plain_http(self):
        sl = Slowloris(Config(host="x", https=False))
        assert sl._ssl is None

    def test_ssl_context_settings_for_https(self):
        sl = Slowloris(Config(host="x", https=True))
        assert isinstance(sl._ssl, ssl.SSLContext)
        assert sl._ssl.check_hostname is False
        assert sl._ssl.verify_mode == ssl.CERT_NONE
        assert sl._ssl.minimum_version == ssl.TLSVersion.TLSv1_2


class _FakeWriter:
    def __init__(self):
        self.buffer = bytearray()
        self.drained = 0

    def write(self, data: bytes) -> None:
        self.buffer.extend(data)

    async def drain(self) -> None:
        self.drained += 1


class TestInitialRequest:
    def test_sends_partial_get_request(self):
        sl = Slowloris(Config(host="target.example"))
        writer = _FakeWriter()
        asyncio.run(sl._send_initial_request(writer))  # type: ignore[arg-type]
        text = writer.buffer.decode()
        assert text.startswith("GET /?")
        assert "Host: target.example\r\n" in text
        assert "User-Agent: " in text
        # Partial request: never terminated with a blank line
        assert not text.endswith("\r\n\r\n")
        assert writer.drained == 1


class TestCLI:
    def test_version(self):
        result = CliRunner().invoke(main, ["--version"])
        assert result.exit_code == 0
        assert slowloris.__version__ in result.output

    def test_no_host_shows_help_and_exits_nonzero(self):
        result = CliRunner().invoke(main, [])
        assert result.exit_code == 1
        assert "Usage" in result.output

    def test_invalid_port_reports_error(self):
        result = CliRunner().invoke(main, ["example.com", "-p", "70000"])
        assert result.exit_code == 1
        assert "Error" in result.output

    def test_useproxy_without_python_socks_fails_fast(self, monkeypatch):
        monkeypatch.setattr(slowloris, "_PROXY_AVAILABLE", False)
        result = CliRunner().invoke(main, ["example.com", "--useproxy"])
        assert result.exit_code == 1
        assert "python-socks" in result.output
