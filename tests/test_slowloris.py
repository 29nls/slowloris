"""Tests for the slowloris module."""

from __future__ import annotations

import asyncio
import logging
import re
import ssl
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest
from click.testing import CliRunner

import slowloris
from slowloris import (
    USER_AGENTS,
    AdaptiveBenchmark,
    Benchmark,
    Config,
    Slowloris,
    _parse_levels,
    _summarize_level,
    main,
    probe,
)


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

    @pytest.mark.parametrize("timeout", [0, -5])
    def test_non_positive_connect_timeout_raises(self, timeout):
        with pytest.raises(ValueError, match="Connect timeout must be positive"):
            Config(host="x", connect_timeout=timeout)

    def test_to_dict_round_trips_all_fields(self):
        cfg = Config(host="x", port=443, https=True)
        d = cfg.to_dict()
        assert d["host"] == "x"
        assert d["port"] == 443
        assert d["https"] is True
        assert set(d) == {
            "host",
            "port",
            "sockets",
            "verbose",
            "randuseragent",
            "useproxy",
            "proxy_host",
            "proxy_port",
            "https",
            "sleeptime",
            "jitter",
            "connect_timeout",
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

    @pytest.mark.parametrize(
        ("args", "expected_level"),
        [
            (["example.com"], logging.INFO),
            (["example.com", "-v"], logging.DEBUG),
        ],
    )
    def test_verbose_sets_log_level(self, monkeypatch, args, expected_level):
        async def _noop(config):
            return None

        monkeypatch.setattr(slowloris, "_run_attack", _noop)
        logging.getLogger().setLevel(logging.WARNING)
        result = CliRunner().invoke(main, args)
        assert result.exit_code == 0
        assert logging.getLogger().level == expected_level


class TestPackaging:
    def test_version_matches_pyproject(self):
        pyproject = Path(__file__).resolve().parent.parent / "pyproject.toml"
        text = pyproject.read_text(encoding="utf-8")
        match = re.search(r'^version = "([^"]+)"', text, re.MULTILINE)
        assert match is not None
        assert match.group(1) == slowloris.__version__


async def _start_http_server():
    """Start a tiny HTTP server that answers complete requests with 200."""

    async def handler(reader, writer):
        try:
            while True:
                line = await reader.readline()
                if not line:
                    return
                if line in (b"\r\n", b"\n"):
                    break
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            await writer.drain()
        except (ConnectionError, asyncio.CancelledError):
            pass
        finally:
            writer.close()

    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    return server, port


class TestBenchmark:
    def test_parse_levels_valid(self):
        assert _parse_levels("10,50,100") == [10, 50, 100]
        assert _parse_levels(" 5 , 20 ") == [5, 20]

    @pytest.mark.parametrize("raw", ["10,abc", "0,5", "", "-3"])
    def test_parse_levels_invalid(self, raw):
        import click

        with pytest.raises(click.BadParameter):
            _parse_levels(raw)

    def test_summarize_level(self):
        s = _summarize_level(50, [(True, 0.01), (True, 0.03), (False, 0.5)])
        assert s["sockets"] == 50
        assert s["probes"] == 3
        assert s["probe_successes"] == 2
        assert s["success_rate"] == round(2 / 3, 4)
        assert s["avg_latency_ms"] == round(0.02 * 1000, 2)
        assert s["max_latency_ms"] == 30.0

    def test_summarize_level_empty(self):
        s = _summarize_level(1, [])
        assert s["success_rate"] == 0.0
        assert s["avg_latency_ms"] is None
        assert s["max_latency_ms"] is None

    @pytest.mark.parametrize(
        ("levels", "fail_under"),
        [([], 0.9), ([0], 0.9), ([1], 1.5), ([1], -0.1)],
    )
    def test_benchmark_validation(self, levels, fail_under):
        with pytest.raises(ValueError):
            Benchmark(Config(host="x"), levels, fail_under=fail_under)

    def test_probe_and_benchmark_end_to_end(self):
        asyncio.run(self._e2e())

    async def _e2e(self):
        server, port = await _start_http_server()
        try:
            ok, latency = await probe("127.0.0.1", port, timeout=5)
            assert ok is True
            assert latency >= 0

            config = Config(
                host="127.0.0.1",
                port=port,
                sleeptime=1,
                jitter=0,
                connect_timeout=5,
            )
            bench = Benchmark(
                config,
                [2, 3],
                step_duration=1.0,
                probe_interval=0.2,
                warmup=0.3,
                fail_under=0.9,
            )
            report = await bench.run()
            assert report["degraded_at"] is None
            assert report["target"]["port"] == port
            assert [lvl["sockets"] for lvl in report["levels"]] == [2, 3]
            assert all(lvl["success_rate"] == 1.0 for lvl in report["levels"])
        finally:
            server.close()
            await server.wait_closed()

    def test_probe_failure_on_closed_port(self):
        ok, latency = asyncio.run(probe("127.0.0.1", 1, timeout=1))
        assert ok is False
        assert latency >= 0


class TestBenchmarkCLI:
    def test_benchmark_success_exit_code(self, monkeypatch):
        async def fake(config, levels, step_duration, fail_under, report_path):
            return 0

        monkeypatch.setattr(slowloris, "_run_benchmark", fake)
        result = CliRunner().invoke(main, ["example.com", "--benchmark", "--levels", "2,4"])
        assert result.exit_code == 0

    def test_benchmark_degraded_exit_code(self, monkeypatch):
        async def fake(config, levels, step_duration, fail_under, report_path):
            return 1

        monkeypatch.setattr(slowloris, "_run_benchmark", fake)
        result = CliRunner().invoke(main, ["example.com", "--benchmark"])
        assert result.exit_code == 1

    def test_benchmark_bad_levels_exit_code(self, monkeypatch):
        async def fake(config, levels, step_duration, fail_under, report_path):
            return 0

        monkeypatch.setattr(slowloris, "_run_benchmark", fake)
        result = CliRunner().invoke(main, ["example.com", "--benchmark", "--levels", "0"])
        assert result.exit_code == 2


def _fake_measure_factory(threshold):
    """Return a fake _measure_level where levels <= threshold stay healthy."""

    async def fake_measure(config, level, *, step_duration, probe_interval, warmup):
        ok = level <= threshold
        return {
            "sockets": level,
            "probes": 1,
            "probe_successes": int(ok),
            "success_rate": 1.0 if ok else 0.0,
            "avg_latency_ms": 1.0,
            "max_latency_ms": 1.0,
            "connections_created": level,
        }

    return fake_measure


class TestAdaptiveBenchmark:
    @pytest.mark.parametrize(
        ("kwargs"),
        [
            {"start": 0},
            {"start": 10, "max_sockets": 5},
            {"tolerance": 0},
            {"fail_under": 1.5},
        ],
    )
    def test_validation(self, kwargs):
        with pytest.raises(ValueError):
            AdaptiveBenchmark(Config(host="x"), **kwargs)

    def test_converges_on_threshold(self, monkeypatch):
        monkeypatch.setattr(slowloris, "_measure_level", _fake_measure_factory(37))
        adaptive = AdaptiveBenchmark(
            Config(host="x"),
            start=1,
            max_sockets=1000,
            tolerance=1,
            fail_under=0.9,
        )
        report = asyncio.run(adaptive.run())
        assert report["converged"] is True
        assert report["critical_sockets"] == 37
        assert report["first_degraded_at"] is not None
        # Search is efficient: far fewer trials than a dense 1..1000 ramp.
        assert len(report["trials"]) < 30

    def test_never_degrades_within_bounds(self, monkeypatch):
        monkeypatch.setattr(slowloris, "_measure_level", _fake_measure_factory(10_000))
        adaptive = AdaptiveBenchmark(
            Config(host="x"),
            start=2,
            max_sockets=8,
            tolerance=1,
        )
        report = asyncio.run(adaptive.run())
        assert report["converged"] is False
        assert report["first_degraded_at"] is None
        assert report["critical_sockets"] == 8


class TestAdaptiveCLI:
    def test_adaptive_success_exit_code(self, monkeypatch):
        async def fake(
            config,
            start,
            max_sockets,
            tolerance,
            step_duration,
            fail_under,
            min_capacity,
            report_path,
        ):
            return 0

        monkeypatch.setattr(slowloris, "_run_adaptive", fake)
        result = CliRunner().invoke(main, ["example.com", "--adaptive"])
        assert result.exit_code == 0

    def test_adaptive_below_capacity_exit_code(self, monkeypatch):
        async def fake(
            config,
            start,
            max_sockets,
            tolerance,
            step_duration,
            fail_under,
            min_capacity,
            report_path,
        ):
            return 1

        monkeypatch.setattr(slowloris, "_run_adaptive", fake)
        result = CliRunner().invoke(main, ["example.com", "--adaptive", "--min-capacity", "500"])
        assert result.exit_code == 1

    def test_adaptive_bad_bounds_exit_code(self, monkeypatch):
        async def fake(*args, **kwargs):
            return 0

        monkeypatch.setattr(slowloris, "_run_adaptive", fake)
        result = CliRunner().invoke(
            main, ["example.com", "--adaptive", "--start", "100", "--max-sockets", "10"]
        )
        assert result.exit_code == 2
