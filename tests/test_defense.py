"""Tests for the defense module (slow-HTTP detection + mitigation)."""

from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from defense import (
    SUPPORTED_SERVERS,
    ConnectionSample,
    DetectorConfig,
    MitigationParams,
    Verdict,
    cli,
    detect,
    generate_mitigation,
    load_samples,
    report_to_dict,
)


def _sample(ip: str, **kw) -> ConnectionSample:
    defaults = dict(
        client_ip=ip,
        age_seconds=30.0,
        bytes_received=40,
        request_complete=False,
        idle_seconds=10.0,
    )
    defaults.update(kw)
    return ConnectionSample(**defaults)


class TestConnectionSample:
    def test_bytes_per_second(self):
        s = _sample("1.1.1.1", age_seconds=10.0, bytes_received=100)
        assert s.bytes_per_second == 10.0

    def test_zero_age_is_instantaneous(self):
        s = _sample("1.1.1.1", age_seconds=0.0, bytes_received=100)
        assert s.bytes_per_second == 100.0

    def test_empty_ip_raises(self):
        with pytest.raises(ValueError, match="client_ip"):
            _sample("")

    def test_negative_age_raises(self):
        with pytest.raises(ValueError, match="age_seconds"):
            _sample("1.1.1.1", age_seconds=-1.0)


class TestDetector:
    def test_clean_traffic_is_ok(self):
        samples = [
            _sample("10.0.0.1", bytes_received=100000, request_complete=True, idle_seconds=0.0)
            for _ in range(3)
        ]
        report = detect(samples)
        assert not report.attack_detected
        assert report.assessments[0].verdict is Verdict.OK

    def test_slowloris_footprint_is_malicious(self):
        # Many slow, stalled, incomplete connections from one IP.
        samples = [_sample("6.6.6.6") for _ in range(25)]
        report = detect(samples)
        assert report.attack_detected
        assert "6.6.6.6" in report.malicious_ips
        top = report.assessments[0]
        assert top.verdict is Verdict.MALICIOUS
        assert top.slow_connections == 25

    def test_new_connections_not_flagged(self):
        # age below min_age_seconds -> not counted as slow even if incomplete.
        samples = [_sample("7.7.7.7", age_seconds=1.0) for _ in range(3)]
        report = detect(samples)
        assert report.assessments[0].slow_connections == 0
        assert report.assessments[0].verdict is Verdict.OK

    def test_threshold_config_respected(self):
        samples = [_sample("8.8.8.8") for _ in range(3)]
        strict = DetectorConfig(max_connections_per_ip=2, malicious_score=2)
        report = detect(samples, strict)
        assert "8.8.8.8" in report.malicious_ips

    def test_bad_detector_config_raises(self):
        with pytest.raises(ValueError, match="malicious_score"):
            DetectorConfig(suspicious_score=5, malicious_score=1)


class TestLoadSamples:
    def test_roundtrip(self):
        raw = json.dumps(
            [
                {
                    "client_ip": "1.2.3.4",
                    "age_seconds": 30,
                    "bytes_received": 40,
                    "request_complete": False,
                    "idle_seconds": 10,
                }
            ]
        )
        samples = load_samples(raw)
        assert len(samples) == 1
        assert samples[0].client_ip == "1.2.3.4"

    def test_not_a_list_raises(self):
        with pytest.raises(ValueError, match="JSON array"):
            load_samples("{}")

    def test_unknown_field_raises(self):
        raw = json.dumps(
            [
                {
                    "client_ip": "x",
                    "age_seconds": 1,
                    "bytes_received": 1,
                    "request_complete": True,
                    "idle_seconds": 0,
                    "evil": 1,
                }
            ]
        )
        with pytest.raises(ValueError, match="unknown field"):
            load_samples(raw)

    def test_missing_field_raises(self):
        with pytest.raises(ValueError, match="missing field"):
            load_samples(json.dumps([{"client_ip": "x"}]))


class TestReportSerialization:
    def test_report_to_dict_is_json_safe(self):
        report = detect([_sample("9.9.9.9") for _ in range(25)])
        payload = report_to_dict(report)
        text = json.dumps(payload)  # must not raise
        assert "malicious" in text
        assert payload["assessments"][0]["verdict"] == "malicious"


class TestMitigation:
    @pytest.mark.parametrize("server", SUPPORTED_SERVERS)
    def test_generates_nonempty_config(self, server):
        cfg = generate_mitigation(server)
        assert cfg.strip()

    def test_nginx_uses_params(self):
        cfg = generate_mitigation(
            "nginx", MitigationParams(header_timeout=7, max_connections_per_ip=5)
        )
        assert "client_header_timeout 7s;" in cfg
        assert "limit_conn sl_conn 5;" in cfg

    def test_haproxy_uses_params(self):
        cfg = generate_mitigation("haproxy", MitigationParams(max_connections_per_ip=15))
        assert "sc0_conn_cur gt 15" in cfg

    def test_unsupported_server_raises(self):
        with pytest.raises(ValueError, match="unsupported server"):
            generate_mitigation("iis")

    def test_bad_params_raise(self):
        with pytest.raises(ValueError, match="header_timeout"):
            MitigationParams(header_timeout=0)


class TestCLI:
    def test_detect_clean_exit_zero(self, tmp_path):
        snap = tmp_path / "snap.json"
        snap.write_text(
            json.dumps(
                [
                    {
                        "client_ip": "1.1.1.1",
                        "age_seconds": 1,
                        "bytes_received": 9999,
                        "request_complete": True,
                        "idle_seconds": 0,
                    }
                ]
            )
        )
        result = CliRunner().invoke(cli, ["detect", "--input", str(snap)])
        assert result.exit_code == 0
        assert '"attack_detected": false' in result.output

    def test_detect_attack_exit_one(self, tmp_path):
        snap = tmp_path / "snap.json"
        conns = [
            {
                "client_ip": "6.6.6.6",
                "age_seconds": 30,
                "bytes_received": 40,
                "request_complete": False,
                "idle_seconds": 10,
            }
            for _ in range(25)
        ]
        snap.write_text(json.dumps(conns))
        result = CliRunner().invoke(cli, ["detect", "--input", str(snap)])
        assert result.exit_code == 1
        assert '"attack_detected": true' in result.output

    def test_detect_reads_stdin(self):
        conns = [
            {
                "client_ip": "6.6.6.6",
                "age_seconds": 30,
                "bytes_received": 40,
                "request_complete": False,
                "idle_seconds": 10,
            }
            for _ in range(25)
        ]
        result = CliRunner().invoke(cli, ["detect"], input=json.dumps(conns))
        assert result.exit_code == 1

    def test_harden_stdout(self):
        result = CliRunner().invoke(cli, ["harden", "nginx", "--header-timeout", "8"])
        assert result.exit_code == 0
        assert "client_header_timeout 8s;" in result.output

    def test_harden_writes_file(self, tmp_path):
        out = tmp_path / "nginx.conf"
        result = CliRunner().invoke(cli, ["harden", "nginx", "--output", str(out)])
        assert result.exit_code == 0
        assert "limit_conn_zone" in out.read_text()
