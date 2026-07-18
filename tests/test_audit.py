"""Tests for the config-audit feature."""

from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from defense import (
    SUPPORTED_SERVERS,
    _parse_duration,
    audit_config,
    audit_has_gap_at_or_above,
    audit_report_to_dict,
    cli,
    generate_mitigation,
)


class TestAuditConfig:
    @pytest.mark.parametrize("server", SUPPORTED_SERVERS)
    def test_generated_config_passes_its_own_audit(self, server):
        # The harden output should satisfy every check for that server.
        report = audit_config(server, generate_mitigation(server))
        assert report.passed == report.total_checks
        assert report.gaps == []
        assert not audit_has_gap_at_or_above(report, "low")

    def test_empty_config_is_all_gaps(self):
        report = audit_config("nginx", "")
        assert report.passed == 0
        assert len(report.gaps) == report.total_checks
        assert audit_has_gap_at_or_above(report, "high")

    def test_partial_config_reports_specific_gap(self):
        # Has timeouts but no per-IP connection cap -> limit_conn gap (high).
        cfg = "client_header_timeout 10s;\nclient_body_timeout 30s;\nsend_timeout 30s;\n"
        report = audit_config("nginx", cfg)
        gap_ids = {g.id for g in report.gaps}
        assert "limit_conn" in gap_ids
        assert "client_header_timeout" not in gap_ids

    def test_fail_severity_threshold(self):
        # Only a low-severity directive missing -> not a high gap.
        cfg = generate_mitigation("nginx").replace("keepalive_timeout 15s;", "")
        report = audit_config("nginx", cfg)
        assert audit_has_gap_at_or_above(report, "low")
        assert not audit_has_gap_at_or_above(report, "high")

    def test_unsupported_server_raises(self):
        with pytest.raises(ValueError, match="unsupported server"):
            audit_config("iis", "")

    def test_report_to_dict_json_safe(self):
        report = audit_config("haproxy", "")
        payload = audit_report_to_dict(report)
        text = json.dumps(payload)
        assert '"gaps"' in text
        assert payload["gaps"] == payload["total_checks"]


class TestDurationParser:
    @pytest.mark.parametrize(
        ("token", "unit", "expected"),
        [
            ("10s", "s", 10.0),
            ("500ms", "s", 0.5),
            ("2m", "s", 120.0),
            ("30", "s", 30.0),
            ("60000", "ms", 60.0),  # bare number honours the unit default
            ("10s", "ms", 10.0),  # explicit unit overrides the default
        ],
    )
    def test_parse(self, token, unit, expected):
        assert _parse_duration(token, unit) == expected

    def test_garbage_returns_none(self):
        assert _parse_duration("soon", "s") is None


class TestValueValidation:
    def test_generated_configs_are_not_weak(self):
        # harden output must be adequate, not merely present.
        for server in SUPPORTED_SERVERS:
            report = audit_config(server, generate_mitigation(server))
            assert report.weak == []

    def test_oversized_timeout_is_weak_not_missing(self):
        cfg = generate_mitigation("nginx").replace(
            "client_header_timeout 10s;", "client_header_timeout 600s;"
        )
        report = audit_config("nginx", cfg)
        weak = {f.id: f for f in report.weak}
        assert "client_header_timeout" in weak
        assert weak["client_header_timeout"].status == "weak"
        assert weak["client_header_timeout"].observed == "600s"
        assert weak["client_header_timeout"].passed is False
        # A weak high-severity check still counts as a gap and trips the CI gate.
        assert audit_has_gap_at_or_above(report, "high")

    def test_oversized_conn_cap_is_weak(self):
        cfg = generate_mitigation("nginx").replace(
            "limit_conn sl_conn 20;", "limit_conn sl_conn 9000;"
        )
        report = audit_config("nginx", cfg)
        assert "limit_conn" in {f.id for f in report.weak}

    def test_haproxy_bare_ms_timeout_is_weak(self):
        # 60000 with no unit = 60s in HAProxy, over the 30s http-request bound.
        cfg = generate_mitigation("haproxy").replace(
            "timeout http-request 10s", "timeout http-request 60000"
        )
        report = audit_config("haproxy", cfg)
        weak = {f.id: f for f in report.weak}
        assert weak["timeout_http_request"].observed == "60000"

    def test_report_dict_has_missing_and_weak_counts(self):
        cfg = generate_mitigation("nginx").replace(
            "client_header_timeout 10s;", "client_header_timeout 600s;"
        )
        payload = audit_report_to_dict(audit_config("nginx", cfg))
        assert payload["weak"] == 1
        assert payload["missing"] == 0
        assert payload["gaps"] == 1


class TestAuditCLI:
    def test_hardened_config_exit_zero(self, tmp_path):
        cfg = tmp_path / "nginx.conf"
        cfg.write_text(generate_mitigation("nginx"))
        result = CliRunner().invoke(cli, ["audit", "nginx", str(cfg)])
        assert result.exit_code == 0
        assert '"gaps": 0' in result.output

    def test_empty_config_exit_one(self, tmp_path):
        cfg = tmp_path / "nginx.conf"
        cfg.write_text("# nothing hardened here\n")
        result = CliRunner().invoke(cli, ["audit", "nginx", str(cfg)])
        assert result.exit_code == 1
        assert '"passed": 0' in result.output

    def test_fail_severity_low_flags_low_gap(self, tmp_path):
        cfg = tmp_path / "nginx.conf"
        cfg.write_text(generate_mitigation("nginx").replace("keepalive_timeout 15s;", ""))
        # Default (high) -> passes; low -> fails on the keepalive gap.
        assert CliRunner().invoke(cli, ["audit", "nginx", str(cfg)]).exit_code == 0
        strict = CliRunner().invoke(cli, ["audit", "nginx", str(cfg), "--fail-severity", "low"])
        assert strict.exit_code == 1

    def test_writes_report_file(self, tmp_path):
        cfg = tmp_path / "h.cfg"
        cfg.write_text(generate_mitigation("haproxy"))
        out = tmp_path / "audit.json"
        result = CliRunner().invoke(cli, ["audit", "haproxy", str(cfg), "--report", str(out)])
        assert result.exit_code == 0
        assert json.loads(out.read_text())["gaps"] == 0
