"""Tests for the config-audit feature."""

from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from defense import (
    SUPPORTED_SERVERS,
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
