"""Tests for defensive observability outputs (Prometheus + HTML)."""

from __future__ import annotations

import json

from click.testing import CliRunner

from defense import (
    ConnectionSample,
    NetworkFlow,
    cli,
    detect,
    detect_floods,
    render_detection_html,
    render_detection_prometheus,
    render_flood_html,
    render_flood_prometheus,
)


def _conn(ip: str) -> ConnectionSample:
    return ConnectionSample(
        client_ip=ip,
        age_seconds=30.0,
        bytes_received=40,
        request_complete=False,
        idle_seconds=10.0,
    )


def _amp_flow() -> NetworkFlow:
    return NetworkFlow(
        protocol="udp",
        src_ip="6.6.6.6",
        src_port=11211,
        dst_port=80,
        packets=100,
        bytes=1_000_000,
    )


class TestDetectionPrometheus:
    def test_metrics_present(self):
        report = detect([_conn("6.6.6.6") for _ in range(25)])
        out = render_detection_prometheus(report)
        assert "slowloris_defense_attack_detected 1" in out
        assert 'slowloris_defense_flagged_ips{verdict="malicious"} 1' in out
        assert 'slowloris_defense_ip_score{ip="6.6.6.6",verdict="malicious"} 5' in out
        # Every metric line has a HELP/TYPE header pair.
        assert out.count("# HELP") == out.count("# TYPE")

    def test_clean_attack_zero(self):
        clean = ConnectionSample(
            client_ip="1.1.1.1",
            age_seconds=1.0,
            bytes_received=9000,
            request_complete=True,
            idle_seconds=0.0,
        )
        report = detect([clean])
        out = render_detection_prometheus(report)
        assert "slowloris_defense_attack_detected 0" in out

    def test_label_escaped(self):
        report = detect(
            [
                ConnectionSample(
                    client_ip='ev"il',
                    age_seconds=30.0,
                    bytes_received=40,
                    request_complete=False,
                    idle_seconds=10.0,
                )
                for _ in range(25)
            ]
        )
        out = render_detection_prometheus(report)
        assert 'ip="ev\\"il"' in out


class TestFloodPrometheus:
    def test_metrics_present(self):
        report = detect_floods([_amp_flow()])
        out = render_flood_prometheus(report)
        assert "slowloris_defense_attack_detected 1" in out
        assert 'slowloris_defense_flood_by_type{type="amplification"} 1' in out
        assert "slowloris_defense_flood_max_bps 8000000" in out

    def test_no_findings(self):
        report = detect_floods(
            [
                NetworkFlow(
                    protocol="tcp",
                    src_ip="1.1.1.1",
                    src_port=1,
                    dst_port=80,
                    packets=1,
                    bytes=60,
                    syn_only=True,
                )
            ]
        )
        out = render_flood_prometheus(report)
        assert "slowloris_defense_attack_detected 0" in out
        assert "slowloris_defense_flood_max_bps 0" in out


class TestHtml:
    def test_detection_html_selfcontained(self):
        report = detect([_conn("6.6.6.6") for _ in range(25)])
        html = render_detection_html(report)
        assert html.startswith("<!doctype html>")
        assert "http" not in html.split("<body>")[0].replace("charset", "")  # no external assets
        assert "6.6.6.6" in html
        assert 'class="critical">critical' in html

    def test_flood_html_selfcontained(self):
        report = detect_floods([_amp_flow()])
        html = render_flood_html(report)
        assert html.startswith("<!doctype html>")
        assert "memcached" in html
        assert "amplification" in html


class TestCLIObservability:
    def test_detect_writes_html_and_prom(self, tmp_path):
        snap = tmp_path / "snap.json"
        snap.write_text(
            json.dumps(
                [
                    {
                        "client_ip": "6.6.6.6",
                        "age_seconds": 30,
                        "bytes_received": 40,
                        "request_complete": False,
                        "idle_seconds": 10,
                    }
                    for _ in range(25)
                ]
            )
        )
        html = tmp_path / "r.html"
        prom = tmp_path / "r.prom"
        result = CliRunner().invoke(
            cli,
            [
                "detect",
                "--input",
                str(snap),
                "--report-html",
                str(html),
                "--report-prometheus",
                str(prom),
            ],
        )
        assert result.exit_code == 1  # attack detected
        assert html.read_text().startswith("<!doctype html>")
        assert "slowloris_defense_attack_detected 1" in prom.read_text()
        # JSON not echoed to stdout when only artifact outputs are requested.
        assert result.output.strip() == ""

    def test_detect_flood_writes_prom(self, tmp_path):
        flows = [
            {
                "protocol": "udp",
                "src_ip": "6.6.6.6",
                "src_port": 11211,
                "dst_port": 80,
                "packets": 100,
                "bytes": 1000000,
            }
        ]
        prom = tmp_path / "flood.prom"
        result = CliRunner().invoke(
            cli, ["detect-flood", "--report-prometheus", str(prom)], input=json.dumps(flows)
        )
        assert result.exit_code == 1
        assert 'slowloris_defense_flood_by_type{type="amplification"} 1' in prom.read_text()
