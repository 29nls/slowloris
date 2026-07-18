"""Tests for volumetric/amplification flood detection + network mitigation."""

from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from defense import (
    SUPPORTED_NET_TARGETS,
    AttackType,
    FloodDetectorConfig,
    NetworkFlow,
    NetworkMitigationParams,
    cli,
    detect_floods,
    flood_report_to_dict,
    generate_network_mitigation,
    load_flows,
)


def _flow(**kw) -> NetworkFlow:
    defaults = dict(
        protocol="tcp",
        src_ip="1.2.3.4",
        src_port=12345,
        dst_port=80,
        packets=100,
        bytes=6000,
        syn_only=False,
        window_seconds=1.0,
    )
    defaults.update(kw)
    return NetworkFlow(**defaults)


class TestNetworkFlow:
    def test_rates(self):
        f = _flow(packets=1000, bytes=1000, window_seconds=2.0)
        assert f.packets_per_second == 500.0
        assert f.bits_per_second == 4000.0
        assert f.avg_packet_bytes == 1.0

    def test_zero_packets_avg(self):
        assert _flow(packets=0, bytes=0).avg_packet_bytes == 0.0

    def test_bad_protocol_raises(self):
        with pytest.raises(ValueError, match="protocol"):
            _flow(protocol="sctp")

    def test_bad_window_raises(self):
        with pytest.raises(ValueError, match="window_seconds"):
            _flow(window_seconds=0)


class TestFloodDetector:
    def test_quiet_traffic(self):
        report = detect_floods([_flow(packets=10, syn_only=True)])
        assert not report.attack_detected

    def test_syn_flood(self):
        report = detect_floods([_flow(protocol="tcp", syn_only=True, packets=2000)])
        assert report.attack_detected
        assert report.findings[0].attack_type is AttackType.SYN_FLOOD

    def test_syn_needs_syn_only(self):
        # Same rate but a completed handshake -> not a SYN flood.
        report = detect_floods([_flow(protocol="tcp", syn_only=False, packets=2000)])
        assert not report.attack_detected

    def test_udp_flood(self):
        report = detect_floods([_flow(protocol="udp", src_port=40000, packets=5000)])
        assert report.findings[0].attack_type is AttackType.UDP_FLOOD

    def test_icmp_flood(self):
        report = detect_floods([_flow(protocol="icmp", src_port=0, dst_port=0, packets=1000)])
        assert report.findings[0].attack_type is AttackType.ICMP_FLOOD

    def test_memcached_amplification(self):
        # Large responses from UDP/11211 -> reflection, even at modest pps.
        report = detect_floods(
            [_flow(protocol="udp", src_port=11211, packets=100, bytes=1_000_000)]
        )
        finding = report.findings[0]
        assert finding.attack_type is AttackType.AMPLIFICATION
        assert finding.service == "memcached"

    def test_amplification_takes_precedence_over_udp_flood(self):
        # High-pps UDP from an amplifier port with big packets -> amplification.
        report = detect_floods([_flow(protocol="udp", src_port=123, packets=5000, bytes=5_000_000)])
        assert report.findings[0].attack_type is AttackType.AMPLIFICATION
        assert report.findings[0].service == "ntp"

    def test_small_amplifier_responses_ignored(self):
        # UDP from amplifier port but tiny packets and low pps -> benign.
        report = detect_floods([_flow(protocol="udp", src_port=53, packets=10, bytes=500)])
        assert not report.attack_detected

    def test_bad_config_raises(self):
        with pytest.raises(ValueError, match="syn_pps"):
            FloodDetectorConfig(syn_pps=0)


class TestLoadFlows:
    def test_roundtrip_with_defaults(self):
        raw = json.dumps(
            [
                {
                    "protocol": "UDP",
                    "src_ip": "9.9.9.9",
                    "src_port": 123,
                    "dst_port": 80,
                    "packets": 10,
                    "bytes": 20,
                }
            ]
        )
        flows = load_flows(raw)
        assert flows[0].protocol == "udp"  # lower-cased
        assert flows[0].window_seconds == 1.0

    def test_missing_field_raises(self):
        with pytest.raises(ValueError, match="missing field"):
            load_flows(json.dumps([{"protocol": "tcp", "src_ip": "x"}]))

    def test_unknown_field_raises(self):
        raw = json.dumps(
            [
                {
                    "protocol": "tcp",
                    "src_ip": "x",
                    "src_port": 1,
                    "dst_port": 2,
                    "packets": 1,
                    "bytes": 1,
                    "evil": True,
                }
            ]
        )
        with pytest.raises(ValueError, match="unknown field"):
            load_flows(raw)

    def test_not_a_list_raises(self):
        with pytest.raises(ValueError, match="JSON array"):
            load_flows("42")


class TestFloodSerialization:
    def test_json_safe(self):
        report = detect_floods([_flow(protocol="tcp", syn_only=True, packets=2000)])
        payload = flood_report_to_dict(report)
        text = json.dumps(payload)
        assert '"syn_flood"' in text


class TestNetworkMitigation:
    @pytest.mark.parametrize("target", SUPPORTED_NET_TARGETS)
    def test_generates_nonempty(self, target):
        assert generate_network_mitigation(target).strip()

    def test_sysctl_enables_syncookies(self):
        cfg = generate_network_mitigation("linux-sysctl")
        assert "net.ipv4.tcp_syncookies = 1" in cfg

    def test_iptables_uses_rate(self):
        cfg = generate_network_mitigation(
            "iptables", NetworkMitigationParams(syn_rate_per_second=7)
        )
        assert "--limit 7/second" in cfg

    def test_unsupported_target_raises(self):
        with pytest.raises(ValueError, match="unsupported target"):
            generate_network_mitigation("pf")

    def test_bad_params_raise(self):
        with pytest.raises(ValueError, match="syn_rate_per_second"):
            NetworkMitigationParams(syn_rate_per_second=0)


class TestFloodCLI:
    def test_detect_flood_clean_exit_zero(self, tmp_path):
        snap = tmp_path / "flows.json"
        snap.write_text(
            json.dumps(
                [
                    {
                        "protocol": "tcp",
                        "src_ip": "1.1.1.1",
                        "src_port": 5,
                        "dst_port": 80,
                        "packets": 10,
                        "bytes": 600,
                        "syn_only": True,
                    }
                ]
            )
        )
        result = CliRunner().invoke(cli, ["detect-flood", "--input", str(snap)])
        assert result.exit_code == 0
        assert '"attack_detected": false' in result.output

    def test_detect_flood_attack_exit_one(self):
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
        result = CliRunner().invoke(cli, ["detect-flood"], input=json.dumps(flows))
        assert result.exit_code == 1
        assert '"amplification"' in result.output

    def test_harden_net_stdout(self):
        result = CliRunner().invoke(cli, ["harden-net", "iptables", "--syn-rate", "9"])
        assert result.exit_code == 0
        assert "--limit 9/second" in result.output

    def test_harden_net_writes_file(self, tmp_path):
        out = tmp_path / "sysctl.conf"
        result = CliRunner().invoke(cli, ["harden-net", "linux-sysctl", "--output", str(out)])
        assert result.exit_code == 0
        assert "tcp_syncookies" in out.read_text()
