#!/usr/bin/env python3
"""Defensive counterpart to slowloris: detect and mitigate slow-HTTP attacks.

Where ``slowloris.py`` *measures* how a server you own tolerates slow-HTTP
load, this module helps you *defend* against it:

1. Detection - analyse a snapshot of in-progress server connections for
   slowloris / slow-HTTP signatures (many concurrent connections from one
   client, stalled/idle connections, and abnormally slow request transfer
   rates) and score each client IP.
2. Mitigation - generate ready-to-apply hardening configuration for common
   web servers / proxies (nginx, Apache, HAProxy): request-read timeouts,
   per-IP connection caps, and request-rate limiting.

Everything here is server-side and defensive. The detector consumes a JSON
snapshot of observed connections (see ``ConnectionSample``); it does not open
or manipulate any connection itself.
"""

from __future__ import annotations

import json
import re
import sys
from dataclasses import asdict, dataclass, field
from enum import Enum
from html import escape
from pathlib import Path

import click
import structlog

__version__ = "0.1.0"

log = structlog.get_logger()


class Verdict(str, Enum):
    """Risk classification for a single client IP."""

    OK = "ok"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


@dataclass(frozen=True)
class ConnectionSample:
    """A point-in-time observation of one in-progress server connection.

    These are meant to be produced by the server / load balancer being
    protected (e.g. from access logs, ``ss``/``netstat`` output, or an
    application middleware) and fed to the detector as a snapshot.
    """

    client_ip: str
    age_seconds: float
    bytes_received: int
    request_complete: bool
    idle_seconds: float

    def __post_init__(self) -> None:
        if not self.client_ip:
            raise ValueError("client_ip cannot be empty")
        if self.age_seconds < 0:
            raise ValueError("age_seconds cannot be negative")
        if self.bytes_received < 0:
            raise ValueError("bytes_received cannot be negative")
        if self.idle_seconds < 0:
            raise ValueError("idle_seconds cannot be negative")

    @property
    def bytes_per_second(self) -> float:
        """Average request-transfer rate; 0 age is treated as instantaneous."""
        if self.age_seconds <= 0:
            return float(self.bytes_received)
        return self.bytes_received / self.age_seconds


@dataclass(frozen=True)
class DetectorConfig:
    """Thresholds that define what looks like a slow-HTTP attack.

    Defaults are conservative starting points; tune them to the legitimate
    traffic profile of the service you are protecting.
    """

    # Only connections at least this old count towards "slow" signatures,
    # so brand-new connections are never flagged.
    min_age_seconds: float = 10.0
    # Incomplete requests transferring slower than this (bytes/sec) look like
    # a client dribbling headers to hold the connection open.
    slow_bytes_per_second: float = 50.0
    # A single client holding more than this many concurrent connections is
    # the classic slowloris footprint.
    max_connections_per_ip: int = 20
    # Incomplete connections idle for longer than this are treated as stalled.
    max_idle_seconds: float = 5.0
    # Per-IP suspicious/malicious score cut-offs (see IPAssessment.score).
    suspicious_score: int = 1
    malicious_score: int = 3

    def __post_init__(self) -> None:
        if self.malicious_score < self.suspicious_score:
            raise ValueError("malicious_score must be >= suspicious_score")


@dataclass
class IPAssessment:
    """Aggregated slow-HTTP risk assessment for a single client IP."""

    client_ip: str
    total_connections: int
    slow_connections: int
    stalled_connections: int
    max_age_seconds: float
    min_bytes_per_second: float
    reasons: list[str] = field(default_factory=list)
    verdict: Verdict = Verdict.OK
    score: int = 0


@dataclass
class DetectionReport:
    """Full detection result for one connection snapshot."""

    total_connections: int
    total_ips: int
    suspicious_ips: list[str]
    malicious_ips: list[str]
    assessments: list[IPAssessment]

    @property
    def attack_detected(self) -> bool:
        return bool(self.malicious_ips)


def _assess_ip(
    client_ip: str,
    samples: list[ConnectionSample],
    config: DetectorConfig,
) -> IPAssessment:
    """Score a single IP's connections against the detector thresholds."""
    slow = 0
    stalled = 0
    for s in samples:
        old_enough = s.age_seconds >= config.min_age_seconds
        if old_enough and not s.request_complete:
            if s.bytes_per_second <= config.slow_bytes_per_second:
                slow += 1
            if s.idle_seconds >= config.max_idle_seconds:
                stalled += 1

    max_age = max((s.age_seconds for s in samples), default=0.0)
    min_rate = min((s.bytes_per_second for s in samples), default=0.0)

    reasons: list[str] = []
    score = 0
    if len(samples) > config.max_connections_per_ip:
        score += 2
        reasons.append(f"{len(samples)} concurrent connections (> {config.max_connections_per_ip})")
    if slow:
        score += 2
        reasons.append(f"{slow} slow incomplete request(s)")
    if stalled:
        score += 1
        reasons.append(f"{stalled} stalled/idle incomplete connection(s)")

    if score >= config.malicious_score:
        verdict = Verdict.MALICIOUS
    elif score >= config.suspicious_score:
        verdict = Verdict.SUSPICIOUS
    else:
        verdict = Verdict.OK

    return IPAssessment(
        client_ip=client_ip,
        total_connections=len(samples),
        slow_connections=slow,
        stalled_connections=stalled,
        max_age_seconds=max_age,
        min_bytes_per_second=min_rate,
        reasons=reasons,
        verdict=verdict,
        score=score,
    )


def detect(
    samples: list[ConnectionSample],
    config: DetectorConfig | None = None,
) -> DetectionReport:
    """Analyse a connection snapshot and classify each client IP."""
    config = config or DetectorConfig()

    by_ip: dict[str, list[ConnectionSample]] = {}
    for s in samples:
        by_ip.setdefault(s.client_ip, []).append(s)

    assessments = [_assess_ip(ip, ip_samples, config) for ip, ip_samples in by_ip.items()]
    assessments.sort(key=lambda a: a.score, reverse=True)

    suspicious = [a.client_ip for a in assessments if a.verdict is Verdict.SUSPICIOUS]
    malicious = [a.client_ip for a in assessments if a.verdict is Verdict.MALICIOUS]

    return DetectionReport(
        total_connections=len(samples),
        total_ips=len(by_ip),
        suspicious_ips=suspicious,
        malicious_ips=malicious,
        assessments=assessments,
    )


def load_samples(raw: str) -> list[ConnectionSample]:
    """Parse a JSON array of connection objects into ``ConnectionSample``s."""
    data = json.loads(raw)
    if not isinstance(data, list):
        raise ValueError("connection snapshot must be a JSON array of objects")

    allowed = {f for f in ConnectionSample.__annotations__}
    samples: list[ConnectionSample] = []
    for i, item in enumerate(data):
        if not isinstance(item, dict):
            raise ValueError(f"connection[{i}] must be an object")
        unknown = set(item) - allowed
        if unknown:
            raise ValueError(f"connection[{i}] has unknown field(s): {sorted(unknown)}")
        try:
            samples.append(
                ConnectionSample(
                    client_ip=str(item["client_ip"]),
                    age_seconds=float(item["age_seconds"]),
                    bytes_received=int(item["bytes_received"]),
                    request_complete=bool(item["request_complete"]),
                    idle_seconds=float(item["idle_seconds"]),
                )
            )
        except KeyError as exc:
            raise ValueError(f"connection[{i}] missing field: {exc.args[0]}") from exc
    return samples


def report_to_dict(report: DetectionReport) -> dict[str, object]:
    """Serialise a ``DetectionReport`` to plain JSON-compatible data."""
    return {
        "total_connections": report.total_connections,
        "total_ips": report.total_ips,
        "attack_detected": report.attack_detected,
        "suspicious_ips": report.suspicious_ips,
        "malicious_ips": report.malicious_ips,
        "assessments": [{**asdict(a), "verdict": a.verdict.value} for a in report.assessments],
    }


# --------------------------------------------------------------------------- #
# Mitigation configuration generators
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class MitigationParams:
    """Tunables shared by the hardening-config generators."""

    header_timeout: int = 10
    body_timeout: int = 30
    max_connections_per_ip: int = 20
    request_rate_per_minute: int = 120

    def __post_init__(self) -> None:
        for name in (
            "header_timeout",
            "body_timeout",
            "max_connections_per_ip",
            "request_rate_per_minute",
        ):
            if getattr(self, name) <= 0:
                raise ValueError(f"{name} must be positive")


def _nginx_config(p: MitigationParams) -> str:
    rate_per_second = max(1, round(p.request_rate_per_minute / 60))
    return f"""# nginx slow-HTTP hardening (place inside http {{ }})
# Time a client may take to send the full request header / body.
client_header_timeout {p.header_timeout}s;
client_body_timeout {p.body_timeout}s;
send_timeout {p.body_timeout}s;
keepalive_timeout 15s;

# Cap concurrent connections and request rate per client IP.
limit_conn_zone $binary_remote_addr zone=sl_conn:10m;
limit_req_zone $binary_remote_addr zone=sl_req:10m rate={rate_per_second}r/s;

server {{
    limit_conn sl_conn {p.max_connections_per_ip};
    limit_req zone=sl_req burst={rate_per_second * 2} nodelay;
    limit_req_status 429;
    limit_conn_status 429;
}}
"""


def _apache_config(p: MitigationParams) -> str:
    return f"""# Apache slow-HTTP hardening
# Requires mod_reqtimeout (bundled) and, for per-IP caps, mod_qos.
<IfModule mod_reqtimeout.c>
    RequestReadTimeout header={p.header_timeout}-{p.header_timeout * 2},minrate=500
    RequestReadTimeout body={p.body_timeout},minrate=500
</IfModule>

Timeout {p.body_timeout}
KeepAliveTimeout 15

<IfModule mod_qos.c>
    QS_SrvMaxConnPerIP {p.max_connections_per_ip}
    QS_SrvMaxConnClose 70%
</IfModule>
"""


def _haproxy_config(p: MitigationParams) -> str:
    return f"""# HAProxy slow-HTTP hardening (frontend / defaults)
defaults
    timeout http-request {p.header_timeout}s
    timeout client {p.body_timeout}s
    timeout http-keep-alive 15s

frontend fe_main
    # Track per-IP connection and request rates in a stick-table.
    stick-table type ip size 100k expire 1m store conn_cur,http_req_rate(1m)
    http-request track-sc0 src
    tcp-request connection reject if {{ sc0_conn_cur gt {p.max_connections_per_ip} }}
    http-request deny deny_status 429 \\
        if {{ sc0_http_req_rate gt {p.request_rate_per_minute} }}
"""


_GENERATORS = {
    "nginx": _nginx_config,
    "apache": _apache_config,
    "haproxy": _haproxy_config,
}

SUPPORTED_SERVERS = tuple(_GENERATORS)


def generate_mitigation(server: str, params: MitigationParams | None = None) -> str:
    """Return hardening configuration text for the given server."""
    try:
        generator = _GENERATORS[server]
    except KeyError:
        raise ValueError(
            f"unsupported server {server!r}; choose from {list(SUPPORTED_SERVERS)}"
        ) from None
    return generator(params or MitigationParams())


# --------------------------------------------------------------------------- #
# Volumetric & amplification flood detection
# --------------------------------------------------------------------------- #

# UDP source ports commonly abused for reflection / amplification attacks.
AMPLIFIER_SERVICES: dict[int, str] = {
    19: "chargen",
    53: "dns",
    123: "ntp",
    161: "snmp",
    389: "cldap",
    1900: "ssdp",
    11211: "memcached",
}

_PROTOCOLS = ("tcp", "udp", "icmp")


class AttackType(str, Enum):
    """Classification of a volumetric flow finding."""

    SYN_FLOOD = "syn_flood"
    UDP_FLOOD = "udp_flood"
    ICMP_FLOOD = "icmp_flood"
    AMPLIFICATION = "amplification"


@dataclass(frozen=True)
class NetworkFlow:
    """Aggregated traffic from one source towards the protected target.

    Meant to be produced by netflow/sflow/conntrack/``tcpdump`` accounting on
    the network you protect. ``syn_only`` marks TCP flows that only ever sent
    SYNs (no completed handshake) - the SYN-flood signature.
    """

    protocol: str
    src_ip: str
    src_port: int
    dst_port: int
    packets: int
    bytes: int
    syn_only: bool = False
    window_seconds: float = 1.0

    def __post_init__(self) -> None:
        if self.protocol not in _PROTOCOLS:
            raise ValueError(f"protocol must be one of {list(_PROTOCOLS)}")
        if not self.src_ip:
            raise ValueError("src_ip cannot be empty")
        if self.packets < 0 or self.bytes < 0:
            raise ValueError("packets and bytes cannot be negative")
        if self.window_seconds <= 0:
            raise ValueError("window_seconds must be positive")

    @property
    def packets_per_second(self) -> float:
        return self.packets / self.window_seconds

    @property
    def bits_per_second(self) -> float:
        return self.bytes * 8 / self.window_seconds

    @property
    def avg_packet_bytes(self) -> float:
        if self.packets == 0:
            return 0.0
        return self.bytes / self.packets


@dataclass(frozen=True)
class FloodDetectorConfig:
    """Thresholds for the volumetric / amplification detector."""

    syn_pps: float = 500.0
    udp_pps: float = 1000.0
    icmp_pps: float = 500.0
    # A UDP flow from an amplifier source port with responses at least this
    # large (and above amplification_min_pps) is treated as reflected traffic.
    amplification_min_avg_bytes: float = 400.0
    amplification_min_pps: float = 50.0

    def __post_init__(self) -> None:
        for name in ("syn_pps", "udp_pps", "icmp_pps", "amplification_min_pps"):
            if getattr(self, name) <= 0:
                raise ValueError(f"{name} must be positive")


@dataclass
class FloodFinding:
    """A single flow classified as part of a volumetric attack."""

    attack_type: AttackType
    protocol: str
    src_ip: str
    src_port: int
    dst_port: int
    packets_per_second: float
    bits_per_second: float
    avg_packet_bytes: float
    severity: str
    detail: str
    service: str | None = None


@dataclass
class FloodReport:
    """Result of analysing a network-flow snapshot."""

    total_flows: int
    findings: list[FloodFinding]

    @property
    def attack_detected(self) -> bool:
        return bool(self.findings)


def _severity(ratio: float) -> str:
    if ratio >= 4:
        return "critical"
    if ratio >= 2:
        return "high"
    return "medium"


def _classify_flow(flow: NetworkFlow, config: FloodDetectorConfig) -> FloodFinding | None:
    """Classify a single flow, or return None when it looks benign."""
    pps = flow.packets_per_second

    if (
        flow.protocol == "udp"
        and flow.src_port in AMPLIFIER_SERVICES
        and flow.avg_packet_bytes >= config.amplification_min_avg_bytes
        and pps >= config.amplification_min_pps
    ):
        service = AMPLIFIER_SERVICES[flow.src_port]
        return FloodFinding(
            attack_type=AttackType.AMPLIFICATION,
            protocol=flow.protocol,
            src_ip=flow.src_ip,
            src_port=flow.src_port,
            dst_port=flow.dst_port,
            packets_per_second=pps,
            bits_per_second=flow.bits_per_second,
            avg_packet_bytes=flow.avg_packet_bytes,
            severity=_severity(flow.avg_packet_bytes / config.amplification_min_avg_bytes),
            detail=(
                f"{service} reflection: {flow.avg_packet_bytes:.0f} B/pkt responses "
                f"from UDP/{flow.src_port}"
            ),
            service=service,
        )

    if flow.protocol == "tcp" and flow.syn_only and pps >= config.syn_pps:
        return FloodFinding(
            attack_type=AttackType.SYN_FLOOD,
            protocol=flow.protocol,
            src_ip=flow.src_ip,
            src_port=flow.src_port,
            dst_port=flow.dst_port,
            packets_per_second=pps,
            bits_per_second=flow.bits_per_second,
            avg_packet_bytes=flow.avg_packet_bytes,
            severity=_severity(pps / config.syn_pps),
            detail=f"{pps:.0f} SYN/s with no completed handshake to port {flow.dst_port}",
        )

    if flow.protocol == "udp" and pps >= config.udp_pps:
        return FloodFinding(
            attack_type=AttackType.UDP_FLOOD,
            protocol=flow.protocol,
            src_ip=flow.src_ip,
            src_port=flow.src_port,
            dst_port=flow.dst_port,
            packets_per_second=pps,
            bits_per_second=flow.bits_per_second,
            avg_packet_bytes=flow.avg_packet_bytes,
            severity=_severity(pps / config.udp_pps),
            detail=f"{pps:.0f} UDP pkt/s to port {flow.dst_port}",
        )

    if flow.protocol == "icmp" and pps >= config.icmp_pps:
        return FloodFinding(
            attack_type=AttackType.ICMP_FLOOD,
            protocol=flow.protocol,
            src_ip=flow.src_ip,
            src_port=flow.src_port,
            dst_port=flow.dst_port,
            packets_per_second=pps,
            bits_per_second=flow.bits_per_second,
            avg_packet_bytes=flow.avg_packet_bytes,
            severity=_severity(pps / config.icmp_pps),
            detail=f"{pps:.0f} ICMP pkt/s",
        )

    return None


def detect_floods(
    flows: list[NetworkFlow],
    config: FloodDetectorConfig | None = None,
) -> FloodReport:
    """Classify a network-flow snapshot for volumetric / amplification attacks."""
    config = config or FloodDetectorConfig()
    findings = [f for f in (_classify_flow(flow, config) for flow in flows) if f is not None]
    findings.sort(key=lambda f: f.bits_per_second, reverse=True)
    return FloodReport(total_flows=len(flows), findings=findings)


def load_flows(raw: str) -> list[NetworkFlow]:
    """Parse a JSON array of flow objects into ``NetworkFlow``s."""
    data = json.loads(raw)
    if not isinstance(data, list):
        raise ValueError("flow snapshot must be a JSON array of objects")

    allowed = set(NetworkFlow.__annotations__)
    required = {"protocol", "src_ip", "src_port", "dst_port", "packets", "bytes"}
    flows: list[NetworkFlow] = []
    for i, item in enumerate(data):
        if not isinstance(item, dict):
            raise ValueError(f"flow[{i}] must be an object")
        unknown = set(item) - allowed
        if unknown:
            raise ValueError(f"flow[{i}] has unknown field(s): {sorted(unknown)}")
        missing = required - set(item)
        if missing:
            raise ValueError(f"flow[{i}] missing field(s): {sorted(missing)}")
        flows.append(
            NetworkFlow(
                protocol=str(item["protocol"]).lower(),
                src_ip=str(item["src_ip"]),
                src_port=int(item["src_port"]),
                dst_port=int(item["dst_port"]),
                packets=int(item["packets"]),
                bytes=int(item["bytes"]),
                syn_only=bool(item.get("syn_only", False)),
                window_seconds=float(item.get("window_seconds", 1.0)),
            )
        )
    return flows


def flood_report_to_dict(report: FloodReport) -> dict[str, object]:
    """Serialise a ``FloodReport`` to plain JSON-compatible data."""
    return {
        "total_flows": report.total_flows,
        "attack_detected": report.attack_detected,
        "findings": [{**asdict(f), "attack_type": f.attack_type.value} for f in report.findings],
    }


# --------------------------------------------------------------------------- #
# Network-layer mitigation (kernel / firewall)
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class NetworkMitigationParams:
    """Rate limits (per second) for the network-layer hardening generators."""

    syn_rate_per_second: int = 25
    udp_rate_per_second: int = 100
    icmp_rate_per_second: int = 10

    def __post_init__(self) -> None:
        for name in ("syn_rate_per_second", "udp_rate_per_second", "icmp_rate_per_second"):
            if getattr(self, name) <= 0:
                raise ValueError(f"{name} must be positive")


def _sysctl_config(p: NetworkMitigationParams) -> str:
    return """# Linux kernel hardening against SYN/flood attacks (/etc/sysctl.d/99-ddos.conf)
# Enable SYN cookies so the listen queue can't be exhausted by half-open SYNs.
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.tcp_synack_retries = 2
net.core.somaxconn = 4096
# Ignore ICMP broadcast/echo abuse and drop spoofed/martian packets.
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_source_route = 0
# Apply with: sysctl --system
"""


def _iptables_config(p: NetworkMitigationParams) -> str:
    return f"""# iptables rate-limiting against SYN/UDP/ICMP floods.
# Drop invalid packets outright.
iptables -A INPUT -m conntrack --ctstate INVALID -j DROP

# SYN flood: rate-limit new TCP connections, drop the excess.
iptables -A INPUT -p tcp --syn -m limit \\
    --limit {p.syn_rate_per_second}/second --limit-burst {p.syn_rate_per_second * 2} -j ACCEPT
iptables -A INPUT -p tcp --syn -j DROP

# UDP flood: rate-limit new UDP flows.
iptables -A INPUT -p udp -m limit \\
    --limit {p.udp_rate_per_second}/second --limit-burst {p.udp_rate_per_second * 2} -j ACCEPT
iptables -A INPUT -p udp -j DROP

# ICMP (ping) flood: rate-limit echo-requests.
iptables -A INPUT -p icmp --icmp-type echo-request -m limit \\
    --limit {p.icmp_rate_per_second}/second -j ACCEPT
iptables -A INPUT -p icmp --icmp-type echo-request -j DROP

# Reflection: never expose amplifiers (ntp/dns/memcached/ssdp/snmp) to the internet;
# block their UDP source ports inbound if you don't run those services.
iptables -A INPUT -p udp -m multiport --sports 19,123,1900,11211 -j DROP
"""


_NET_GENERATORS = {
    "linux-sysctl": _sysctl_config,
    "iptables": _iptables_config,
}

SUPPORTED_NET_TARGETS = tuple(_NET_GENERATORS)


def generate_network_mitigation(
    target: str,
    params: NetworkMitigationParams | None = None,
) -> str:
    """Return network-layer hardening configuration for the given target."""
    try:
        generator = _NET_GENERATORS[target]
    except KeyError:
        raise ValueError(
            f"unsupported target {target!r}; choose from {list(SUPPORTED_NET_TARGETS)}"
        ) from None
    return generator(params or NetworkMitigationParams())


# --------------------------------------------------------------------------- #
# Observability outputs (Prometheus + HTML) for the detectors
# --------------------------------------------------------------------------- #

_FLOOD_SEVERITY_RANK = {"medium": 1, "high": 2, "critical": 3}


def _prom_escape(value: str) -> str:
    """Escape a Prometheus label value (backslash, quote, newline)."""
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _slow_http_risk_level(report: DetectionReport) -> str:
    if report.malicious_ips:
        return "critical"
    if report.suspicious_ips:
        return "elevated"
    return "ok"


def _flood_risk_level(report: FloodReport) -> str:
    if not report.findings:
        return "ok"
    worst = max(_FLOOD_SEVERITY_RANK.get(f.severity, 0) for f in report.findings)
    return {3: "critical", 2: "high"}.get(worst, "elevated")


def render_detection_prometheus(report: DetectionReport) -> str:
    """Render a slow-HTTP ``DetectionReport`` as Prometheus text-exposition metrics."""
    lines = [
        "# HELP slowloris_defense_connections_total Connections in the analysed snapshot",
        "# TYPE slowloris_defense_connections_total gauge",
        f"slowloris_defense_connections_total {report.total_connections}",
        "# HELP slowloris_defense_ips_total Distinct client IPs analysed",
        "# TYPE slowloris_defense_ips_total gauge",
        f"slowloris_defense_ips_total {report.total_ips}",
        "# HELP slowloris_defense_attack_detected 1 if malicious IPs were found",
        "# TYPE slowloris_defense_attack_detected gauge",
        f"slowloris_defense_attack_detected {int(report.attack_detected)}",
        "# HELP slowloris_defense_flagged_ips Flagged client IPs by verdict",
        "# TYPE slowloris_defense_flagged_ips gauge",
        f'slowloris_defense_flagged_ips{{verdict="suspicious"}} {len(report.suspicious_ips)}',
        f'slowloris_defense_flagged_ips{{verdict="malicious"}} {len(report.malicious_ips)}',
        "# HELP slowloris_defense_ip_score Risk score per client IP",
        "# TYPE slowloris_defense_ip_score gauge",
    ]
    for a in report.assessments:
        ip = _prom_escape(a.client_ip)
        lines.append(
            f'slowloris_defense_ip_score{{ip="{ip}",verdict="{a.verdict.value}"}} {a.score}'
        )
    return "\n".join(lines) + "\n"


def render_flood_prometheus(report: FloodReport) -> str:
    """Render a ``FloodReport`` as Prometheus text-exposition metrics."""
    by_type: dict[str, int] = {}
    for f in report.findings:
        by_type[f.attack_type.value] = by_type.get(f.attack_type.value, 0) + 1
    max_bps = max((f.bits_per_second for f in report.findings), default=0.0)

    lines = [
        "# HELP slowloris_defense_flows_total Flows in the analysed snapshot",
        "# TYPE slowloris_defense_flows_total gauge",
        f"slowloris_defense_flows_total {report.total_flows}",
        "# HELP slowloris_defense_attack_detected 1 if any flood finding was raised",
        "# TYPE slowloris_defense_attack_detected gauge",
        f"slowloris_defense_attack_detected {int(report.attack_detected)}",
        "# HELP slowloris_defense_flood_findings_total Number of offending flows",
        "# TYPE slowloris_defense_flood_findings_total gauge",
        f"slowloris_defense_flood_findings_total {len(report.findings)}",
        "# HELP slowloris_defense_flood_by_type Offending flows by attack type",
        "# TYPE slowloris_defense_flood_by_type gauge",
    ]
    for attack_type, count in sorted(by_type.items()):
        lines.append(f'slowloris_defense_flood_by_type{{type="{attack_type}"}} {count}')
    lines.append("# HELP slowloris_defense_flood_max_bps Peak bits/sec across offending flows")
    lines.append("# TYPE slowloris_defense_flood_max_bps gauge")
    lines.append(f"slowloris_defense_flood_max_bps {max_bps:.0f}")
    return "\n".join(lines) + "\n"


_HTML_STYLE = (
    "body{font-family:system-ui,sans-serif;margin:2rem;color:#111}"
    "table{border-collapse:collapse;margin-top:1rem}"
    "th,td{border:1px solid #ccc;padding:4px 10px;text-align:left}"
    ".critical{color:#b00020;font-weight:bold}.high{color:#c05600;font-weight:bold}"
    ".elevated{color:#c05600}.medium{color:#c05600}.ok{color:#0a7d33}"
)


def _html_page(title: str, body: str) -> str:
    return (
        "<!doctype html><html><head><meta charset='utf-8'>"
        f"<title>{escape(title)}</title><style>{_HTML_STYLE}</style></head><body>"
        f"<h1>{escape(title)}</h1>{body}</body></html>"
    )


def render_detection_html(report: DetectionReport) -> str:
    """Render a self-contained HTML report for a slow-HTTP ``DetectionReport``."""
    risk = _slow_http_risk_level(report)
    rows = []
    for a in report.assessments:
        reasons = escape("; ".join(a.reasons)) if a.reasons else "-"
        rows.append(
            f"<tr><td>{escape(a.client_ip)}</td>"
            f'<td class="{a.verdict.value}">{a.verdict.value}</td>'
            f"<td>{a.score}</td><td>{a.total_connections}</td>"
            f"<td>{a.slow_connections}</td><td>{a.stalled_connections}</td>"
            f"<td>{reasons}</td></tr>"
        )
    body = (
        f'<p>Overall risk: <span class="{risk}">{risk}</span></p>'
        f"<ul><li><b>Connections</b>: {report.total_connections}</li>"
        f"<li><b>Distinct IPs</b>: {report.total_ips}</li>"
        f"<li><b>Suspicious</b>: {len(report.suspicious_ips)}</li>"
        f"<li><b>Malicious</b>: {len(report.malicious_ips)}</li></ul>"
        "<table><tr><th>Client IP</th><th>Verdict</th><th>Score</th>"
        "<th>Conns</th><th>Slow</th><th>Stalled</th><th>Reasons</th></tr>"
        f"{''.join(rows)}</table>"
    )
    return _html_page("Slow-HTTP detection report", body)


def render_flood_html(report: FloodReport) -> str:
    """Render a self-contained HTML report for a ``FloodReport``."""
    risk = _flood_risk_level(report)
    rows = []
    for f in report.findings:
        service = escape(f.service) if f.service else "-"
        rows.append(
            f'<tr><td class="{f.severity}">{f.attack_type.value}</td>'
            f"<td>{f.severity}</td><td>{escape(f.src_ip)}</td>"
            f"<td>{escape(f.protocol)}/{f.src_port}</td><td>{f.dst_port}</td>"
            f"<td>{f.packets_per_second:.0f}</td><td>{f.bits_per_second:.0f}</td>"
            f"<td>{service}</td><td>{escape(f.detail)}</td></tr>"
        )
    body = (
        f'<p>Overall risk: <span class="{risk}">{risk}</span></p>'
        f"<ul><li><b>Flows</b>: {report.total_flows}</li>"
        f"<li><b>Findings</b>: {len(report.findings)}</li></ul>"
        "<table><tr><th>Attack</th><th>Severity</th><th>Source IP</th>"
        "<th>Proto/SrcPort</th><th>DstPort</th><th>pkt/s</th><th>bit/s</th>"
        "<th>Service</th><th>Detail</th></tr>"
        f"{''.join(rows)}</table>"
    )
    return _html_page("Volumetric / amplification detection report", body)


# --------------------------------------------------------------------------- #
# Configuration audit (find hardening gaps in an existing server config)
# --------------------------------------------------------------------------- #

_SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


_DURATION_UNITS = {"ms": 0.001, "s": 1.0, "m": 60.0, "h": 3600.0, "d": 86400.0}


def _parse_duration(token: str, unit_default: str) -> float | None:
    """Parse a directive time token (e.g. ``10s``, ``500ms``, ``30``) to seconds."""
    match = re.fullmatch(r"(\d+)(ms|s|m|h|d)?", token.strip())
    if not match:
        return None
    return int(match.group(1)) * _DURATION_UNITS[match.group(2) or unit_default]


@dataclass(frozen=True)
class HardeningCheck:
    """A single directive we expect to see in a hardened server config.

    ``pattern`` decides presence. When ``value_pattern`` is set its first capture
    group is parsed and compared against ``max_value``: a present directive whose
    value exceeds the bound is reported as ``weak`` rather than ``ok``.
    """

    id: str
    pattern: str
    severity: str
    description: str
    remediation: str
    value_pattern: str | None = None
    value_kind: str | None = None  # "duration" | "count"
    max_value: float | None = None
    duration_unit_default: str = "s"
    weak_remediation: str | None = None


@dataclass
class AuditFinding:
    """Result of one hardening check against a config.

    ``status`` is ``ok`` (present and adequate), ``missing`` (directive absent),
    or ``weak`` (present but the value is too permissive). ``passed`` is a
    convenience alias for ``status == "ok"``.
    """

    id: str
    severity: str
    description: str
    remediation: str
    passed: bool
    status: str
    observed: str | None = None


@dataclass
class AuditReport:
    """Outcome of auditing a server config for slow-HTTP hardening."""

    server: str
    total_checks: int
    passed: int
    findings: list[AuditFinding]

    @property
    def gaps(self) -> list[AuditFinding]:
        return [f for f in self.findings if not f.passed]

    @property
    def missing(self) -> list[AuditFinding]:
        return [f for f in self.findings if f.status == "missing"]

    @property
    def weak(self) -> list[AuditFinding]:
        return [f for f in self.findings if f.status == "weak"]


_NGINX_CHECKS = (
    HardeningCheck(
        "client_header_timeout",
        r"client_header_timeout\s+\d",
        "high",
        "Header read timeout limits how long a client may dribble request headers.",
        "Add `client_header_timeout 10s;` to the http block.",
        value_pattern=r"client_header_timeout\s+(\d+(?:ms|s|m|h)?)",
        value_kind="duration",
        max_value=30.0,
        weak_remediation="Lower `client_header_timeout` to <=30s (e.g. 10s).",
    ),
    HardeningCheck(
        "client_body_timeout",
        r"client_body_timeout\s+\d",
        "high",
        "Body read timeout bounds slow request-body attacks.",
        "Add `client_body_timeout 30s;`.",
        value_pattern=r"client_body_timeout\s+(\d+(?:ms|s|m|h)?)",
        value_kind="duration",
        max_value=60.0,
        weak_remediation="Lower `client_body_timeout` to <=60s (e.g. 30s).",
    ),
    HardeningCheck(
        "limit_conn",
        r"limit_conn\s+\S+\s+\d",
        "high",
        "Per-IP connection cap blunts slowloris connection hoarding.",
        "Define `limit_conn_zone` and add `limit_conn <zone> 20;`.",
        value_pattern=r"limit_conn\s+\S+\s+(\d+)",
        value_kind="count",
        max_value=100.0,
        weak_remediation="Lower the `limit_conn` per-IP cap to <=100 (e.g. 20).",
    ),
    HardeningCheck(
        "limit_req",
        r"limit_req\s+zone=",
        "medium",
        "Per-IP request-rate limit throttles HTTP floods.",
        "Define `limit_req_zone` and add `limit_req zone=<zone> burst=... nodelay;`.",
    ),
    HardeningCheck(
        "send_timeout",
        r"send_timeout\s+\d",
        "medium",
        "Send timeout drops clients that read responses too slowly.",
        "Add `send_timeout 30s;`.",
        value_pattern=r"send_timeout\s+(\d+(?:ms|s|m|h)?)",
        value_kind="duration",
        max_value=60.0,
        weak_remediation="Lower `send_timeout` to <=60s (e.g. 30s).",
    ),
    HardeningCheck(
        "keepalive_timeout",
        r"keepalive_timeout\s+\d",
        "low",
        "A short keep-alive timeout frees idle connections sooner.",
        "Add `keepalive_timeout 15s;`.",
        value_pattern=r"keepalive_timeout\s+(\d+(?:ms|s|m|h)?)",
        value_kind="duration",
        max_value=65.0,
        weak_remediation="Lower `keepalive_timeout` to <=65s (e.g. 15s).",
    ),
)

_APACHE_CHECKS = (
    HardeningCheck(
        "reqtimeout",
        r"RequestReadTimeout",
        "high",
        "mod_reqtimeout bounds how long headers/body may take to arrive.",
        "Enable mod_reqtimeout and set `RequestReadTimeout header=10-20,minrate=500`.",
    ),
    HardeningCheck(
        "conn_per_ip",
        r"QS_SrvMaxConnPerIP|MaxConnPerIP",
        "high",
        "Per-IP connection cap (mod_qos / mod_limitipconn) blunts connection hoarding.",
        "Enable mod_qos and set `QS_SrvMaxConnPerIP 20`.",
        value_pattern=r"(?:QS_SrvMaxConnPerIP|MaxConnPerIP)\s+(\d+)",
        value_kind="count",
        max_value=100.0,
        weak_remediation="Lower the per-IP connection cap to <=100 (e.g. 20).",
    ),
    HardeningCheck(
        "timeout",
        r"^\s*Timeout\s+\d",
        "medium",
        "The global Timeout bounds slow request/response phases.",
        "Set `Timeout 30`.",
        value_pattern=r"^\s*Timeout\s+(\d+)",
        value_kind="duration",
        max_value=60.0,
        weak_remediation="Lower `Timeout` to <=60 seconds (e.g. 30).",
    ),
    HardeningCheck(
        "keepalive_timeout",
        r"KeepAliveTimeout\s+\d",
        "low",
        "A short KeepAliveTimeout frees idle connections sooner.",
        "Set `KeepAliveTimeout 15`.",
        value_pattern=r"KeepAliveTimeout\s+(\d+)",
        value_kind="duration",
        max_value=65.0,
        weak_remediation="Lower `KeepAliveTimeout` to <=65 seconds (e.g. 15).",
    ),
)

_HAPROXY_CHECKS = (
    HardeningCheck(
        "timeout_http_request",
        r"timeout\s+http-request",
        "high",
        "`timeout http-request` caps how long the full request may take to arrive.",
        "Add `timeout http-request 10s` to defaults/frontend.",
        value_pattern=r"timeout\s+http-request\s+(\d+(?:ms|s|m|h)?)",
        value_kind="duration",
        max_value=30.0,
        duration_unit_default="ms",
        weak_remediation="Lower `timeout http-request` to <=30s (e.g. 10s).",
    ),
    HardeningCheck(
        "conn_limit",
        r"sc0_conn_cur|maxconn\s+\d",
        "high",
        "A per-IP stick-table connection limit (or maxconn) caps concurrency.",
        "Track src in a stick-table and reject when `sc0_conn_cur` exceeds a cap.",
    ),
    HardeningCheck(
        "timeout_client",
        r"timeout\s+client",
        "medium",
        "`timeout client` drops idle/slow client connections.",
        "Add `timeout client 30s`.",
        value_pattern=r"timeout\s+client\s+(\d+(?:ms|s|m|h)?)",
        value_kind="duration",
        max_value=60.0,
        duration_unit_default="ms",
        weak_remediation="Lower `timeout client` to <=60s (e.g. 30s).",
    ),
    HardeningCheck(
        "timeout_keep_alive",
        r"timeout\s+http-keep-alive",
        "low",
        "A short keep-alive timeout frees idle connections sooner.",
        "Add `timeout http-keep-alive 15s`.",
        value_pattern=r"timeout\s+http-keep-alive\s+(\d+(?:ms|s|m|h)?)",
        value_kind="duration",
        max_value=65.0,
        duration_unit_default="ms",
        weak_remediation="Lower `timeout http-keep-alive` to <=65s (e.g. 15s).",
    ),
)

_AUDIT_CHECKS = {
    "nginx": _NGINX_CHECKS,
    "apache": _APACHE_CHECKS,
    "haproxy": _HAPROXY_CHECKS,
}


_AUDIT_FLAGS = re.IGNORECASE | re.MULTILINE


def _evaluate_check(check: HardeningCheck, config_text: str) -> AuditFinding:
    status = "ok"
    observed: str | None = None
    remediation = check.remediation

    if re.search(check.pattern, config_text, _AUDIT_FLAGS) is None:
        status = "missing"
    elif check.value_pattern is not None and check.max_value is not None:
        match = re.search(check.value_pattern, config_text, _AUDIT_FLAGS)
        if match is not None:
            token = match.group(1)
            if check.value_kind == "duration":
                value = _parse_duration(token, check.duration_unit_default)
            else:
                value = float(token)
            if value is not None and value > check.max_value:
                status = "weak"
                observed = token
                remediation = check.weak_remediation or check.remediation

    return AuditFinding(
        id=check.id,
        severity=check.severity,
        description=check.description,
        remediation=remediation,
        passed=status == "ok",
        status=status,
        observed=observed,
    )


def audit_config(server: str, config_text: str) -> AuditReport:
    """Check an existing server config for slow-HTTP hardening gaps."""
    try:
        checks = _AUDIT_CHECKS[server]
    except KeyError:
        raise ValueError(
            f"unsupported server {server!r}; choose from {list(_AUDIT_CHECKS)}"
        ) from None

    findings = [_evaluate_check(c, config_text) for c in checks]
    passed = sum(1 for f in findings if f.passed)
    return AuditReport(
        server=server,
        total_checks=len(findings),
        passed=passed,
        findings=findings,
    )


def audit_report_to_dict(report: AuditReport) -> dict[str, object]:
    """Serialise an ``AuditReport`` to plain JSON-compatible data."""
    return {
        "server": report.server,
        "total_checks": report.total_checks,
        "passed": report.passed,
        "gaps": len(report.gaps),
        "missing": len(report.missing),
        "weak": len(report.weak),
        "findings": [asdict(f) for f in report.findings],
    }


def audit_has_gap_at_or_above(report: AuditReport, min_severity: str) -> bool:
    """True if any failing check is at least ``min_severity`` severe."""
    threshold = _SEVERITY_RANK[min_severity]
    return any(_SEVERITY_RANK.get(f.severity, 0) >= threshold for f in report.gaps)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


@click.group(help="Detect and mitigate slow-HTTP (slowloris) attacks.")
@click.version_option(version=__version__)
def cli() -> None:
    pass


@cli.command("detect")
@click.option(
    "--input",
    "input_path",
    type=click.Path(exists=True, dir_okay=False),
    default=None,
    help="JSON connection snapshot to analyse (default: read from stdin)",
)
@click.option(
    "--report",
    "report_path",
    type=click.Path(dir_okay=False, writable=True),
    default=None,
    help="Write the JSON detection report to this path (default: stdout)",
)
@click.option("--min-age", type=float, default=DetectorConfig.min_age_seconds, show_default=True)
@click.option(
    "--slow-bps",
    type=float,
    default=DetectorConfig.slow_bytes_per_second,
    show_default=True,
    help="Bytes/sec at or below which an incomplete request is 'slow'",
)
@click.option(
    "--max-conns",
    type=int,
    default=DetectorConfig.max_connections_per_ip,
    show_default=True,
    help="Concurrent connections per IP above which it is suspicious",
)
@click.option(
    "--max-idle",
    type=float,
    default=DetectorConfig.max_idle_seconds,
    show_default=True,
)
@click.option(
    "--report-html",
    "html_path",
    type=click.Path(dir_okay=False, writable=True),
    default=None,
    help="Write a self-contained HTML detection report to this path",
)
@click.option(
    "--report-prometheus",
    "prometheus_path",
    type=click.Path(dir_okay=False, writable=True),
    default=None,
    help="Write Prometheus text-exposition metrics to this path",
)
def detect_cmd(
    input_path: str | None,
    report_path: str | None,
    min_age: float,
    slow_bps: float,
    max_conns: int,
    max_idle: float,
    html_path: str | None,
    prometheus_path: str | None,
) -> None:
    """Analyse a connection snapshot; exit non-zero if an attack is detected."""
    raw = Path(input_path).read_text() if input_path else sys.stdin.read()
    samples = load_samples(raw)
    config = DetectorConfig(
        min_age_seconds=min_age,
        slow_bytes_per_second=slow_bps,
        max_connections_per_ip=max_conns,
        max_idle_seconds=max_idle,
    )
    report = detect(samples, config)
    payload = json.dumps(report_to_dict(report), indent=2)

    if html_path:
        Path(html_path).write_text(render_detection_html(report))
    if prometheus_path:
        Path(prometheus_path).write_text(render_detection_prometheus(report))

    if report_path:
        Path(report_path).write_text(payload + "\n")
        log.info(
            "detection complete",
            malicious=len(report.malicious_ips),
            suspicious=len(report.suspicious_ips),
            report=report_path,
        )
    elif not (html_path or prometheus_path):
        click.echo(payload)

    if report.attack_detected:
        raise SystemExit(1)


@cli.command("harden")
@click.argument("server", type=click.Choice(SUPPORTED_SERVERS))
@click.option(
    "--header-timeout", type=int, default=MitigationParams.header_timeout, show_default=True
)
@click.option("--body-timeout", type=int, default=MitigationParams.body_timeout, show_default=True)
@click.option(
    "--max-conns",
    type=int,
    default=MitigationParams.max_connections_per_ip,
    show_default=True,
)
@click.option(
    "--rate-per-minute",
    type=int,
    default=MitigationParams.request_rate_per_minute,
    show_default=True,
)
@click.option(
    "--output",
    "output_path",
    type=click.Path(dir_okay=False, writable=True),
    default=None,
    help="Write the config to this path (default: stdout)",
)
def harden_cmd(
    server: str,
    header_timeout: int,
    body_timeout: int,
    max_conns: int,
    rate_per_minute: int,
    output_path: str | None,
) -> None:
    """Print hardening configuration for SERVER (nginx, apache, haproxy)."""
    params = MitigationParams(
        header_timeout=header_timeout,
        body_timeout=body_timeout,
        max_connections_per_ip=max_conns,
        request_rate_per_minute=rate_per_minute,
    )
    config = generate_mitigation(server, params)
    if output_path:
        Path(output_path).write_text(config)
        log.info("wrote mitigation config", server=server, output=output_path)
    else:
        click.echo(config)


@cli.command("detect-flood")
@click.option(
    "--input",
    "input_path",
    type=click.Path(exists=True, dir_okay=False),
    default=None,
    help="JSON network-flow snapshot to analyse (default: read from stdin)",
)
@click.option(
    "--report",
    "report_path",
    type=click.Path(dir_okay=False, writable=True),
    default=None,
    help="Write the JSON flood report to this path (default: stdout)",
)
@click.option("--syn-pps", type=float, default=FloodDetectorConfig.syn_pps, show_default=True)
@click.option("--udp-pps", type=float, default=FloodDetectorConfig.udp_pps, show_default=True)
@click.option("--icmp-pps", type=float, default=FloodDetectorConfig.icmp_pps, show_default=True)
@click.option(
    "--amp-bytes",
    type=float,
    default=FloodDetectorConfig.amplification_min_avg_bytes,
    show_default=True,
    help="Min avg response size (bytes/pkt) for an amplifier flow to count",
)
@click.option(
    "--amp-pps",
    type=float,
    default=FloodDetectorConfig.amplification_min_pps,
    show_default=True,
)
@click.option(
    "--report-html",
    "html_path",
    type=click.Path(dir_okay=False, writable=True),
    default=None,
    help="Write a self-contained HTML flood report to this path",
)
@click.option(
    "--report-prometheus",
    "prometheus_path",
    type=click.Path(dir_okay=False, writable=True),
    default=None,
    help="Write Prometheus text-exposition metrics to this path",
)
def detect_flood_cmd(
    input_path: str | None,
    report_path: str | None,
    syn_pps: float,
    udp_pps: float,
    icmp_pps: float,
    amp_bytes: float,
    amp_pps: float,
    html_path: str | None,
    prometheus_path: str | None,
) -> None:
    """Analyse a flow snapshot for volumetric/amplification attacks; exit 1 if found."""
    raw = Path(input_path).read_text() if input_path else sys.stdin.read()
    flows = load_flows(raw)
    config = FloodDetectorConfig(
        syn_pps=syn_pps,
        udp_pps=udp_pps,
        icmp_pps=icmp_pps,
        amplification_min_avg_bytes=amp_bytes,
        amplification_min_pps=amp_pps,
    )
    report = detect_floods(flows, config)
    payload = json.dumps(flood_report_to_dict(report), indent=2)

    if html_path:
        Path(html_path).write_text(render_flood_html(report))
    if prometheus_path:
        Path(prometheus_path).write_text(render_flood_prometheus(report))

    if report_path:
        Path(report_path).write_text(payload + "\n")
        log.info("flood analysis complete", findings=len(report.findings), report=report_path)
    elif not (html_path or prometheus_path):
        click.echo(payload)

    if report.attack_detected:
        raise SystemExit(1)


@cli.command("harden-net")
@click.argument("target", type=click.Choice(SUPPORTED_NET_TARGETS))
@click.option(
    "--syn-rate",
    type=int,
    default=NetworkMitigationParams.syn_rate_per_second,
    show_default=True,
    help="Accepted new SYNs per second (iptables)",
)
@click.option(
    "--udp-rate",
    type=int,
    default=NetworkMitigationParams.udp_rate_per_second,
    show_default=True,
)
@click.option(
    "--icmp-rate",
    type=int,
    default=NetworkMitigationParams.icmp_rate_per_second,
    show_default=True,
)
@click.option(
    "--output",
    "output_path",
    type=click.Path(dir_okay=False, writable=True),
    default=None,
    help="Write the config to this path (default: stdout)",
)
def harden_net_cmd(
    target: str,
    syn_rate: int,
    udp_rate: int,
    icmp_rate: int,
    output_path: str | None,
) -> None:
    """Print network-layer hardening for TARGET (linux-sysctl, iptables)."""
    params = NetworkMitigationParams(
        syn_rate_per_second=syn_rate,
        udp_rate_per_second=udp_rate,
        icmp_rate_per_second=icmp_rate,
    )
    config = generate_network_mitigation(target, params)
    if output_path:
        Path(output_path).write_text(config)
        log.info("wrote network mitigation config", target=target, output=output_path)
    else:
        click.echo(config)


@cli.command("audit")
@click.argument("server", type=click.Choice(SUPPORTED_SERVERS))
@click.argument("config_file", type=click.Path(exists=True, dir_okay=False))
@click.option(
    "--report",
    "report_path",
    type=click.Path(dir_okay=False, writable=True),
    default=None,
    help="Write the JSON audit report to this path (default: stdout)",
)
@click.option(
    "--fail-severity",
    type=click.Choice(["low", "medium", "high"]),
    default="high",
    show_default=True,
    help="Exit non-zero if any gap is at least this severe",
)
def audit_cmd(
    server: str,
    config_file: str,
    report_path: str | None,
    fail_severity: str,
) -> None:
    """Audit an existing SERVER CONFIG_FILE for slow-HTTP hardening gaps."""
    report = audit_config(server, Path(config_file).read_text())
    payload = json.dumps(audit_report_to_dict(report), indent=2)

    if report_path:
        Path(report_path).write_text(payload + "\n")
        log.info(
            "audit complete",
            server=server,
            passed=report.passed,
            gaps=len(report.gaps),
            report=report_path,
        )
    else:
        click.echo(payload)

    if audit_has_gap_at_or_above(report, fail_severity):
        raise SystemExit(1)


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
