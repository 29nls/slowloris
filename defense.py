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
import sys
from dataclasses import asdict, dataclass, field
from enum import Enum
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
def detect_cmd(
    input_path: str | None,
    report_path: str | None,
    min_age: float,
    slow_bps: float,
    max_conns: int,
    max_idle: float,
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

    if report_path:
        Path(report_path).write_text(payload + "\n")
        log.info(
            "detection complete",
            malicious=len(report.malicious_ips),
            suspicious=len(report.suspicious_ips),
            report=report_path,
        )
    else:
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


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
