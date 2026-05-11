"""
AI feature extraction utilities.

This module converts raw scan/test results into a compact feature vector
that can later be used by ML models or transformer-based reasoning.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

from scanner.fingerprint import DroneFingerprint
from scanner.port_scanner import PortStatus
from scanner.wifi_scanner import WiFiNetwork
from scanner.protocol_detector import ProtocolObservation
from tests.safe_tests import SafeTestResults


@dataclass
class AnalysisFeatures:
    """
    Numeric/boolean features summarizing the drone's security posture.

    This is what ML models and advanced AI will consume later.
    """
    open_ports_count: int
    has_control_port: int
    has_telemetry_port: int
    has_video_port: int
    has_mavlink: int
    has_unknown_protocol: int
    wifi_security_level: int  # 0=open/none, 1=weak, 2=strong, -1=unknown
    ping_loss: float          # percentage, -1 if unknown
    avg_latency_ms: float     # -1 if unknown
    diag_success: int         # 1 if diagnostic packet succeeded, 0 otherwise

    def as_vector(self) -> list[float]:
        """Convert features into a simple list for ML models."""
        return [
            float(self.open_ports_count),
            float(self.has_control_port),
            float(self.has_telemetry_port),
            float(self.has_video_port),
            float(self.has_mavlink),
            float(self.has_unknown_protocol),
            float(self.wifi_security_level),
            float(self.ping_loss),
            float(self.avg_latency_ms),
            float(self.diag_success),
        ]

    def to_dict(self) -> dict[str, float]:
        """Convert features into a dict for ML inference alignment."""
        return {
            "open_ports_count": self.open_ports_count,
            "has_control_port": self.has_control_port,
            "has_telemetry_port": self.has_telemetry_port,
            "has_video_port": self.has_video_port,
            "has_mavlink": self.has_mavlink,
            "has_unknown_protocol": self.has_unknown_protocol,
            "wifi_security_level": self.wifi_security_level,
            "ping_loss": self.ping_loss,
            "avg_latency_ms": self.avg_latency_ms,
            "diag_success": self.diag_success,
        }


def _map_wifi_security(network: Optional[WiFiNetwork]) -> int:
    """
    Map Wi-Fi security description to a numeric level.

    0 = open / none
    1 = weak (WEP / unknown)
    2 = strong (WPA2 / WPA3)
    -1 = unknown / not seen
    """
    if not network or not network.security:
        return -1

    sec = network.security.lower()
    if "open" in sec or "none" in sec:
        return 0
    if "wpa2" in sec or "wpa3" in sec:
        return 2
    # everything else (WEP, WPA, etc.)
    return 1


def build_features(
    fingerprint: DroneFingerprint,
    wifi_data: List[WiFiNetwork],
    ports: List[PortStatus],
    protocols: List[ProtocolObservation],
    safe_tests: Optional[SafeTestResults] = None,
) -> AnalysisFeatures:
    """
    Aggregate all raw scan/test objects into a single AnalysisFeatures instance.
    """

    # ---- Ports ----
    open_ports = [p.port for p in ports if p.is_open]
    open_ports_count = len(open_ports)

    has_control_port = int(any(p in {8888, 8889, 14550} for p in open_ports))
    has_telemetry_port = int(any(p in {8890, 8891, 4090} for p in open_ports))
    has_video_port = int(11111 in open_ports)

    # ---- Protocols ----
    protos = {obs.protocol for obs in protocols}
    has_mavlink = int("MAVLink" in protos)
    has_unknown_protocol = int("Unknown" in protos or not protos)

    # ---- Wi-Fi ----
    # Prefer fingerprint.wifi_network if set, otherwise first scanned network
    candidate_wifi = fingerprint.wifi_network or (wifi_data[0] if wifi_data else None)
    wifi_security_level = _map_wifi_security(candidate_wifi)

    # ---- Safe tests ----
    ping_loss = -1.0
    avg_latency_ms = -1.0
    diag_success = 0

    if safe_tests:
        # Ping
        if safe_tests.ping and safe_tests.ping.packet_loss is not None:
            ping_loss = float(safe_tests.ping.packet_loss)
        # Latency
        if safe_tests.latency and safe_tests.latency.average_ms is not None:
            avg_latency_ms = float(safe_tests.latency.average_ms)
        # Diagnostic
        if safe_tests.packet:
            diag_success = 1 if safe_tests.packet.success else 0

    return AnalysisFeatures(
        open_ports_count=open_ports_count,
        has_control_port=has_control_port,
        has_telemetry_port=has_telemetry_port,
        has_video_port=has_video_port,
        has_mavlink=has_mavlink,
        has_unknown_protocol=has_unknown_protocol,
        wifi_security_level=wifi_security_level,
        ping_loss=ping_loss,
        avg_latency_ms=avg_latency_ms,
        diag_success=diag_success,
    )
