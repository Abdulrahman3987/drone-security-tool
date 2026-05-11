"""
Fake drone scenario generator for offline testing.

Every call to FakeDroneScenario.generate() produces a completely
random (but realistic) set of scan results — different WiFi security,
ports, protocols, and network-health values each time.

The output types are identical to what real scanners return, so the
data flows through the same VulnerabilityEngine.analyze() pipeline
unchanged.  The score will reflect the actual random values rather than
always returning the same fixed result.
"""
from __future__ import annotations

import random
import string
from dataclasses import dataclass
from typing import List, Optional, Tuple

from scanner.fingerprint import DroneFingerprint
from scanner.port_scanner import PortStatus, PORT_RISKS
from scanner.protocol_detector import ProtocolObservation
from scanner.wifi_scanner import WiFiNetwork
from tests.safe_tests import (
    LatencyResult,
    PacketSendResult,
    PingTestResult,
    SafeTestResults,
)


# ---------------------------------------------------------------------------
# Reference data
# ---------------------------------------------------------------------------

_DRONE_MODELS: List[Tuple[str, str]] = [
    ("TELLO",    "Ryze Tello"),
    ("DJI-MINI", "DJI Mini 3"),
    ("DJI-AIR",  "DJI Air 2S"),
    ("DJI-FPV",  "DJI FPV"),
    ("MAVIC",    "DJI Mavic 3"),
    ("PARROT",   "Parrot Anafi"),
    ("SKYDIO",   "Skydio 2+"),
]

# (security_string, weight) — weight drives appearance frequency
_WIFI_PROFILES: List[Tuple[str, int]] = [
    ("Open",           15),   # 15 % – risky
    ("WEP",            10),   # 10 % – crackable
    ("WPA-Personal",   15),   # 15 % – weak
    ("WPA2-Personal",  40),   # 40 % – safe
    ("WPA3-Personal",  20),   # 20 % – strong
]

# (port, base_open_probability, service_label)
_PORT_TABLE: List[Tuple[int, float, str]] = [
    (8888,  0.20, "DJI Command"),
    (8889,  0.35, "DJI Command"),
    (8890,  0.40, "Telemetry/Video"),
    (8891,  0.38, "Telemetry/Video"),
    (4090,  0.28, "Custom Telemetry"),
    (11111, 0.42, "Tello Video Stream"),
    (14550, 0.25, "MAVLink Ground Control"),
]

# (protocol, base_probability)
_PROTO_TABLE: List[Tuple[str, float]] = [
    ("UDP",     0.70),
    ("TCP",     0.40),
    ("MAVLink", 0.30),
    ("DJI SDK", 0.25),
    ("Unknown", 0.28),
]

_PROTO_DESCRIPTIONS = {
    "UDP":     "Datagram-based control traffic, often unencrypted.",
    "TCP":     "Reliable socket traffic — may carry SDK commands.",
    "MAVLink": "MAVLink telemetry/control frames detected.",
    "DJI SDK": "DJI custom SDK messages observed.",
    "Unknown": "Unable to fingerprint protocol with limited capture.",
}

_PORT_RISK_EXTRA = {
    8888:  "Drone AP management port exposed.",
    11111: "Tello video stream exposed — Replay attack possible.",
    4090:  "Custom telemetry channel exposed — data may leak.",
}

_FIRMWARE_HINTS = [
    "v01.04.06.00", "v02.01.00.20", "v03.00.10.10",
    "v1.3.0.0", "v1.0.4 (EOL)", "Unknown",
]


# ---------------------------------------------------------------------------
# Result container (backward-compatible with old FakeDroneScan name)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class FakeDroneScan:
    """Holds all random scan data plus a display summary."""
    wifi: List[WiFiNetwork]
    ports: List[PortStatus]
    protocols: List[ProtocolObservation]
    fingerprint: DroneFingerprint
    tests: SafeTestResults
    description: str = ""


# ---------------------------------------------------------------------------
# Generator
# ---------------------------------------------------------------------------

class FakeDroneScenario:
    """
    Generates a random-but-realistic drone scan each time .generate() is called.

    Design:
    - WiFi security is drawn from a weighted distribution.
    - Each port has its own independent open probability (± Gaussian jitter),
      so the combination of open ports is unique every run.
    - MAVLink protocol probability increases when port 14550 is open.
    - Network health (loss, latency) uses tiered distributions:
        healthy drones are most common, degraded and severe appear occasionally.
    - Results span the full 0-100 risk range across many runs.
    """

    def __init__(self, seed: Optional[int] = None) -> None:
        # Use a fresh Random instance so the main process random state is unaffected.
        self._rng = random.Random(seed)

    # ------------------------------------------------------------------
    # Public
    # ------------------------------------------------------------------

    def generate(self) -> FakeDroneScan:
        """Return one fully randomised drone scan."""
        ssid_prefix, model_label = self._rng.choice(_DRONE_MODELS)
        suffix = "".join(
            self._rng.choices(string.ascii_uppercase + string.digits, k=4)
        )
        drone_name = f"{ssid_prefix}-{suffix}"
        fake_ip = (
            f"192.168.{self._rng.randint(1, 10)}.{self._rng.randint(1, 9)}"
        )

        wifi   = self._gen_wifi(drone_name)
        ports  = self._gen_ports()
        protos = self._gen_protocols(ports)
        tests  = self._gen_tests()

        open_ports  = [p.port for p in ports if p.is_open]
        proto_names = [o.protocol for o in protos]

        fp = DroneFingerprint(
            model=model_label,
            wifi_security=wifi.security,
            wifi_network=wifi,
            open_ports=open_ports,
            protocols=proto_names,
            firmware_hint=self._rng.choice(_FIRMWARE_HINTS),
            behavior_info=f"Fake scan — simulated target {fake_ip}",
        )

        description = self._build_description(
            drone_name, model_label, fake_ip, wifi, ports, protos, tests
        )

        return FakeDroneScan(
            wifi=[wifi],
            ports=ports,
            protocols=protos,
            fingerprint=fp,
            tests=tests,
            description=description,
        )

    # Backward-compatible alias used by legacy callers.
    @classmethod
    def build(cls, target_ip: str = "127.0.0.1") -> FakeDroneScan:
        return cls().generate()

    # ------------------------------------------------------------------
    # Internal generators
    # ------------------------------------------------------------------

    def _gen_wifi(self, ssid: str) -> WiFiNetwork:
        names, weights = zip(*_WIFI_PROFILES)
        security_str = self._rng.choices(names, weights=weights, k=1)[0]

        bssid = ":".join(f"{self._rng.randint(0, 255):02X}" for _ in range(6))
        signal = self._rng.randint(38, 97)
        channel = self._rng.choice([1, 6, 11, 36, 40, 44, 48, 149, 153])

        return WiFiNetwork(
            ssid=ssid,
            bssid=bssid,
            signal=signal,
            security=security_str,
            channel=channel,
            is_drone_like=True,
        )

    def _gen_ports(self) -> List[PortStatus]:
        results: List[PortStatus] = []
        for port, base_prob, service in _PORT_TABLE:
            # Gaussian jitter ±0.12 so the same port isn't always open/closed.
            prob = max(0.05, min(0.95, base_prob + self._rng.gauss(0, 0.12)))
            is_open = self._rng.random() < prob
            risk_msg = (
                PORT_RISKS.get(port)
                or _PORT_RISK_EXTRA.get(port)
                or f"Port {port} is reachable."
            )
            results.append(PortStatus(
                port=port,
                is_open=is_open,
                service=service,
                risk=risk_msg if is_open else None,
            ))
        return results

    def _gen_protocols(self, ports: List[PortStatus]) -> List[ProtocolObservation]:
        open_port_nums = {p.port for p in ports if p.is_open}
        # MAVLink more likely when port 14550 is already open
        mavlink_boost = 0.30 if 14550 in open_port_nums else 0.0

        detected: List[ProtocolObservation] = []
        for proto, base_prob in _PROTO_TABLE:
            prob = base_prob + (mavlink_boost if proto == "MAVLink" else 0.0)
            if self._rng.random() < min(prob, 0.95):
                detected.append(ProtocolObservation(
                    protocol=proto,
                    description=_PROTO_DESCRIPTIONS[proto],
                ))

        # Guarantee at least one protocol
        if not detected:
            detected.append(ProtocolObservation(
                protocol="UDP",
                description=_PROTO_DESCRIPTIONS["UDP"],
            ))
        return detected

    def _gen_tests(self) -> SafeTestResults:
        """
        Tiered packet-loss and latency distributions:
          Healthy  (80 % of runs): loss 0-8 %,   latency  20-80 ms
          Degraded (12 %):         loss 8-30 %,  latency  80-200 ms
          Severe    (8 %):         loss 30-80 %, latency 200-800 ms
        """
        tier = self._rng.random()
        if tier < 0.80:
            loss    = self._rng.uniform(0, 8)
            latency = self._rng.uniform(20, 80)
        elif tier < 0.92:
            loss    = self._rng.uniform(8, 30)
            latency = self._rng.uniform(80, 200)
        else:
            loss    = self._rng.uniform(30, 80)
            latency = self._rng.uniform(200, 800)

        loss    = round(loss, 1)
        latency = round(latency, 1)
        ping_ok = loss < 50
        diag_ok = loss < 40 and latency < 500

        return SafeTestResults(
            ping=PingTestResult(
                success=ping_ok,
                packet_loss=loss,
                details=f"4 packets, {loss:.1f}% lost",
            ),
            latency=LatencyResult(average_ms=latency, samples=4),
            packet=PacketSendResult(
                success=diag_ok,
                bytes_sent=11 if diag_ok else 0,
                note="hello-drone responded" if diag_ok else "no response",
            ),
        )

    # ------------------------------------------------------------------
    # Description string
    # ------------------------------------------------------------------

    def _build_description(
        self,
        drone_name: str,
        model_label: str,
        fake_ip: str,
        wifi: WiFiNetwork,
        ports: List[PortStatus],
        protos: List[ProtocolObservation],
        tests: SafeTestResults,
    ) -> str:
        open_ports  = [str(p.port) for p in ports if p.is_open]
        proto_names = [o.protocol for o in protos]
        loss    = tests.ping.packet_loss or 0.0
        latency = tests.latency.average_ms or 0.0

        lines = [
            "─" * 46,
            f"  Model        : {model_label} ({drone_name})",
            f"  Simulated IP : {fake_ip}",
            f"  Wi-Fi        : {wifi.ssid}  [{wifi.security}]"
            f"  Signal {wifi.signal}%  Ch{wifi.channel}",
            f"  Open ports   : {', '.join(open_ports) if open_ports else 'None'}",
            f"  Protocols    : {', '.join(proto_names)}",
            f"  Packet loss  : {loss:.1f}%",
            f"  Avg latency  : {latency:.1f} ms",
            f"  Diagnostic   : {'OK' if tests.packet.success else 'FAILED'}",
            "─" * 46,
        ]
        return "\n".join(lines)
