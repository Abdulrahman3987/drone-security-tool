"""
Data structures representing a drone fingerprint aggregated from scan modules.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from scanner.wifi_scanner import WiFiNetwork


@dataclass
class DroneFingerprint:
    model: Optional[str] = None
    wifi_security: Optional[str] = None
    wifi_network: Optional[WiFiNetwork] = None
    open_ports: List[int] = field(default_factory=list)
    protocols: List[str] = field(default_factory=list)
    firmware_hint: Optional[str] = None
    behavior_info: Optional[str] = None

    def update_wifi(self, networks: List[WiFiNetwork]) -> None:
        drone_networks = [net for net in networks if net.is_drone_like]
        if drone_networks:
            strongest = sorted(
                drone_networks,
                key=lambda n: n.signal or -100,
                reverse=True,
            )[0]
            self.wifi_network = strongest
            self.wifi_security = strongest.security
            if strongest.ssid.upper().startswith("TELLO"):
                self.model = "Ryze Tello"
            elif strongest.ssid.upper().startswith("DJI"):
                self.model = "DJI"
        elif networks and not self.wifi_network:
            self.wifi_network = networks[0]
            self.wifi_security = networks[0].security

    def update_ports(self, ports: List[int]) -> None:
        for port in ports:
            if port not in self.open_ports:
                self.open_ports.append(port)

    def update_protocols(self, protocols: List[str]) -> None:
        for proto in protocols:
            if proto not in self.protocols:
                self.protocols.append(proto)

    def summary(self) -> str:
        wifi = self.wifi_network.ssid if self.wifi_network else "Unknown SSID"
        security = self.wifi_security or "Unknown"
        ports = ", ".join(str(p) for p in sorted(self.open_ports)) or "None"
        protocols = ", ".join(self.protocols) or "Unknown"
        model = self.model or "Unknown Model"
        return (
            f"Model: {model}\n"
            f"Wi-Fi: {wifi} ({security})\n"
            f"Open Ports: {ports}\n"
            f"Protocols: {protocols}\n"
            f"Firmware Hint: {self.firmware_hint or 'Unknown'}"
        )
