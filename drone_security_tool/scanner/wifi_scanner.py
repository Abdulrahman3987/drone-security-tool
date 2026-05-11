"""
Wi-Fi scanner module responsible for enumerating nearby networks and
identifying drone-like SSIDs.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional

from utils.helpers import LOGGER, current_platform, run_command


DRONE_PATTERNS = [
    re.compile(r"TELLO[-_]", re.IGNORECASE),
    re.compile(r"DJI[-_]", re.IGNORECASE),
    re.compile(r"MAVIC", re.IGNORECASE),
    re.compile(r"PARROT", re.IGNORECASE),
    re.compile(r"ANA(FI)?", re.IGNORECASE),
    re.compile(r"SKYDIO", re.IGNORECASE),
]


@dataclass
class WiFiNetwork:
    ssid: str
    bssid: Optional[str] = None
    signal: Optional[int] = None
    security: str = "Unknown"
    channel: Optional[int] = None
    is_drone_like: bool = False
    extra: dict = field(default_factory=dict)


class WiFiScanner:
    """
    Lightweight Wi-Fi scanner that uses OS specific commands to discover networks.
    """

    def __init__(self) -> None:
        self.platform = current_platform()

    def scan_networks(self) -> List[WiFiNetwork]:
        LOGGER.info("Scanning Wi-Fi networks using %s backend", self.platform)
        if self.platform == "windows":
            networks = self._scan_windows()
        elif self.platform in {"linux", "mac"}:
            networks = self._scan_unix()
        else:
            LOGGER.warning("Unsupported platform %s for Wi-Fi scanning", self.platform)
            networks = []
        return [self._mark_drone_candidates(network) for network in networks]

    def _scan_windows(self) -> List[WiFiNetwork]:
        output = run_command(
            ["netsh", "wlan", "show", "networks", "mode=Bssid"], timeout=6
        )
        networks: List[WiFiNetwork] = []
        current: Optional[WiFiNetwork] = None
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("SSID"):
                _, ssid = line.split(":", 1)
                current = WiFiNetwork(ssid=ssid.strip())
                networks.append(current)
            elif line.startswith("Authentication") and current:
                current.security = line.split(":", 1)[1].strip()
            elif line.startswith("BSSID") and current:
                current.bssid = line.split(":", 1)[1].strip()
            elif line.startswith("Signal") and current:
                value = line.split(":", 1)[1].strip().rstrip("%")
                try:
                    current.signal = int(value)
                except ValueError:
                    current.signal = None
            elif line.startswith("Channel") and current:
                try:
                    current.channel = int(line.split(":", 1)[1].strip())
                except ValueError:
                    current.channel = None
        return networks

    def _scan_unix(self) -> List[WiFiNetwork]:
        # Prefer nmcli, fallback to airport/iwlist depending on platform.
        nmcli_output = run_command(["nmcli", "-t", "-f", "SSID,SECURITY,SIGNAL", "dev", "wifi"])
        networks: List[WiFiNetwork] = []
        if nmcli_output:
            for line in nmcli_output.splitlines():
                parts = line.split(":")
                if not parts or not parts[0]:
                    continue
                ssid = parts[0]
                security = parts[1] if len(parts) > 1 else "Unknown"
                signal = parts[2] if len(parts) > 2 else None
                try:
                    signal_value = int(signal) if signal else None
                except ValueError:
                    signal_value = None
                networks.append(
                    WiFiNetwork(
                        ssid=ssid,
                        security=security or "Unknown",
                        signal=signal_value,
                    )
                )
            return networks

        # iwlist fallback
        iwlist_output = run_command(["iwlist", "scanning"])
        if iwlist_output:
            current: Optional[WiFiNetwork] = None
            for line in iwlist_output.splitlines():
                line = line.strip()
                if "Cell" in line and "Address" in line:
                    if current:
                        networks.append(current)
                    bssid = line.split("Address:")[-1].strip()
                    current = WiFiNetwork(ssid="Unknown", bssid=bssid)
                elif "ESSID" in line and current:
                    current.ssid = line.split("ESSID:")[-1].strip().strip('"')
                elif "Channel" in line and current:
                    try:
                        current.channel = int(line.split("Channel")[-1].strip(": "))
                    except ValueError:
                        current.channel = None
                elif "Quality" in line and current:
                    # Format like Quality=70/100 Signal level=-40 dBm
                    if "Signal level" in line:
                        parts = line.split("Signal level=")
                        signal_part = parts[-1].split()[0]
                        try:
                            current.signal = int(signal_part.replace("dBm", ""))
                        except ValueError:
                            current.signal = None
            if current:
                networks.append(current)
        return networks

    def _mark_drone_candidates(self, network: WiFiNetwork) -> WiFiNetwork:
        ssid = network.ssid or ""
        network.is_drone_like = any(pattern.search(ssid) for pattern in DRONE_PATTERNS)
        return network

    def describe_networks(self, networks: List[WiFiNetwork]) -> str:
        if not networks:
            return "No Wi-Fi networks detected."
        lines = []
        for net in networks:
            risk = " (drone-like)" if net.is_drone_like else ""
            security = net.security or "Unknown"
            lines.append(f"- {net.ssid} [{security}]{risk}")
        return "\n".join(lines)
