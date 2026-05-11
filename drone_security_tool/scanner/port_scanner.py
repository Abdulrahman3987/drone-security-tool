"""
Port scanner targeting common drone control interfaces.
"""
from __future__ import annotations

import socket
from dataclasses import dataclass
from typing import Iterable, List, Optional

from utils.helpers import LOGGER


DEFAULT_PORTS = [8888, 8889, 8890, 8891, 4090, 11111, 14550]
PORT_RISKS = {
    8889: "Default DJI control port (UDP) - commands could be spoofed.",
    8890: "Telemetry stream - exposed data may reveal position.",
    8891: "Video/telemetry - unencrypted stream possible.",
    11111: "Common Tello video stream port - exposed video may leak camera data.",
    14550: "MAVLink ground control channel.",
}


@dataclass
class PortStatus:
    port: int
    is_open: bool
    service: Optional[str] = None
    risk: Optional[str] = None


class PortScanner:
    """
    Simple TCP/UDP port scanner.
    """

    def __init__(self, timeout: float = 1.0) -> None:
        self.timeout = timeout

    def scan_ports(self, ip_address: str, ports: Optional[Iterable[int]] = None) -> List[PortStatus]:
        ports = list(ports or DEFAULT_PORTS)
        LOGGER.info("Scanning %s ports on %s", len(ports), ip_address)
        results: List[PortStatus] = []
        for port in ports:

            tcp_open = self._is_tcp_open(ip_address, port)
            udp_open = self._is_udp_open(ip_address, port)

            is_open = tcp_open or udp_open

            status = PortStatus(
                port=port,
                is_open=is_open,
                service=self._describe_port(port),
                risk=PORT_RISKS.get(port),
            )
            results.append(status)

        return results


    def _is_tcp_open(self, ip: str, port: int) -> bool:
        try:
            with socket.create_connection((ip, port), timeout=self.timeout):
                return True
        except (socket.timeout, ConnectionRefusedError, OSError):
            return False
        
    def _is_udp_open(self, ip: str, port: int) -> bool:  
          sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
          sock.settimeout(self.timeout)

          try:
        # Send a small packet
              sock.sendto(b"test", (ip, port))

        # Wait for ANY reply from fake drone or real drone
              data, _ = sock.recvfrom(1024)
              return True

          except Exception:
              return False
          finally:
            sock.close() 

    def _describe_port(self, port: int) -> str:
        if port in {8888, 8889}:
            return "DJI Command"
        if port in {8890, 8891}:
            return "Telemetry/Video"
        if port == 14550:
            return "MAVLink Ground Control"
        if port == 4090:
            return "Custom Telemetry"
        if port == 11111:
            return "Video Stream"
        return "Unknown"
