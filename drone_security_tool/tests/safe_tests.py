"""
Safe, non-invasive security tests for drones.
"""
from __future__ import annotations

import socket
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Optional

from utils.helpers import LOGGER


@dataclass
class PingTestResult:
    success: bool
    packet_loss: Optional[float]
    details: str


@dataclass
class LatencyResult:
    average_ms: Optional[float]
    samples: int


@dataclass
class PacketSendResult:
    success: bool
    bytes_sent: int
    note: str


@dataclass
class SafeTestResults:
    ping: PingTestResult
    latency: LatencyResult
    packet: PacketSendResult


class SafeTestRunner:
    """
    Execute non-destructive tests such as ping and latency checks.
    """

    def __init__(self, test_port: int = 8889) -> None:
        self.test_port = test_port

    def run_all(self, ip_address: str) -> SafeTestResults:
        ping = self.run_ping(ip_address)
        latency = self.measure_latency(ip_address)
        packet = self.send_small_packet(ip_address)
        return SafeTestResults(ping=ping, latency=latency, packet=packet)

    def run_ping(self, ip_address: str, count: int = 3) -> PingTestResult:
        LOGGER.info("Running ping test to %s", ip_address)
        command = ["ping", ip_address]
        if sys.platform.startswith("win"):
            command.extend(["-n", str(count)])
        else:
            command.extend(["-c", str(count)])
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
        except (FileNotFoundError, subprocess.SubprocessError) as exc:
            return PingTestResult(success=False, packet_loss=None, details=str(exc))
        output = result.stdout
        packet_loss = self._parse_packet_loss(output)
        success = result.returncode == 0
        return PingTestResult(success=success, packet_loss=packet_loss, details=output.strip())

    def measure_latency(self, ip_address: str, attempts: int = 4) -> LatencyResult:
        LOGGER.info("Measuring latency to %s", ip_address)
        samples = []
        for _ in range(attempts):
            start = time.perf_counter()
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(1.0)
                sock.sendto(b"\x00", (ip_address, self.test_port))
                samples.append((time.perf_counter() - start) * 1000)
            except OSError:
                break
            finally:
                sock.close()
        average = sum(samples) / len(samples) if samples else None
        return LatencyResult(average_ms=average, samples=len(samples))

    def send_small_packet(self, ip_address: str) -> PacketSendResult:
        LOGGER.info("Sending small diagnostic packet to %s:%s", ip_address, self.test_port)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1.0)
        payload = b"hello-drone"
        try:
            sent = sock.sendto(payload, (ip_address, self.test_port))
            note = "Diagnostic packet sent (no movement commands)."
            return PacketSendResult(success=True, bytes_sent=sent, note=note)
        except OSError as exc:
            return PacketSendResult(success=False, bytes_sent=0, note=str(exc))
        finally:
            sock.close()

    def _parse_packet_loss(self, output: str) -> Optional[float]:
        marker = "loss"
        for line in output.splitlines():
            if marker in line.lower():
                numbers = [part for part in line.replace("%", " ").split() if part.isdigit()]
                if numbers:
                    try:
                        value = float(numbers[-1])
                        return value
                    except ValueError:
                        return None
        return None
