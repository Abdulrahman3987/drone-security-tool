"""
Protocol detector that attempts to identify the primary communication
protocols used by the drone.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional, Set

from utils.helpers import LOGGER


@dataclass
class ProtocolObservation:
    protocol: str
    description: str


class ProtocolDetector:
    """
    Attempt to capture a few packets and infer the protocol.
    """

    def __init__(self, interface: Optional[str] = None) -> None:
        self.interface = interface

    def detect_protocols(self, target_ip: str, duration: int = 6) -> List[ProtocolObservation]:
        protocols: Set[str] = set()
        LOGGER.info("Capturing packets targeting %s", target_ip)
        if self._scapy_available():
            protocols.update(self._capture_with_scapy(target_ip, duration))
        elif self._pyshark_available():
            protocols.update(self._capture_with_pyshark(target_ip, duration))
        else:
            LOGGER.warning("Neither scapy nor pyshark is available, protocol detection limited")
        if not protocols:
            protocols.add("Unknown")
        observations = [self._describe(proto) for proto in sorted(protocols)]
        return observations

    def _scapy_available(self) -> bool:
        try:
            import scapy.all  # noqa: F401

            return True
        except ImportError:
            return False

    def _pyshark_available(self) -> bool:
        try:
            import pyshark  # noqa: F401

            return True
        except ImportError:
            return False

    def _capture_with_scapy(self, target_ip: str, duration: int) -> Set[str]:
        from scapy.all import IP, TCP, UDP, sniff  # type: ignore

        detected: Set[str] = set()

        def _handler(packet):
            if IP in packet:
                ip_layer = packet[IP]
                if ip_layer.src != target_ip and ip_layer.dst != target_ip:
                    return
                if TCP in packet:
                    detected.add("TCP")
                if UDP in packet:
                    detected.add("UDP")
                    payload = bytes(packet[UDP].payload)[:2]
                    if payload and payload[0] == 0xFE:
                        detected.add("MAVLink")
                if packet.haslayer("Raw"):
                    raw = bytes(packet["Raw"])[:4]
                    if raw.startswith(b"DJI"):
                        detected.add("DJI SDK")

        sniff(
            filter=f"host {target_ip}",
            iface=self.interface,
            timeout=duration,
            prn=_handler,
            count=25,
            store=False,
        )
        return detected

    def _capture_with_pyshark(self, target_ip: str, duration: int) -> Set[str]:
        import pyshark

        detected: Set[str] = set()
        capture = pyshark.LiveCapture(
            interface=self.interface,
            bpf_filter=f"host {target_ip}",
        )
        try:
            for packet in capture.sniff_continuously(packet_count=20):
                layer_names = {layer.layer_name.upper() for layer in packet.layers}
                if "UDP" in layer_names:
                    detected.add("UDP")
                if "TCP" in layer_names:
                    detected.add("TCP")
                if "MAVLINK" in layer_names:
                    detected.add("MAVLink")
                if any("DJI" in layer.layer_name.upper() for layer in packet.layers):
                    detected.add("DJI SDK")
        finally:
            capture.close()
        return detected
    

    def analyze_pcap(self, pcap_path: str):
        """
        Offline mode:
        Analyze a PCAP file (ISOT dataset, or any capture)
        and return:
          - protocols detected
          - open ports inferred from packets
          - simple packet statistics
        """

        try:
            import pyshark
        except ImportError:
            raise RuntimeError("PyShark is required for offline PCAP analysis.")

        cap = pyshark.FileCapture(pcap_path)

        protocols = set()
        open_ports = set()
        packet_sizes = []
        intervals = []

        prev_time = None

        for pkt in cap:
            try:
                # ---- Protocol recognition ----
                layer_names = {layer.layer_name.upper() for layer in pkt.layers}

                if "UDP" in layer_names:
                    protocols.add("UDP")
                    if hasattr(pkt.udp, "dstport"):
                        open_ports.add(int(pkt.udp.dstport))
                if "TCP" in layer_names:
                    protocols.add("TCP")
                    if hasattr(pkt.tcp, "dstport"):
                        open_ports.add(int(pkt.tcp.dstport))
                if "MAVLINK" in layer_names:
                    protocols.add("MAVLink")
                if any("DJI" in layer.layer_name.upper() for layer in pkt.layers):
                    protocols.add("DJI SDK")

                # ---- Packet size ----
                if hasattr(pkt, "length"):
                    packet_sizes.append(int(pkt.length))

                # ---- Timing (intervals) ----
                if hasattr(pkt, "sniff_time"):
                    t = pkt.sniff_time.timestamp()
                    if prev_time is not None:
                        intervals.append(t - prev_time)
                    prev_time = t

            except Exception:
                continue

        cap.close()

        # ---- Compute stats ----
        avg_size = sum(packet_sizes) / len(packet_sizes) if packet_sizes else 0
        avg_interval = sum(intervals) / len(intervals) if intervals else 0

        stats = {
            "avg_packet_size": avg_size,
            "avg_interval": avg_interval,
        }

        if not protocols:
            protocols.add("Unknown")

        return list(protocols), list(open_ports), stats


    def _describe(self, proto: str) -> ProtocolObservation:
        descriptions = {
            "UDP": "Datagram-based control traffic, often unencrypted.",
            "TCP": "Reliable socket traffic - may carry SDK commands.",
            "MAVLink": "MAVLink telemetry/control frames detected.",
            "DJI SDK": "DJI custom SDK messages observed.",
            "Unknown": "Unable to fingerprint protocol with limited capture.",
        }
        return ProtocolObservation(protocol=proto, description=descriptions.get(proto, proto))
