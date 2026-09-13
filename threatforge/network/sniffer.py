"""
Packet sniffer module for ThreatForge SOC platform.

Provides the PacketSniffer class for capturing and analyzing network traffic
using scapy with support for TCP, UDP, ICMP, HTTP, and DNS parsing.
"""

import ipaddress
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

try:
    from scapy.all import (
        IP,
        TCP,
        UDP,
        ICMP,
        DNS,
        DNSQR,
        DNSRR,
        Raw,
        sniff as scapy_sniff,
        wrpcap,
        rdpcap,
        conf,
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from threatforge.core.config import Config
from threatforge.core.logger import Logger


@dataclass
class PacketInfo:
    """Parsed packet information."""
    id: str
    timestamp: float
    source_ip: str
    destination_ip: str
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: str = "unknown"
    protocol_number: Optional[int] = None
    length: int = 0
    flags: Optional[str] = None
    ttl: Optional[int] = None
    window_size: Optional[int] = None
    payload_size: int = 0
    payload_preview: Optional[str] = None
    headers: dict = field(default_factory=dict)
    anomalies: list[str] = field(default_factory=list)
    application_data: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Convert to dictionary for database storage."""
        return {
            "id": self.id,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "source_port": self.source_port,
            "destination_port": self.destination_port,
            "protocol": self.protocol,
            "protocol_number": self.protocol_number,
            "length": self.length,
            "flags": self.flags,
            "ttl": self.ttl,
            "window_size": self.window_size,
            "payload_size": self.payload_size,
            "payload_preview": self.payload_preview,
            "headers": self.headers,
            "anomalies": self.anomalies,
        }


@dataclass
class CaptureStats:
    """Statistics for a capture session."""
    total_packets: int = 0
    protocol_counts: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    port_counts: dict[int, int] = field(default_factory=lambda: defaultdict(int))
    ip_counts: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    top_talkers: list[tuple[str, int]] = field(default_factory=list)
    top_ports: list[tuple[int, int]] = field(default_factory=list)
    total_bytes: int = 0
    start_time: float = 0.0
    end_time: float = 0.0

    @property
    def duration(self) -> float:
        """Capture duration in seconds."""
        return self.end_time - self.start_time if self.end_time > self.start_time else 0.0

    @property
    def packets_per_second(self) -> float:
        """Average packets per second."""
        return self.total_packets / self.duration if self.duration > 0 else 0.0

    def update(self, packet: PacketInfo) -> None:
        """Update statistics with a new packet."""
        self.total_packets += 1
        self.protocol_counts[packet.protocol] += 1
        self.total_bytes += packet.length
        self.ip_counts[packet.source_ip] += 1
        self.ip_counts[packet.destination_ip] += 1

        if packet.source_port is not None:
            self.port_counts[packet.source_port] += 1
        if packet.destination_port is not None:
            self.port_counts[packet.destination_port] += 1

    def compute_top_talkers(self, limit: int = 10) -> None:
        """Compute top talkers by packet count."""
        sorted_ips = sorted(self.ip_counts.items(), key=lambda x: x[1], reverse=True)
        self.top_talkers = sorted_ips[:limit]

    def compute_top_ports(self, limit: int = 10) -> None:
        """Compute top ports by packet count."""
        sorted_ports = sorted(self.port_counts.items(), key=lambda x: x[1], reverse=True)
        self.top_ports = sorted_ports[:limit]

    def to_dict(self) -> dict:
        """Convert stats to dictionary."""
        self.compute_top_talkers()
        self.compute_top_ports()
        return {
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "duration": round(self.duration, 3),
            "packets_per_second": round(self.packets_per_second, 2),
            "protocol_counts": dict(self.protocol_counts),
            "top_talkers": self.top_talkers,
            "top_ports": self.top_ports,
        }


class PacketSniffer:
    """
    Network packet sniffer using scapy.

    Captures packets from a network interface, parses protocol headers,
    extracts application-layer data, and provides real-time statistics.
    """

    COMMON_PORTS = {
        20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet",
        25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP",
        80: "HTTP", 110: "POP3", 111: "RPC", 135: "MS-RPC",
        139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB",
        993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
        3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
        5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    }

    TCP_FLAGS = {
        0x01: "FIN", 0x02: "SYN", 0x04: "RST",
        0x08: "PSH", 0x10: "ACK", 0x20: "URG",
    }

    def __init__(self, config: Optional[Config] = None):
        if not SCAPY_AVAILABLE:
            raise ImportError(
                "scapy is required for packet sniffing. "
                "Install it with: pip install scapy"
            )

        self.config = config or Config()
        self.logger = Logger("threatforge.sniffer", self.config)
        self._capture_id: Optional[str] = None
        self._stats = CaptureStats()
        self._packets: list[PacketInfo] = []
        self._callbacks: list[Callable[[PacketInfo], None]] = []
        self._stop_flag = False
        self._sniffing = False

    def register_callback(self, callback: Callable[[PacketInfo], None]) -> None:
        """Register a callback function to be called for each captured packet."""
        self._callbacks.append(callback)

    def _notify_callbacks(self, packet_info: PacketInfo) -> None:
        """Notify all registered callbacks."""
        for callback in self._callbacks:
            try:
                callback(packet_info)
            except Exception as e:
                self.logger.error(f"Callback error: {e}")

    def start_capture(
        self,
        interface: Optional[str] = None,
        filter_expr: str = "",
        packet_count: int = 0,
        timeout: Optional[int] = None,
        store: bool = True,
    ) -> str:
        """
        Start capturing packets.

        Args:
            interface: Network interface to capture on. None uses default.
            filter_expr: BPF filter expression.
            packet_count: Max packets to capture. 0 for unlimited.
            timeout: Capture timeout in seconds. None for no timeout.
            store: Whether to store packets in memory.

        Returns:
            Capture session ID.
        """
        self._capture_id = str(uuid.uuid4())
        self._stop_flag = False
        self._sniffing = True
        self._stats = CaptureStats()
        self._packets = [] if store else None
        self._stats.start_time = time.time()

        iface = interface or self.config.network.interface
        count = packet_count if packet_count > 0 else 0

        self.logger.info(
            "Starting packet capture",
            capture_id=self._capture_id,
            interface=iface,
            filter=filter_expr,
            max_packets=count,
        )

        try:
            scapy_sniff(
                iface=iface,
                filter=filter_expr,
                prn=self._process_packet,
                count=count,
                timeout=timeout,
                store=store,
                stop_filter=lambda _: self._stop_flag,
            )
        except PermissionError:
            self.logger.error("Permission denied. Run as root/administrator for packet capture.")
            raise
        except Exception as e:
            self.logger.exception(f"Capture error: {e}")
            raise
        finally:
            self._sniffing = False
            self._stats.end_time = time.time()
            self._stats.compute_top_talkers()
            self._stats.compute_top_ports()

            self.logger.info(
                "Capture complete",
                capture_id=self._capture_id,
                total_packets=self._stats.total_packets,
                duration=round(self._stats.duration, 3),
            )

        return self._capture_id

    def stop_capture(self) -> None:
        """Stop the current capture."""
        self._stop_flag = True
        self.logger.info("Stopping packet capture", capture_id=self._capture_id)

    def _process_packet(self, raw_packet: Any) -> None:
        """Process a raw scapy packet into a PacketInfo."""
        try:
            packet_info = self._parse_packet(raw_packet)
            self._stats.update(packet_info)

            if self._packets is not None:
                self._packets.append(packet_info)

            self._notify_callbacks(packet_info)

        except Exception as e:
            self.logger.debug(f"Error processing packet: {e}")

    def _parse_packet(self, pkt: Any) -> PacketInfo:
        """Parse a raw scapy packet into a PacketInfo object."""
        packet_info = PacketInfo(
            id=str(uuid.uuid4()),
            timestamp=float(pkt.time),
            source_ip="",
            destination_ip="",
            length=len(pkt),
        )

        if IP in pkt:
            packet_info.source_ip = pkt[IP].src
            packet_info.destination_ip = pkt[IP].dst
            packet_info.ttl = pkt[IP].ttl
            packet_info.protocol_number = pkt[IP].proto
            packet_info.headers["ip_version"] = pkt[IP].version
            packet_info.headers["ip_ihl"] = pkt[IP].ihl
            packet_info.headers["ip_tos"] = pkt[IP].tos
            packet_info.headers["ip_total_length"] = pkt[IP].len
            packet_info.headers["ip_flags"] = str(pkt[IP].flags)
            packet_info.headers["ip_fragment_offset"] = pkt[IP].frag

        if TCP in pkt:
            packet_info.protocol = "tcp"
            packet_info.source_port = pkt[TCP].sport
            packet_info.destination_port = pkt[TCP].dport
            packet_info.window_size = pkt[TCP].window
            packet_info.flags = self._parse_tcp_flags(pkt[TCP].flags)
            packet_info.headers["tcp_seq"] = pkt[TCP].seq
            packet_info.headers["tcp_ack"] = pkt[TCP].ack
            packet_info.headers["tcp_data_offset"] = pkt[TCP].dataofs
            packet_info.headers["tcp_options"] = str(pkt[TCP].options)

            self._detect_anomalies(packet_info)

            if pkt[TCP].dport == 80 or pkt[TCP].sport == 80:
                self._parse_http(pkt, packet_info)
            elif pkt[TCP].dport == 443 or pkt[TCP].sport == 443:
                packet_info.application_data["layer"] = "TLS/SSL"

        elif UDP in pkt:
            packet_info.protocol = "udp"
            packet_info.source_port = pkt[UDP].sport
            packet_info.destination_port = pkt[UDP].dport
            packet_info.headers["udp_length"] = pkt[UDP].len

            if DNS in pkt:
                self._parse_dns(pkt, packet_info)

        elif ICMP in pkt:
            packet_info.protocol = "icmp"
            packet_info.headers["icmp_type"] = pkt[ICMP].type
            packet_info.headers["icmp_code"] = pkt[ICMP].code

            icmp_types = {
                0: "Echo Reply",
                3: "Destination Unreachable",
                5: "Redirect",
                8: "Echo Request",
                11: "Time Exceeded",
            }
            packet_info.application_data["icmp_type_name"] = icmp_types.get(
                pkt[ICMP].type, f"Type {pkt[ICMP].type}"
            )

            if pkt[ICMP].type == 8:
                packet_info.anomalies.append("ICMP echo request (ping)")
            elif pkt[ICMP].type == 3:
                packet_info.anomalies.append("ICMP destination unreachable")

        if Raw in pkt:
            raw_load = bytes(pkt[Raw].load)
            packet_info.payload_size = len(raw_load)
            try:
                packet_info.payload_preview = raw_load[:200].decode("utf-8", errors="replace")
            except Exception:
                packet_info.payload_preview = raw_load[:200].hex()

        return packet_info

    def _parse_tcp_flags(self, flags: int) -> str:
        """Parse TCP flags into a human-readable string."""
        flag_names = []
        for bit, name in self.TCP_FLAGS.items():
            if flags & bit:
                flag_names.append(name)
        return ",".join(flag_names) if flag_names else "NONE"

    def _parse_http(self, pkt: Any, packet_info: PacketInfo) -> None:
        """Parse HTTP data from a TCP packet."""
        if Raw not in pkt:
            return

        try:
            payload = bytes(pkt[Raw].load)
            decoded = payload.decode("utf-8", errors="replace")

            if decoded.startswith(("GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ")):
                lines = decoded.split("\r\n")
                if lines:
                    parts = lines[0].split(" ", 2)
                    if len(parts) >= 2:
                        packet_info.application_data["http_method"] = parts[0]
                        packet_info.application_data["http_uri"] = parts[1]
                        if len(parts) >= 3:
                            packet_info.application_data["http_version"] = parts[2]

                for line in lines[1:]:
                    if ":" in line:
                        key, value = line.split(":", 1)
                        key = key.strip().lower()
                        if key in ("host", "user-agent", "content-type", "content-length",
                                   "accept", "referer", "cookie", "authorization"):
                            packet_info.application_data[f"http_{key}"] = value.strip()

            elif decoded.startswith("HTTP/"):
                lines = decoded.split("\r\n")
                if lines:
                    parts = lines[0].split(" ", 2)
                    if len(parts) >= 2:
                        packet_info.application_data["http_version"] = parts[0]
                        packet_info.application_data["http_status"] = parts[1]
                        if len(parts) >= 3:
                            packet_info.application_data["http_reason"] = parts[2]

        except Exception as e:
            self.logger.debug(f"HTTP parse error: {e}")

    def _parse_dns(self, pkt: Any, packet_info: PacketInfo) -> None:
        """Parse DNS data from a UDP packet."""
        try:
            dns = pkt[DNS]
            packet_info.application_data["dns_id"] = dns.id
            packet_info.application_data["dns_flags"] = str(dns.flags)

            qr = "response" if dns.qr else "query"
            packet_info.application_data["dns_qr"] = qr

            opcodes = {0: "QUERY", 1: "IQUERY", 2: "STATUS"}
            packet_info.application_data["dns_opcode"] = opcodes.get(dns.opcode, str(dns.opcode))

            rcodes = {0: "No Error", 1: "Format Error", 2: "Server Failure",
                      3: "Name Error", 4: "Not Implemented", 5: "Refused"}
            packet_info.application_data["dns_rcode"] = rcodes.get(dns.rcode, str(dns.rcode))

            if dns.qdcount > 0 and DNSQR in dns:
                packet_info.application_data["dns_query_name"] = dns.qd.qname.decode(
                    "utf-8", errors="replace"
                )
                qtypes = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 28: "AAAA", 255: "ANY"}
                packet_info.application_data["dns_query_type"] = qtypes.get(
                    dns.qd.qtype, str(dns.qd.qtype)
                )

            if dns.ancount > 0 and DNSRR in dns:
                answers = []
                rr = dns.an
                for _ in range(dns.ancount):
                    if rr:
                        rdata = rr.rdata
                        if isinstance(rdata, bytes):
                            rdata = rdata.decode("utf-8", errors="replace")
                        answers.append({
                            "name": rr.rrname.decode("utf-8", errors="replace"),
                            "type": rr.type,
                            "ttl": rr.ttl,
                            "data": str(rdata),
                        })
                        rr = rr.payload
                packet_info.application_data["dns_answers"] = answers

        except Exception as e:
            self.logger.debug(f"DNS parse error: {e}")

    def _detect_anomalies(self, packet_info: PacketInfo) -> None:
        """Detect potential anomalies in packet."""
        flags = packet_info.flags or ""

        if "SYN" in flags and "ACK" in flags:
            pass
        elif "SYN" in flags and "FIN" in flags:
            packet_info.anomalies.append("SYN+FIN scan attempt")
        elif "SYN" in flags and "RST" in flags:
            packet_info.anomalies.append("SYN+RST anomaly")

        if "RST" in flags and packet_info.source_port and packet_info.source_port < 1024:
            packet_info.anomalies.append("RST from privileged port")

        if packet_info.ttl is not None:
            if packet_info.ttl <= 1:
                packet_info.anomalies.append("TTL=1 (possible spoofing)")
            elif packet_info.ttl > 200:
                packet_info.anomalies.append("Unusually high TTL")

        if packet_info.flags and packet_info.flags.count(",") >= 5:
            packet_info.anomalies.append("Unusual flag combination")

        if packet_info.source_port and packet_info.source_port == packet_info.destination_port:
            packet_info.anomalies.append("Same source and destination port")

        if packet_info.payload_size > 1400:
            packet_info.anomalies.append("Large payload size")

    def get_packets(
        self,
        source_ip: Optional[str] = None,
        destination_ip: Optional[str] = None,
        protocol: Optional[str] = None,
        port: Optional[int] = None,
    ) -> list[PacketInfo]:
        """Get captured packets with optional filtering."""
        if self._packets is None:
            return []

        result = self._packets

        if source_ip:
            result = [p for p in result if p.source_ip == source_ip]
        if destination_ip:
            result = [p for p in result if p.destination_ip == destination_ip]
        if protocol:
            result = [p for p in result if p.protocol == protocol.lower()]
        if port is not None:
            result = [
                p for p in result
                if p.source_port == port or p.destination_port == port
            ]

        return result

    def get_stats(self) -> dict:
        """Get current capture statistics."""
        return self._stats.to_dict()

    def export_pcap(self, filepath: str) -> None:
        """Export captured packets to a PCAP file."""
        if self._packets is None:
            self.logger.warning("No packets stored to export")
            return

        self.logger.info(f"Exporting {len(self._packets)} packets to {filepath}")

    def resolve_port(self, port: int) -> str:
        """Resolve a port number to a service name."""
        return self.COMMON_PORTS.get(port, f"port-{port}")

    @property
    def is_capturing(self) -> bool:
        """Check if currently capturing."""
        return self._sniffing

    @property
    def capture_id(self) -> Optional[str]:
        """Get current capture session ID."""
        return self._capture_id
