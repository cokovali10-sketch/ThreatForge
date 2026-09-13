"""
Network analyzer module for ThreatForge SOC platform.

Provides the NetworkAnalyzer class for traffic flow analysis, connection
tracking, bandwidth monitoring, and anomaly detection.
"""

import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from threatforge.core.config import Config
from threatforge.core.logger import Logger


@dataclass
class Connection:
    """Tracked network connection."""
    id: str
    source_ip: str
    source_port: int
    destination_ip: str
    destination_port: int
    protocol: str
    state: str = "new"
    first_seen: float = 0.0
    last_seen: float = 0.0
    packets_sent: int = 0
    packets_received: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    flags_seen: list[str] = field(default_factory=list)

    @property
    def duration(self) -> float:
        """Connection duration in seconds."""
        return self.last_seen - self.first_seen if self.last_seen > self.first_seen else 0.0

    @property
    def total_packets(self) -> int:
        """Total packets in both directions."""
        return self.packets_sent + self.packets_received

    @property
    def total_bytes(self) -> int:
        """Total bytes in both directions."""
        return self.bytes_sent + self.bytes_received

    @property
    def avg_packet_size(self) -> float:
        """Average packet size."""
        total = self.total_packets
        return self.total_bytes / total if total > 0 else 0.0

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "source_ip": self.source_ip,
            "source_port": self.source_port,
            "destination_ip": self.destination_ip,
            "destination_port": self.destination_port,
            "protocol": self.protocol,
            "state": self.state,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "duration": round(self.duration, 3),
            "packets_sent": self.packets_sent,
            "packets_received": self.packets_received,
            "bytes_sent": self.bytes_sent,
            "bytes_received": self.bytes_received,
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
        }


@dataclass
class TrafficFlow:
    """Aggregated traffic flow between two endpoints."""
    source_ip: str
    destination_ip: str
    protocol: str
    total_bytes: int = 0
    total_packets: int = 0
    connection_count: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0
    port_pairs: set = field(default_factory=set)

    @property
    def avg_bytes_per_connection(self) -> float:
        return self.total_bytes / self.connection_count if self.connection_count > 0 else 0.0

    def to_dict(self) -> dict:
        return {
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "protocol": self.protocol,
            "total_bytes": self.total_bytes,
            "total_packets": self.total_packets,
            "connection_count": self.connection_count,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "duration": round(self.last_seen - self.first_seen, 3) if self.last_seen > self.first_seen else 0,
            "ports": list(self.port_pairs),
        }


@dataclass
class BandwidthSample:
    """Bandwidth usage at a point in time."""
    timestamp: float
    bytes_in: int = 0
    bytes_out: int = 0
    packets_in: int = 0
    packets_out: int = 0

    @property
    def total_bytes(self) -> int:
        return self.bytes_in + self.bytes_out

    @property
    def total_packets(self) -> int:
        return self.packets_in + self.packets_out


@dataclass
class Anomaly:
    """Detected network anomaly."""
    id: str
    timestamp: float
    anomaly_type: str
    severity: str
    description: str
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    details: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "anomaly_type": self.anomaly_type,
            "severity": self.severity,
            "description": self.description,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "details": self.details,
        }


class NetworkAnalyzer:
    """
    Network traffic analyzer for ThreatForge.

    Provides traffic flow analysis, connection tracking, bandwidth monitoring,
    and real-time anomaly detection for security operations.
    """

    def __init__(self, config: Optional[Config] = None):
        self.config = config or Config()
        self.logger = Logger("threatforge.analyzer", self.config)

        self._connections: dict[str, Connection] = {}
        self._flows: dict[str, TrafficFlow] = {}
        self._bandwidth_samples: list[BandwidthSample] = []
        self._anomalies: list[Anomaly] = []

        self._ip_packet_counts: dict[str, list[float]] = defaultdict(list)
        self._ip_byte_counts: dict[str, int] = defaultdict(int)
        self._port_scan_tracker: dict[str, set[int]] = defaultdict(set)
        self._connection_tracker: dict[str, list[float]] = defaultdict(list)

        self._config_anomaly = {
            "port_scan_threshold": 25,
            "port_scan_window": 60,
            "bandwidth_spike_multiplier": 5.0,
            "connection_rate_threshold": 100,
            "connection_rate_window": 60,
            "large_transfer_threshold": 1073741824,
            "new_port_threshold": 10,
        }

        self._baseline_established = False
        self._baseline_bandwidth: float = 0.0
        self._baseline_connections_per_second: float = 0.0

    def _connection_key(self, src_ip: str, src_port: int, dst_ip: str, dst_port: int, proto: str) -> str:
        """Generate a canonical connection key."""
        parts = sorted([(src_ip, src_port), (dst_ip, dst_port)])
        return f"{parts[0][0]}:{parts[0][1]}-{parts[1][0]}:{parts[1][1]}-{proto}"

    def _flow_key(self, src_ip: str, dst_ip: str, proto: str) -> str:
        """Generate a flow key."""
        return f"{src_ip}->{dst_ip}:{proto}"

    def process_packet(self, packet_data: dict) -> None:
        """
        Process a parsed packet from the sniffer.

        Args:
            packet_data: Dictionary with packet fields (source_ip, destination_ip, etc.)
        """
        now = time.time()
        src_ip = packet_data.get("source_ip", "")
        dst_ip = packet_data.get("destination_ip", "")
        src_port = packet_data.get("source_port")
        dst_port = packet_data.get("destination_port")
        protocol = packet_data.get("protocol", "unknown")
        length = packet_data.get("length", 0)
        flags = packet_data.get("flags", "")

        self._update_connection(src_ip, src_port, dst_ip, dst_port, protocol, length, flags, now)
        self._update_flow(src_ip, dst_ip, protocol, src_port, dst_port, length, now)
        self._update_bandwidth(src_ip, dst_ip, length, now)
        self._detect_anomalies(src_ip, dst_ip, src_port, dst_port, protocol, length, now)

    def _update_connection(
        self, src_ip: str, src_port: Optional[int], dst_ip: str,
        dst_port: Optional[int], protocol: str, length: int,
        flags: str, timestamp: float,
    ) -> None:
        """Update connection tracking."""
        if src_port is None or dst_port is None:
            return

        conn_key = self._connection_key(src_ip, src_port, dst_ip, dst_port, protocol)

        if conn_key not in self._connections:
            self._connections[conn_key] = Connection(
                id=str(uuid.uuid4()),
                source_ip=src_ip,
                source_port=src_port,
                destination_ip=dst_ip,
                destination_port=dst_port,
                protocol=protocol,
                state="active",
                first_seen=timestamp,
            )

        conn = self._connections[conn_key]
        conn.last_seen = timestamp
        conn.packets_sent += 1
        conn.bytes_sent += length

        if flags:
            conn.flags_seen.extend(flags.split(","))
            self._update_connection_state(conn, flags)

        self._connection_tracker[conn_key].append(timestamp)

    def _update_connection_state(self, conn: Connection, flags: str) -> None:
        """Update connection state based on TCP flags."""
        if "SYN" in flags and "ACK" not in flags:
            conn.state = "syn_sent"
        elif "SYN" in flags and "ACK" in flags:
            conn.state = "syn_ack"
        elif "ACK" in flags and conn.state == "syn_ack":
            conn.state = "established"
        elif "FIN" in flags:
            conn.state = "closing"
        elif "RST" in flags:
            conn.state = "reset"
        elif "ACK" in flags:
            conn.state = "established"

    def _update_flow(
        self, src_ip: str, dst_ip: str, protocol: str,
        src_port: Optional[int], dst_port: Optional[int],
        length: int, timestamp: float,
    ) -> None:
        """Update traffic flow aggregation."""
        flow_key = self._flow_key(src_ip, dst_ip, protocol)

        if flow_key not in self._flows:
            self._flows[flow_key] = TrafficFlow(
                source_ip=src_ip,
                destination_ip=dst_ip,
                protocol=protocol,
                first_seen=timestamp,
            )

        flow = self._flows[flow_key]
        flow.total_bytes += length
        flow.total_packets += 1
        flow.last_seen = timestamp

        if src_port is not None and dst_port is not None:
            flow.port_pairs.add((src_port, dst_port))

    def _update_bandwidth(self, src_ip: str, dst_ip: str, length: int, timestamp: float) -> None:
        """Update bandwidth tracking."""
        sample_interval = 1.0
        current_bucket = int(timestamp / sample_interval) * sample_interval

        if not self._bandwidth_samples or self._bandwidth_samples[-1].timestamp != current_bucket:
            self._bandwidth_samples.append(BandwidthSample(timestamp=current_bucket))

        sample = self._bandwidth_samples[-1]
        sample.bytes_out += length
        sample.packets_out += 1

        if len(self._bandwidth_samples) > 3600:
            self._bandwidth_samples = self._bandwidth_samples[-3600:]

    def _detect_anomalies(
        self, src_ip: str, dst_ip: str, src_port: Optional[int],
        dst_port: Optional[int], protocol: str, length: int, timestamp: float,
    ) -> None:
        """Run anomaly detection checks."""
        self._detect_port_scan(src_ip, dst_ip, timestamp)
        self._detect_connection_rate_anomaly(src_ip, timestamp)
        self._detect_bandwidth_spike(length, timestamp)
        self._detect_large_transfer(src_ip, dst_ip, length, timestamp)

    def _detect_port_scan(self, src_ip: str, dst_ip: str, timestamp: float) -> None:
        """Detect potential port scanning activity."""
        key = f"{src_ip}->{dst_ip}"
        self._port_scan_tracker[key].add(timestamp)

        window = self._config_anomaly["port_scan_window"]
        cutoff = timestamp - window
        self._port_scan_tracker[key] = {
            t for t in self._port_scan_tracker[key] if t > cutoff
        }

        if len(self._port_scan_tracker[key]) >= self._config_anomaly["port_scan_threshold"]:
            self._create_anomaly(
                anomaly_type="port_scan",
                severity="high",
                description=f"Potential port scan from {src_ip} to {dst_ip} "
                           f"({len(self._port_scan_tracker[key])} connections in {window}s)",
                source_ip=src_ip,
                destination_ip=dst_ip,
                details={
                    "connection_count": len(self._port_scan_tracker[key]),
                    "window_seconds": window,
                },
            )
            self._port_scan_tracker[key].clear()

    def _detect_connection_rate_anomaly(self, src_ip: str, timestamp: float) -> None:
        """Detect unusually high connection rates."""
        window = self._config_anomaly["connection_rate_window"]
        cutoff = timestamp - window

        recent = [t for t in self._connection_tracker.get(src_ip, []) if t > cutoff]
        rate = len(recent) / window if window > 0 else 0

        if rate > self._config_anomaly["connection_rate_threshold"] / window:
            self._create_anomaly(
                anomaly_type="connection_rate",
                severity="medium",
                description=f"High connection rate from {src_ip}: {rate:.1f} connections/sec",
                source_ip=src_ip,
                details={"rate_per_second": round(rate, 2), "window_seconds": window},
            )

    def _detect_bandwidth_spike(self, length: int, timestamp: float) -> None:
        """Detect bandwidth spikes relative to baseline."""
        if len(self._bandwidth_samples) < 60:
            return

        recent_window = 10
        recent_samples = self._bandwidth_samples[-recent_window:]
        avg_recent = sum(s.total_bytes for s in recent_samples) / recent_window

        baseline_window = 60
        baseline_samples = self._bandwidth_samples[-baseline_window:-recent_window]
        if not baseline_samples:
            return

        avg_baseline = sum(s.total_bytes for s in baseline_samples) / len(baseline_samples)

        if avg_baseline > 0 and avg_recent > avg_baseline * self._config_anomaly["bandwidth_spike_multiplier"]:
            self._create_anomaly(
                anomaly_type="bandwidth_spike",
                severity="medium",
                description=f"Bandwidth spike detected: {avg_recent:.0f} bytes/s vs baseline {avg_baseline:.0f} bytes/s",
                details={
                    "current_rate": round(avg_recent, 2),
                    "baseline_rate": round(avg_baseline, 2),
                    "multiplier": round(avg_recent / avg_baseline, 2),
                },
            )

    def _detect_large_transfer(self, src_ip: str, dst_ip: str, length: int, timestamp: float) -> None:
        """Detect unusually large data transfers."""
        flow_key = self._flow_key(src_ip, dst_ip, "tcp")
        flow = self._flows.get(flow_key)
        if flow and flow.total_bytes > self._config_anomaly["large_transfer_threshold"]:
            self._create_anomaly(
                anomaly_type="large_transfer",
                severity="low",
                description=f"Large data transfer: {src_ip} -> {dst_ip} ({flow.total_bytes} bytes)",
                source_ip=src_ip,
                destination_ip=dst_ip,
                details={"total_bytes": flow.total_bytes, "connection_count": flow.connection_count},
            )

    def _create_anomaly(
        self, anomaly_type: str, severity: str, description: str,
        source_ip: Optional[str] = None, destination_ip: Optional[str] = None,
        details: Optional[dict] = None,
    ) -> Anomaly:
        """Create and record an anomaly."""
        anomaly = Anomaly(
            id=str(uuid.uuid4()),
            timestamp=time.time(),
            anomaly_type=anomaly_type,
            severity=severity,
            description=description,
            source_ip=source_ip,
            destination_ip=destination_ip,
            details=details or {},
        )

        self._anomalies.append(anomaly)
        self.logger.warning(
            f"Anomaly detected: {description}",
            anomaly_id=anomaly.id,
            type=anomaly_type,
            severity=severity,
        )

        return anomaly

    def get_connections(
        self,
        state: Optional[str] = None,
        source_ip: Optional[str] = None,
        destination_ip: Optional[str] = None,
        limit: int = 100,
    ) -> list[dict]:
        """Get tracked connections with optional filtering."""
        connections = list(self._connections.values())

        if state:
            connections = [c for c in connections if c.state == state]
        if source_ip:
            connections = [c for c in connections if c.source_ip == source_ip]
        if destination_ip:
            connections = [c for c in connections if c.destination_ip == destination_ip]

        connections.sort(key=lambda c: c.last_seen, reverse=True)
        return [c.to_dict() for c in connections[:limit]]

    def get_flows(
        self,
        src_ip: Optional[str] = None,
        dst_ip: Optional[str] = None,
        protocol: Optional[str] = None,
        limit: int = 100,
    ) -> list[dict]:
        """Get traffic flows with optional filtering."""
        flows = list(self._flows.values())

        if src_ip:
            flows = [f for f in flows if f.source_ip == src_ip]
        if dst_ip:
            flows = [f for f in flows if f.destination_ip == dst_ip]
        if protocol:
            flows = [f for f in flows if f.protocol == protocol]

        flows.sort(key=lambda f: f.total_bytes, reverse=True)
        return [f.to_dict() for f in flows[:limit]]

    def get_bandwidth_history(self, duration_seconds: int = 300) -> list[dict]:
        """Get bandwidth usage history."""
        cutoff = time.time() - duration_seconds
        samples = [s for s in self._bandwidth_samples if s.timestamp > cutoff]

        return [
            {
                "timestamp": s.timestamp,
                "bytes_in": s.bytes_in,
                "bytes_out": s.bytes_out,
                "total_bytes": s.total_bytes,
                "packets_in": s.packets_in,
                "packets_out": s.packets_out,
            }
            for s in samples
        ]

    def get_anomalies(
        self,
        anomaly_type: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 100,
    ) -> list[dict]:
        """Get detected anomalies with optional filtering."""
        anomalies = self._anomalies

        if anomaly_type:
            anomalies = [a for a in anomalies if a.anomaly_type == anomaly_type]
        if severity:
            anomalies = [a for a in anomalies if a.severity == severity]

        anomalies.sort(key=lambda a: a.timestamp, reverse=True)
        return [a.to_dict() for a in anomalies[:limit]]

    def get_statistics(self) -> dict:
        """Get comprehensive analysis statistics."""
        active_conns = [c for c in self._connections.values() if c.state == "established"]
        total_bytes = sum(f.total_bytes for f in self._flows.values())
        total_packets = sum(f.total_packets for f in self._flows.values())

        proto_dist = defaultdict(int)
        for flow in self._flows.values():
            proto_dist[flow.protocol] += flow.total_bytes

        top_sources = defaultdict(int)
        top_destinations = defaultdict(int)
        for conn in self._connections.values():
            top_sources[conn.source_ip] += conn.bytes_sent
            top_destinations[conn.destination_ip] += conn.bytes_received

        return {
            "active_connections": len(active_conns),
            "total_connections": len(self._connections),
            "total_flows": len(self._flows),
            "total_bytes": total_bytes,
            "total_packets": total_packets,
            "total_anomalies": len(self._anomalies),
            "protocol_distribution": dict(proto_dist),
            "top_sources": sorted(top_sources.items(), key=lambda x: x[1], reverse=True)[:10],
            "top_destinations": sorted(top_destinations.items(), key=lambda x: x[1], reverse=True)[:10],
            "bandwidth_samples": len(self._bandwidth_samples),
        }

    def get_host_profile(self, ip: str) -> dict:
        """Build a behavioral profile for a specific host."""
        connections = [c for c in self._connections.values()
                       if c.source_ip == ip or c.destination_ip == ip]

        src_conns = [c for c in connections if c.source_ip == ip]
        dst_conns = [c for c in connections if c.destination_ip == ip]

        unique_destinations = set(c.destination_ip for c in src_conns)
        unique_sources = set(c.source_ip for c in dst_conns)
        unique_ports = set(c.destination_port for c in src_conns)

        proto_usage = defaultdict(int)
        for c in src_conns:
            proto_usage[c.protocol] += c.bytes_sent

        states = defaultdict(int)
        for c in connections:
            states[c.state] += 1

        return {
            "ip": ip,
            "total_connections": len(connections),
            "outbound_connections": len(src_conns),
            "inbound_connections": len(dst_conns),
            "unique_destinations": len(unique_destinations),
            "unique_sources": len(unique_sources),
            "unique_ports_accessed": len(unique_ports),
            "protocol_usage": dict(proto_usage),
            "connection_states": dict(states),
            "total_bytes_sent": sum(c.bytes_sent for c in src_conns),
            "total_bytes_received": sum(c.bytes_received for c in dst_conns),
            "avg_packet_size": (
                sum(c.avg_packet_size for c in connections) / len(connections)
                if connections else 0
            ),
        }

    def cleanup_stale_connections(self, timeout: float = 300.0) -> int:
        """Remove connections that haven't seen activity within timeout."""
        now = time.time()
        stale_keys = [
            key for key, conn in self._connections.items()
            if now - conn.last_seen > timeout
        ]

        for key in stale_keys:
            del self._connections[key]
            if key in self._connection_tracker:
                del self._connection_tracker[key]

        if stale_keys:
            self.logger.debug(f"Cleaned up {len(stale_keys)} stale connections")

        return len(stale_keys)

    def reset(self) -> None:
        """Reset all analysis state."""
        self._connections.clear()
        self._flows.clear()
        self._bandwidth_samples.clear()
        self._anomalies.clear()
        self._ip_packet_counts.clear()
        self._ip_byte_counts.clear()
        self._port_scan_tracker.clear()
        self._connection_tracker.clear()
        self.logger.info("Network analyzer state reset")
