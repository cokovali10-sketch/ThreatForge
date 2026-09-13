"""
Port scanner module for ThreatForge SOC platform.

Provides the PortScanner class with SYN scan, TCP connect, UDP scan,
service detection, OS fingerprinting, and concurrent scanning via asyncio.
"""

import asyncio
import ipaddress
import socket
import struct
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Optional

from threatforge.core.config import Config
from threatforge.core.logger import Logger


@dataclass
class PortResult:
    """Result of a single port scan."""
    port: int
    state: str
    protocol: str = "tcp"
    service: Optional[str] = None
    version: Optional[str] = None
    banner: Optional[str] = None
    response_time: float = 0.0
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "port": self.port,
            "state": self.state,
            "protocol": self.protocol,
            "service": self.service,
            "version": self.version,
            "banner": self.banner,
            "response_time": round(self.response_time, 4),
            "error": self.error,
        }


@dataclass
class HostResult:
    """Scan result for a single host."""
    ip: str
    hostname: Optional[str] = None
    state: str = "unknown"
    open_ports: list[PortResult] = field(default_factory=list)
    os_guess: Optional[str] = None
    os_details: Optional[dict] = field(default_factory=dict)
    mac_address: Optional[str] = None
    vendor: Optional[str] = None
    scan_time: float = 0.0
    start_time: float = 0.0
    end_time: float = 0.0

    @property
    def port_count(self) -> int:
        return len(self.open_ports)

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "hostname": self.hostname,
            "state": self.state,
            "open_ports": [p.to_dict() for p in self.open_ports],
            "port_count": self.port_count,
            "os_guess": self.os_guess,
            "os_details": self.os_details,
            "mac_address": self.mac_address,
            "vendor": self.vendor,
            "scan_time": round(self.scan_time, 3),
        }


@dataclass
class ScanResult:
    """Complete scan result."""
    scan_id: str
    scan_type: str
    target: str
    targets: list[str]
    start_time: float
    end_time: float = 0.0
    hosts: list[HostResult] = field(default_factory=list)
    total_ports_scanned: int = 0
    open_ports_found: int = 0
    errors: list[str] = field(default_factory=list)

    @property
    def duration(self) -> float:
        return self.end_time - self.start_time if self.end_time > self.start_time else 0.0

    def to_dict(self) -> dict:
        return {
            "scan_id": self.scan_id,
            "scan_type": self.scan_type,
            "target": self.target,
            "targets": self.targets,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration": round(self.duration, 3),
            "hosts": [h.to_dict() for h in self.hosts],
            "total_hosts": len(self.hosts),
            "total_ports_scanned": self.total_ports_scanned,
            "open_ports_found": self.open_ports_found,
            "errors": self.errors,
        }


SERVICE_SIGNATURES = {
    21: ("ftp", "FTP"),
    22: ("ssh", "SSH"),
    23: ("telnet", "Telnet"),
    25: ("smtp", "SMTP"),
    53: ("dns", "DNS"),
    80: ("http", "HTTP"),
    110: ("pop3", "POP3"),
    111: ("rpcbind", "RPC"),
    135: ("msrpc", "MSRPC"),
    139: ("netbios", "NetBIOS"),
    143: ("imap", "IMAP"),
    443: ("https", "HTTPS"),
    445: ("smb", "SMB"),
    993: ("imaps", "IMAPS"),
    995: ("pop3s", "POP3S"),
    1433: ("mssql", "MS SQL"),
    1521: ("oracle", "Oracle"),
    3306: ("mysql", "MySQL"),
    3389: ("rdp", "RDP"),
    5432: ("postgresql", "PostgreSQL"),
    5900: ("vnc", "VNC"),
    6379: ("redis", "Redis"),
    8080: ("http-proxy", "HTTP Proxy"),
    8443: ("https-alt", "HTTPS Alt"),
    27017: ("mongodb", "MongoDB"),
}

BANNER_GRABBERS = {
    "ssh": b"SSH-2.0-OpenSSH_8.9\r\n",
    "http": b"GET / HTTP/1.0\r\nHost: target\r\n\r\n",
    "https": b"GET / HTTP/1.0\r\nHost: target\r\n\r\n",
    "smtp": b"EHLO scan\r\n",
    "ftp": b"USER anonymous\r\n",
    "telnet": b"\r\n",
    "pop3": b"QUIT\r\n",
    "imap": b"a001 LOGOUT\r\n",
}

OS_FINGERPRINTS = {
    "ttl_64_linux": {"os": "Linux", "ttl_range": (63, 65)},
    "ttl_128_windows": {"os": "Windows", "ttl_range": (127, 129)},
    "ttl_255_cisco": {"os": "Cisco IOS", "ttl_range": (254, 255)},
    "ttl_30_solaris": {"os": "Solaris/AIX", "ttl_range": (29, 31)},
    "ttl_20_macos": {"os": "macOS/iOS", "ttl_range": (19, 21)},
}


class PortScanner:
    """
    Network port scanner for ThreatForge.

    Supports SYN scan, TCP connect scan, UDP scan with service detection
    and OS fingerprinting. Uses asyncio for high-performance concurrent scanning.
    """

    def __init__(self, config: Optional[Config] = None):
        self.config = config or Config()
        self.logger = Logger("threatforge.scanner", self.config)
        self._semaphore: Optional[asyncio.Semaphore] = None
        self._stop_flag = False
        self._scan_progress: dict[str, float] = {}

    async def scan_host(
        self,
        target: str,
        ports: Optional[list[int]] = None,
        scan_type: str = "tcp_connect",
        timeout: Optional[float] = None,
        service_detection: bool = True,
        os_detection: bool = True,
        banner_grab: bool = True,
    ) -> HostResult:
        """
        Scan a single host.

        Args:
            target: IP address or hostname to scan.
            ports: List of ports to scan. None uses common ports.
            scan_type: Scan type - 'tcp_connect', 'syn', or 'udp'.
            timeout: Connection timeout in seconds.
            service_detection: Enable service version detection.
            os_detection: Enable OS fingerprinting.
            banner_grab: Enable banner grabbing.

        Returns:
            HostResult with scan results.
        """
        if ports is None:
            ports = self.config.scanner.common_ports

        timeout = timeout or self.config.scanner.connect_timeout
        host_result = HostResult(ip=target, start_time=time.time())
        self._stop_flag = False

        try:
            try:
                host_result.hostname = socket.gethostbyaddr(target)[0]
            except (socket.herror, socket.gaierror, OSError):
                pass
        except Exception:
            pass

        host_result.state = "up"
        self.logger.info(f"Scanning {target} ({len(ports)} ports)", scan_type=scan_type)

        self._semaphore = asyncio.Semaphore(self.config.scanner.max_concurrent_tasks)

        if scan_type == "syn":
            tasks = [self._syn_scan_port(target, port, timeout) for port in ports]
        elif scan_type == "udp":
            tasks = [self._udp_scan_port(target, port, timeout) for port in ports]
        else:
            tasks = [self._tcp_connect_port(target, port, timeout) for port in ports]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, Exception):
                continue
            if result is None:
                continue

            port_result = result
            if port_result.state == "open":
                host_result.open_ports.append(port_result)

                if service_detection:
                    await self._detect_service(target, port_result)

                if banner_grab and port_result.service:
                    await self._grab_banner(target, port_result)

        if os_detection and host_result.open_ports:
            await self._detect_os(target, host_result)

        host_result.end_time = time.time()
        host_result.scan_time = host_result.end_time - host_result.start_time

        self.logger.info(
            f"Scan complete for {target}: {host_result.port_count} open ports",
            duration=round(host_result.scan_time, 3),
        )

        return host_result

    async def scan_network(
        self,
        targets: list[str],
        ports: Optional[list[int]] = None,
        scan_type: str = "tcp_connect",
        timeout: Optional[float] = None,
        service_detection: bool = True,
        os_detection: bool = True,
    ) -> ScanResult:
        """
        Scan multiple hosts concurrently.

        Args:
            targets: List of IP addresses or CIDR ranges.
            ports: Ports to scan on each host.
            scan_type: Scan type.
            timeout: Connection timeout.
            service_detection: Enable service detection.
            os_detection: Enable OS detection.

        Returns:
            ScanResult with all host results.
        """
        scan_result = ScanResult(
            scan_id=str(uuid.uuid4()),
            scan_type=scan_type,
            target=targets[0] if len(targets) == 1 else f"{len(targets)} hosts",
            targets=targets,
            start_time=time.time(),
        )

        self.logger.info(
            f"Starting network scan",
            scan_id=scan_result.scan_id,
            targets=len(targets),
            scan_type=scan_type,
        )

        host_tasks = [
            self.scan_host(
                target, ports, scan_type, timeout, service_detection, os_detection
            )
            for target in targets
        ]

        host_results = await asyncio.gather(*host_tasks, return_exceptions=True)

        for result in host_results:
            if isinstance(result, Exception):
                scan_result.errors.append(str(result))
                continue

            scan_result.hosts.append(result)
            scan_result.open_ports_found += result.port_count

        scan_result.end_time = time.time()
        self._expand_cidr_targets(scan_result)

        self.logger.info(
            f"Network scan complete",
            scan_id=scan_result.scan_id,
            hosts_scanned=len(scan_result.hosts),
            open_ports=scan_result.open_ports_found,
            duration=round(scan_result.duration, 3),
        )

        return scan_result

    def _expand_cidr_targets(self, scan_result: ScanResult) -> None:
        """Track total ports scanned across all hosts."""
        total = 0
        ports_per_host = len(self.config.scanner.common_ports)
        for host in scan_result.hosts:
            total += ports_per_host
        scan_result.total_ports_scanned = total

    async def _tcp_connect_port(
        self, target: str, port: int, timeout: float
    ) -> Optional[PortResult]:
        """Perform a TCP connect scan on a single port."""
        if self._stop_flag:
            return None

        async with self._semaphore:
            result = PortResult(port=port, state="closed", protocol="tcp")
            start = time.time()

            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(target, port),
                    timeout=timeout,
                )
                result.state = "open"
                result.response_time = time.time() - start
                writer.close()
                await writer.wait_closed()

            except asyncio.TimeoutError:
                result.state = "filtered"
                result.error = "timeout"
                result.response_time = time.time() - start

            except ConnectionRefusedError:
                result.state = "closed"
                result.error = "connection refused"
                result.response_time = time.time() - start

            except (OSError, asyncio.CancelledError) as e:
                result.state = "closed"
                result.error = str(e)
                result.response_time = time.time() - start

            return result

    async def _syn_scan_port(
        self, target: str, port: int, timeout: float
    ) -> Optional[PortResult]:
        """
        Perform a SYN scan on a single port.
        Falls back to TCP connect if raw sockets are unavailable.
        """
        if self._stop_flag:
            return None

        try:
            return await self._raw_syn_scan(target, port, timeout)
        except (PermissionError, OSError):
            self.logger.debug(
                f"SYN scan unavailable for {target}:{port}, falling back to TCP connect"
            )
            return await self._tcp_connect_port(target, port, timeout)

    async def _raw_syn_scan(
        self, target: str, port: int, timeout: float
    ) -> PortResult:
        """Low-level SYN scan using raw sockets."""
        result = PortResult(port=port, state="closed", protocol="tcp")
        start = time.time()

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            sock.settimeout(timeout)
        except PermissionError:
            raise
        except OSError as e:
            result.state = "error"
            result.error = str(e)
            return result

        try:
            src_port = (port + 1000) % 65535
            packet = self._build_syn_packet(target, port, src_port)
            sock.sendto(packet, (target, port))

            response = await asyncio.get_event_loop().run_in_executor(
                None, lambda: self._recv_response(sock, timeout)
            )

            if response:
                flags = response.get("flags", 0)
                if flags & 0x12 == 0x12:
                    result.state = "open"
                    result.response_time = time.time() - start
                    rst_packet = self._build_rst_packet(target, port, src_port)
                    try:
                        sock.sendto(rst_packet, (target, port))
                    except OSError:
                        pass
                elif flags & 0x04:
                    result.state = "closed"
                    result.response_time = time.time() - start
                elif flags & 0x12 == 0x14:
                    result.state = "closed"
                    result.response_time = time.time() - start
            else:
                result.state = "filtered"
                result.response_time = time.time() - start

        except Exception as e:
            result.state = "error"
            result.error = str(e)
            result.response_time = time.time() - start
        finally:
            sock.close()

        return result

    def _build_syn_packet(self, target: str, dst_port: int, src_port: int) -> bytes:
        """Build a raw SYN packet."""
        src_ip = "0.0.0.0"

        tcp_header = struct.pack(
            "!HHIIBBHHH",
            src_port,
            dst_port,
            0,
            0,
            (5 << 4),
            0x02,
            65535,
            0,
            0,
        )

        ip_header = struct.pack(
            "!BBHHHBBH4s4s",
            0x45,
            0,
            20 + 20,
            0,
            0,
            64,
            socket.IPPROTO_TCP,
            0,
            socket.inet_aton(src_ip),
            socket.inet_aton(target),
        )

        checksum = self._checksum(ip_header + tcp_header)
        tcp_header = struct.pack(
            "!HHIIBBHHH",
            src_port,
            dst_port,
            0,
            0,
            (5 << 4),
            0x02,
            65535,
            0,
            checksum,
        )

        return ip_header + tcp_header

    def _build_rst_packet(self, target: str, dst_port: int, src_port: int) -> bytes:
        """Build a RST packet to close the connection."""
        src_ip = "0.0.0.0"

        tcp_header = struct.pack(
            "!HHIIBBHHH",
            src_port,
            dst_port,
            0,
            0,
            (5 << 4),
            0x04,
            0,
            0,
            0,
        )

        ip_header = struct.pack(
            "!BBHHHBBH4s4s",
            0x45,
            0,
            20 + 20,
            0,
            0,
            64,
            socket.IPPROTO_TCP,
            0,
            socket.inet_aton(src_ip),
            socket.inet_aton(target),
        )

        checksum = self._checksum(ip_header + tcp_header)
        tcp_header = struct.pack(
            "!HHIIBBHHH",
            src_port,
            dst_port,
            0,
            0,
            (5 << 4),
            0x04,
            0,
            0,
            checksum,
        )

        return ip_header + tcp_header

    def _checksum(self, data: bytes) -> int:
        """Calculate IP/TCP checksum."""
        if len(data) % 2:
            data += b'\x00'

        s = 0
        for i in range(0, len(data), 2):
            w = (data[i] << 8) + data[i + 1]
            s += w

        s = (s >> 16) + (s & 0xFFFF)
        s = ~s & 0xFFFF
        return socket.htons(s)

    def _recv_response(self, sock: socket.socket, timeout: float) -> Optional[dict]:
        """Receive and parse a TCP response."""
        try:
            sock.settimeout(timeout)
            data, addr = sock.recvfrom(65535)

            if len(data) < 20:
                return None

            ip_header = struct.unpack("!BBHHHBBH4s4s", data[:20])
            ihl = (ip_header[0] & 0x0F) * 4
            proto = ip_header[6]

            if proto != socket.IPPROTO_TCP:
                return None

            tcp_header = struct.unpack("!HHIIBBHHH", data[ihl:ihl + 20])
            flags = tcp_header[5]

            return {
                "src_ip": addr[0],
                "dst_port": tcp_header[0],
                "src_port": tcp_header[1],
                "flags": flags,
                "seq": tcp_header[2],
                "ack": tcp_header[3],
            }

        except socket.timeout:
            return None
        except Exception:
            return None

    async def _udp_scan_port(
        self, target: str, port: int, timeout: float
    ) -> Optional[PortResult]:
        """Perform a UDP scan on a single port."""
        if self._stop_flag:
            return None

        async with self._semaphore:
            result = PortResult(port=port, state="closed", protocol="udp")
            start = time.time()

            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(timeout)

                await asyncio.get_event_loop().run_in_executor(
                    None, lambda: sock.sendto(b"\x00" * 12, (target, port))
                )

                try:
                    data, addr = await asyncio.get_event_loop().run_in_executor(
                        None, lambda: sock.recvfrom(1024)
                    )
                    result.state = "open"
                    result.response_time = time.time() - start

                except socket.timeout:
                    if port in (53, 67, 68, 123, 161, 162, 500, 514, 1900, 5353):
                        result.state = "open|filtered"
                    else:
                        result.state = "closed|filtered"
                    result.response_time = time.time() - start

                except ConnectionRefusedError:
                    result.state = "closed"
                    result.response_time = time.time() - start

                finally:
                    sock.close()

            except OSError as e:
                result.state = "error"
                result.error = str(e)
                result.response_time = time.time() - start

            return result

    async def _detect_service(self, target: str, port_result: PortResult) -> None:
        """Detect service running on an open port."""
        if port_result.port in SERVICE_SIGNATURES:
            port_result.service, version_hint = SERVICE_SIGNATURES[port_result.port]
            port_result.version = version_hint

    async def _grab_banner(self, target: str, port_result: PortResult) -> None:
        """Grab service banner for version detection."""
        if not port_result.service:
            return

        grabber = BANNER_GRABBERS.get(port_result.service)
        if not grabber:
            return

        try:
            if port_result.service in ("http", "https"):
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(target, port_result.port),
                    timeout=self.config.scanner.read_timeout,
                )
                writer.write(grabber)
                await writer.drain()

                data = await asyncio.wait_for(
                    reader.read(1024),
                    timeout=self.config.scanner.read_timeout,
                )
                banner = data.decode("utf-8", errors="replace").strip()
                writer.close()
                await writer.wait_closed()
            else:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(target, port_result.port),
                    timeout=self.config.scanner.read_timeout,
                )

                try:
                    data = await asyncio.wait_for(
                        reader.read(1024),
                        timeout=self.config.scanner.read_timeout,
                    )
                    banner = data.decode("utf-8", errors="replace").strip()
                except asyncio.TimeoutError:
                    banner = ""

                writer.close()
                await writer.wait_closed()

            if banner:
                port_result.banner = banner[:500]
                self._parse_banner_version(port_result, banner)

        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            pass

    def _parse_banner_version(self, port_result: PortResult, banner: str) -> None:
        """Extract version information from banner."""
        banner_lower = banner.lower()

        if "ssh" in banner_lower:
            parts = banner.split()
            if len(parts) >= 2:
                port_result.version = parts[1]

        elif "apache" in banner_lower:
            for part in banner.split():
                if part[0].isdigit():
                    port_result.version = f"Apache {part}"
                    break

        elif "nginx" in banner_lower:
            for part in banner.split("/"):
                if "nginx" in part.lower():
                    port_result.version = part.strip()
                    break

        elif "microsoft" in banner_lower or "iis" in banner_lower:
            port_result.version = banner.split("\r\n")[0][:100]

        elif "ftpd" in banner_lower or "ftp" in banner_lower:
            port_result.version = banner.split("\r\n")[0][:100]

        elif "smtp" in banner_lower:
            port_result.version = banner.split("\r\n")[0][:100]

    async def _detect_os(self, target: str, host_result: HostResult) -> None:
        """Detect operating system using TCP/IP fingerprinting."""
        try:
            ttl = await self._get_ttl(target)
            if ttl is None:
                return

            for os_name, fingerprint in OS_FINGERPRINTS.items():
                low, high = fingerprint["ttl_range"]
                if low <= ttl <= high:
                    host_result.os_guess = fingerprint["os"]
                    host_result.os_details = {
                        "ttl": ttl,
                        "method": "ttl_fingerprint",
                        "confidence": "medium",
                    }
                    break

            if not host_result.os_guess:
                host_result.os_guess = "Unknown"
                host_result.os_details = {
                    "ttl": ttl,
                    "method": "ttl_fingerprint",
                    "confidence": "low",
                }

        except Exception as e:
            self.logger.debug(f"OS detection failed for {target}: {e}")

    async def _get_ttl(self, target: str) -> Optional[int]:
        """Get TTL from target using a raw socket probe."""
        try:
            loop = asyncio.get_event_loop()

            def _probe_ttl() -> int:
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
                try:
                    sock.settimeout(2.0)
                    icmp_echo = struct.pack("!BBHHH", 8, 0, 0, 1, 1)
                    identifier = (1 << 16) | 1
                    checksum = self._checksum(icmp_echo)
                    icmp_echo = struct.pack("!BBHHH", 8, 0, checksum, 1, 1)

                    sock.sendto(icmp_echo, (target, 0))
                    sock.settimeout(2.0)
                    data, addr = sock.recvfrom(1024)
                    ip_header_len = (data[0] & 0x0F) * 4
                    ttl = data[ip_header_len + 8]
                    return ttl
                finally:
                    sock.close()

            return await loop.run_in_executor(None, _probe_ttl)

        except (PermissionError, OSError):
            pass

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2.0)
            await asyncio.get_event_loop().run_in_executor(
                None, lambda: sock.connect((target, 80))
            )
            ttl = sock.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)
            sock.close()
            return ttl
        except Exception:
            return None

    async def quick_scan(self, target: str, port_count: int = 20) -> HostResult:
        """Perform a quick scan of the most common ports."""
        ports = self.config.scanner.common_ports[:port_count]
        return await self.scan_host(
            target,
            ports=ports,
            scan_type="tcp_connect",
            service_detection=True,
            os_detection=False,
            banner_grab=True,
        )

    async def full_scan(self, target: str) -> HostResult:
        """Perform a full port scan (1-65535)."""
        ports = list(range(1, 65536))
        return await self.scan_host(
            target,
            ports=ports,
            scan_type="tcp_connect",
            service_detection=True,
            os_detection=True,
            banner_grab=True,
        )

    async def syn_scan(self, target: str, ports: Optional[list[int]] = None) -> HostResult:
        """Perform a SYN scan."""
        return await self.scan_host(
            target,
            ports=ports,
            scan_type="syn",
            service_detection=True,
            os_detection=True,
            banner_grab=False,
        )

    async def udp_scan(self, target: str, ports: Optional[list[int]] = None) -> HostResult:
        """Perform a UDP scan."""
        if ports is None:
            ports = [53, 67, 68, 123, 161, 162, 500, 514, 1900, 5353]

        return await self.scan_host(
            target,
            ports=ports,
            scan_type="udp",
            service_detection=False,
            os_detection=False,
            banner_grab=False,
        )

    def stop(self) -> None:
        """Stop the current scan."""
        self._stop_flag = True
        self.logger.info("Scan stop requested")

    def get_common_ports(self) -> list[int]:
        """Get the list of common ports from config."""
        return self.config.scanner.common_ports

    def resolve_target(self, target: str) -> Optional[str]:
        """Resolve a hostname to an IP address."""
        try:
            return socket.gethostbyname(target)
        except socket.gaierror:
            return None

    def expand_cidr(self, cidr: str) -> list[str]:
        """Expand a CIDR notation to a list of IP addresses."""
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            return [str(host) for host in network.hosts()]
        except ValueError:
            return [cidr]
