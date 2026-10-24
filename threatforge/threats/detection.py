from __future__ import annotations

import re
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable
# --- константы вынесены FORGE refactor ---
CONST_5 = 5
CONST_60 = 60
CONST_1024 = 1024



class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class DetectionRule:
    rule_id: str
    name: str
    description: str
    severity: Severity
    mitre_tactic: str
    mitre_technique: str
    enabled: bool = True
    false_positive_count: int = 0
    detection_count: int = 0
    last_triggered: datetime | None = None


@dataclass
class Alert:
    alert_id: str
    rule_id: str
    rule_name: str
    severity: Severity
    message: str
    source_ip: str
    destination_ip: str
    timestamp: datetime
    mitre_tactic: str
    mitre_technique: str
    raw_event: dict = field(default_factory=dict)
    is_false_positive: bool = False
    investigation_notes: str = ""
    indicator_matches: list[str] = field(default_factory=list)


@dataclass
class FalsePositiveRecord:
    alert_id: str
    rule_id: str
    reason: str
    analyst: str
    timestamp: datetime


class ThreatDetector:
    def __init__(self) -> None:
        self.rules: dict[str, DetectionRule] = {}
        self.alerts: list[Alert] = []
        self.false_positives: list[FalsePositiveRecord] = []
        self._custom_checkers: dict[str, Callable[..., bool]] = {}
        self._initialize_rules()

    def _initialize_rules(self) -> None:
        rules = [
            DetectionRule(
                rule_id="BRUTE_FORCE_001",
                name="Brute Force Authentication",
                description="Multiple failed login attempts from the same source within a short time window",
                severity=Severity.HIGH,
                mitre_tactic="Credential Access",
                mitre_technique="T1110 - Brute Force",
            ),
            DetectionRule(
                rule_id="PORT_SCAN_002",
                name="Port Scanning Activity",
                description="Connection attempts to multiple ports on the same host in rapid succession",
                severity=Severity.MEDIUM,
                mitre_tactic="Discovery",
                mitre_technique="T1046 - Network Service Discovery",
            ),
            DetectionRule(
                rule_id="DNS_TUNNEL_003",
                name="DNS Tunneling",
                description="Unusually large or encoded DNS queries indicating data exfiltration or C2",
                severity=Severity.HIGH,
                mitre_tactic="Exfiltration",
                mitre_technique="T1048 - Exfiltration Over Alternative Protocol",
            ),
            DetectionRule(
                rule_id="C2_BEACON_004",
                name="C2 Beacon Activity",
                description="Regular periodic outbound connections to a known or suspicious command and control server",
                severity=Severity.CRITICAL,
                mitre_tactic="Command and Control",
                mitre_technique="T1071 - Application Layer Protocol",
            ),
            DetectionRule(
                rule_id="LATERAL_MOVE_005",
                name="Lateral Movement Detection",
                description="Suspicious remote execution or authentication patterns indicating lateral movement",
                severity=Severity.CRITICAL,
                mitre_tactic="Lateral Movement",
                mitre_technique="T1021 - Remote Services",
            ),
            DetectionRule(
                rule_id="DATA_EXFIL_006",
                name="Data Exfiltration",
                description="Large outbound data transfer or transfer to unusual destinations",
                severity=Severity.CRITICAL,
                mitre_tactic="Exfiltration",
                mitre_technique="T1041 - Exfiltration Over C2 Channel",
            ),
            DetectionRule(
                rule_id="PRIV_ESC_007",
                name="Privilege Escalation",
                description="Attempt to escalate privileges through exploitation or misconfiguration",
                severity=Severity.CRITICAL,
                mitre_tactic="Privilege Escalation",
                mitre_technique="T1068 - Exploitation for Privilege Escalation",
            ),
            DetectionRule(
                rule_id="MALWARE_C2_008",
                name="Malware Command and Control",
                description="Communication with known malware infrastructure or patterns matching malware beacons",
                severity=Severity.CRITICAL,
                mitre_tactic="Command and Control",
                mitre_technique="T1071.001 - Web Protocols",
            ),
            DetectionRule(
                rule_id="CRED_STUFF_009",
                name="Credential Stuffing",
                description="Distributed login attempts using known compromised credential lists",
                severity=Severity.HIGH,
                mitre_tactic="Credential Access",
                mitre_technique="T1110.004 - Credential Stuffing",
            ),
            DetectionRule(
                rule_id="SQL_INJECT_010",
                name="SQL Injection Attempt",
                description="HTTP request containing SQL injection patterns in parameters or headers",
                severity=Severity.HIGH,
                mitre_tactic="Initial Access",
                mitre_technique="T1190 - Exploit Public-Facing Application",
            ),
            DetectionRule(
                rule_id="XSS_011",
                name="Cross-Site Scripting Attempt",
                description="HTTP request containing reflected or stored XSS payloads",
                severity=Severity.MEDIUM,
                mitre_tactic="Initial Access",
                mitre_technique="T1189 - Drive-by Compromise",
            ),
            DetectionRule(
                rule_id="PATH_TRAV_012",
                name="Path Traversal Attempt",
                description="HTTP request attempting directory traversal to access restricted files",
                severity=Severity.HIGH,
                mitre_tactic="Initial Access",
                mitre_technique="T1190 - Exploit Public-Facing Application",
            ),
            DetectionRule(
                rule_id="SUSP_PROC_013",
                name="Suspicious Process Execution",
                description="Execution of process associated with living-off-the-land techniques",
                severity=Severity.HIGH,
                mitre_tactic="Execution",
                mitre_technique="T1059 - Command and Scripting Interpreter",
            ),
            DetectionRule(
                rule_id="ANOM_LOGIN_014",
                name="Anomalous Login Activity",
                description="Login from unusual location, time, or device for the user account",
                severity=Severity.MEDIUM,
                mitre_tactic="Initial Access",
                mitre_technique="T1078 - Valid Accounts",
            ),
            DetectionRule(
                rule_id="UNUS_DNS_015",
                name="Unusual DNS Query Pattern",
                description="DNS queries to newly registered domains or domain generation algorithms",
                severity=Severity.HIGH,
                mitre_tactic="Command and Control",
                mitre_technique="T1568 - Dynamic Resolution",
            ),
            DetectionRule(
                rule_id="LARGE_XFER_016",
                name="Large Data Transfer",
                description="Outbound data transfer exceeding normal baseline threshold",
                severity=Severity.MEDIUM,
                mitre_tactic="Exfiltration",
                mitre_technique="T1030 - Data Transfer Size Limits",
            ),
            DetectionRule(
                rule_id="SCAN_ACT_017",
                name="Internal Scanning Activity",
                description="Host performing internal network scanning beyond its normal behavior",
                severity=Severity.HIGH,
                mitre_tactic="Discovery",
                mitre_technique="T1018 - Remote System Discovery",
            ),
            DetectionRule(
                rule_id="KNOWN_IOC_018",
                name="Known Indicator of Compromise",
                description="Traffic matches a known IOC from threat intelligence feeds",
                severity=Severity.CRITICAL,
                mitre_tactic="Multiple",
                mitre_technique="Multiple - IOC Match",
            ),
            DetectionRule(
                rule_id="SUSP_UA_019",
                name="Suspicious User-Agent",
                description="HTTP request with user-agent string associated with known malware or attack tools",
                severity=Severity.MEDIUM,
                mitre_tactic="Command and Control",
                mitre_technique="T1071 - Application Layer Protocol",
            ),
            DetectionRule(
                rule_id="API_ABUSE_020",
                name="API Abuse Detection",
                description="Abnormal API usage patterns indicating abuse, scraping, or exploitation",
                severity=Severity.MEDIUM,
                mitre_tactic="Impact",
                mitre_technique="T1499 - Endpoint Denial of Service",
            ),
            DetectionRule(
                rule_id="COAL_DOLL_021",
                name="Coin Mining Activity",
                description="Cryptocurrency mining network activity or process indicators",
                severity=Severity.HIGH,
                mitre_tactic="Impact",
                mitre_technique="T1496 - Resource Hijacking",
            ),
            DetectionRule(
                rule_id="RANSOM_022",
                name="Ransomware Indicators",
                description="File encryption patterns, ransom note creation, or shadow copy deletion",
                severity=Severity.CRITICAL,
                mitre_tactic="Impact",
                mitre_technique="T1486 - Data Encrypted for Impact",
            ),
        ]
        for rule in rules:
            self.rules[rule.rule_id] = rule

    def register_custom_checker(self, rule_id: str, checker: Callable[..., bool]) -> None:
        self._custom_checkers[rule_id] = checker

    def enable_rule(self, rule_id: str) -> None:
        if rule_id in self.rules:
            self.rules[rule_id].enabled = True

    def disable_rule(self, rule_id: str) -> None:
        if rule_id in self.rules:
            self.rules[rule_id].enabled = False

    def evaluate_event(self, event: dict[str, Any]) -> list[Alert]:
        alerts: list[Alert] = []
        for rule in self.rules.values():
            if not rule.enabled:
                continue
            checker = self._custom_checkers.get(rule.rule_id)
            if checker and checker(event, rule):
                alert = self._create_alert(rule, event)
                alerts.append(alert)
                self.alerts.append(alert)
                rule.detection_count += 1
                rule.last_triggered = datetime.utcnow()
        return alerts

    def _create_alert(self, rule: DetectionRule, event: dict[str, Any]) -> Alert:
        source_ip = event.get("source_ip", event.get("src_ip", "0.0.0.0"))
        destination_ip = event.get("destination_ip", event.get("dst_ip", "0.0.0.0"))
        return Alert(
            alert_id=str(uuid.uuid4()),
            rule_id=rule.rule_id,
            rule_name=rule.name,
            severity=rule.severity,
            message=f"{rule.name}: {rule.description}",
            source_ip=source_ip,
            destination_ip=destination_ip,
            timestamp=datetime.utcnow(),
            mitre_tactic=rule.mitre_tactic,
            mitre_technique=rule.mitre_technique,
            raw_event=event,
        )

    def check_brute_force(self, events: list[dict], threshold: int = CONST_5, window_seconds: int = 300) -> list[Alert]:
        alerts: list[Alert] = []
        rule = self.rules.get("BRUTE_FORCE_001")
        if not rule or not rule.enabled:
            return alerts
        failed_by_source: dict[str, list[dict]] = defaultdict(list)
        for event in events:
            if event.get("event_type") == "failed_login":
                src = event.get("source_ip", "")
                failed_by_source[src].append(event)
        for src_ip, failed_events in failed_by_source.items():
            if len(failed_events) >= threshold:
                alert = Alert(
                    alert_id=str(uuid.uuid4()),
                    rule_id=rule.rule_id,
                    rule_name=rule.name,
                    severity=rule.severity,
                    message=f"Brute force detected from {src_ip}: {len(failed_events)} failed attempts",
                    source_ip=src_ip,
                    destination_ip=failed_events[0].get("destination_ip", ""),
                    timestamp=datetime.utcnow(),
                    mitre_tactic=rule.mitre_tactic,
                    mitre_technique=rule.mitre_technique,
                    raw_event={"attempts": failed_events[-CONST_5:]},
                )
                alerts.append(alert)
                self.alerts.append(alert)
                rule.detection_count += 1
                rule.last_triggered = datetime.utcnow()
        return alerts

    def check_port_scan(self, events: list[dict], port_threshold: int = 10, window_seconds: int = CONST_60) -> list[Alert]:
        alerts: list[Alert] = []
        rule = self.rules.get("PORT_SCAN_002")
        if not rule or not rule.enabled:
            return alerts
        ports_by_source: dict[str, set[str]] = defaultdict(set)
        for event in events:
            if event.get("event_type") == "connection_attempt":
                src = event.get("source_ip", "")
                dst_port = str(event.get("destination_port", ""))
                ports_by_source[src].add(dst_port)
        for src_ip, ports in ports_by_source.items():
            if len(ports) >= port_threshold:
                alert = Alert(
                    alert_id=str(uuid.uuid4()),
                    rule_id=rule.rule_id,
                    rule_name=rule.name,
                    severity=rule.severity,
                    message=f"Port scan detected from {src_ip}: {len(ports)} unique ports",
                    source_ip=src_ip,
                    destination_ip="",
                    timestamp=datetime.utcnow(),
                    mitre_tactic=rule.mitre_tactic,
                    mitre_technique=rule.mitre_technique,
                    raw_event={"scanned_ports": sorted(ports)},
                )
                alerts.append(alert)
                self.alerts.append(alert)
                rule.detection_count += 1
                rule.last_triggered = datetime.utcnow()
        return alerts

    def check_dns_tunneling(self, queries: list[dict], entropy_threshold: float = 3.5, length_threshold: int = 50) -> list[Alert]:
        alerts: list[Alert] = []
        rule = self.rules.get("DNS_TUNNEL_003")
        if not rule or not rule.enabled:
            return alerts
        for query in queries:
            qname = query.get("query_name", "")
            entropy = self._calculate_entropy(qname)
            if entropy > entropy_threshold or len(qname) > length_threshold:
                alert = Alert(
                    alert_id=str(uuid.uuid4()),
                    rule_id=rule.rule_id,
                    rule_name=rule.name,
                    severity=rule.severity,
                    message=f"Potential DNS tunneling: {qname} (entropy={entropy:.2f}, length={len(qname)})",
                    source_ip=query.get("source_ip", ""),
                    destination_ip=query.get("dns_server", ""),
                    timestamp=datetime.utcnow(),
                    mitre_tactic=rule.mitre_tactic,
                    mitre_technique=rule.mitre_technique,
                    raw_event=query,
                    indicator_matches=[qname],
                )
                alerts.append(alert)
                self.alerts.append(alert)
                rule.detection_count += 1
                rule.last_triggered = datetime.utcnow()
        return alerts

    def check_c2_beacon(self, connections: list[dict], interval_tolerance: float = 0.3, min_beacons: int = CONST_5) -> list[Alert]:
        alerts: list[Alert] = []
        rule = self.rules.get("C2_BEACON_004")
        if not rule or not rule.enabled:
            return alerts
        by_dest: dict[str, list[dict]] = defaultdict(list)
        for conn in connections:
            dst = conn.get("destination_ip", "")
            by_dest[dst].append(conn)
        for dst_ip, conns in by_dest.items():
            if len(conns) < min_beacons:
                continue
            timestamps = sorted([c.get("timestamp", 0) for c in conns])
            intervals = [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)]
            if not intervals:
                continue
            avg_interval = sum(intervals) / len(intervals)
            if avg_interval == 0:
                continue
            jitter = sum(abs(iv - avg_interval) / avg_interval for iv in intervals) / len(intervals)
            if jitter < interval_tolerance:
                alert = Alert(
                    alert_id=str(uuid.uuid4()),
                    rule_id=rule.rule_id,
                    rule_name=rule.name,
                    severity=rule.severity,
                    message=f"C2 beacon detected to {dst_ip}: {len(conns)} connections, avg interval {avg_interval:.1f}s, jitter {jitter:.2f}",
                    source_ip=conns[0].get("source_ip", ""),
                    destination_ip=dst_ip,
                    timestamp=datetime.utcnow(),
                    mitre_tactic=rule.mitre_tactic,
                    mitre_technique=rule.mitre_technique,
                    raw_event={"beacon_count": len(conns), "avg_interval": avg_interval, "jitter": jitter},
                )
                alerts.append(alert)
                self.alerts.append(alert)
                rule.detection_count += 1
                rule.last_triggered = datetime.utcnow()
        return alerts

    def check_lateral_movement(self, events: list[dict]) -> list[Alert]:
        alerts: list[Alert] = []
        rule = self.rules.get("LATERAL_MOVE_005")
        if not rule or not rule.enabled:
            return alerts
        suspicious_tools = {"psexec", "wmic", "winrm", "ssh", "smbexec", "mimikatz", "wmiexec"}
        for event in events:
            cmd = event.get("command", "").lower()
            process = event.get("process_name", "").lower()
            if any(tool in cmd or tool in process for tool in suspicious_tools):
                alert = Alert(
                    alert_id=str(uuid.uuid4()),
                    rule_id=rule.rule_id,
                    rule_name=rule.name,
                    severity=rule.severity,
                    message=f"Suspicious remote execution detected: {event.get('process_name', 'unknown')}",
                    source_ip=event.get("source_ip", ""),
                    destination_ip=event.get("destination_ip", ""),
                    timestamp=datetime.utcnow(),
                    mitre_tactic=rule.mitre_tactic,
                    mitre_technique=rule.mitre_technique,
                    raw_event=event,
                )
                alerts.append(alert)
                self.alerts.append(alert)
                rule.detection_count += 1
                rule.last_triggered = datetime.utcnow()
        return alerts

    def check_data_exfiltration(self, events: list[dict], size_threshold_mb: float = 100) -> list[Alert]:
        alerts: list[Alert] = []
        rule = self.rules.get("DATA_EXFIL_006")
        if not rule or not rule.enabled:
            return alerts
        for event in events:
            bytes_transferred = event.get("bytes_transferred", 0)
            size_mb = bytes_transferred / (CONST_1024 * CONST_1024)
            if size_mb > size_threshold_mb:
                alert = Alert(
                    alert_id=str(uuid.uuid4()),
                    rule_id=rule.rule_id,
                    rule_name=rule.name,
                    severity=rule.severity,
                    message=f"Large data transfer: {size_mb:.1f} MB to {event.get('destination_ip', 'unknown')}",
                    source_ip=event.get("source_ip", ""),
                    destination_ip=event.get("destination_ip", ""),
                    timestamp=datetime.utcnow(),
                    mitre_tactic=rule.mitre_tactic,
                    mitre_technique=rule.mitre_technique,
                    raw_event=event,
                )
                alerts.append(alert)
                self.alerts.append(alert)
                rule.detection_count += 1
                rule.last_triggered = datetime.utcnow()
        return alerts

    def check_privilege_escalation(self, events: list[dict]) -> list[Alert]:
        alerts: list[Alert] = []
        rule = self.rules.get("PRIV_ESC_007")
        if not rule or not rule.enabled:
            return alerts
        suspicious_patterns = [
            r"sudo\s+-s",
            r"setuid",
            r"chmod\s+\+s",
            r"net\s+localgroup\s+administrators",
            r"net\s+user.*\/add",
            r"reg\s+add.*run",
            r"at\s+\d+",
            r"schtasks",
        ]
        for event in events:
            cmd = event.get("command", "")
            for pattern in suspicious_patterns:
                if re.search(pattern, cmd, re.IGNORECASE):
                    alert = Alert(
                        alert_id=str(uuid.uuid4()),
                        rule_id=rule.rule_id,
                        rule_name=rule.name,
                        severity=rule.severity,
                        message=f"Privilege escalation attempt: {cmd[:200]}",
                        source_ip=event.get("source_ip", ""),
                        destination_ip=event.get("destination_ip", ""),
                        timestamp=datetime.utcnow(),
                        mitre_tactic=rule.mitre_tactic,
                        mitre_technique=rule.mitre_technique,
                        raw_event=event,
                    )
                    alerts.append(alert)
                    self.alerts.append(alert)
                    rule.detection_count += 1
                    rule.last_triggered = datetime.utcnow()
                    break
        return alerts

    def check_sql_injection(self, requests: list[dict]) -> list[Alert]:
        alerts: list[Alert] = []
        rule = self.rules.get("SQL_INJECT_010")
        if not rule or not rule.enabled:
            return alerts
        sqli_patterns = [
            r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|CREATE|EXEC)\b)",
            r"(--|#|\/\*|\*\/)",
            r"(\bOR\b\s+\b\d+\b\s*=\s*\b\d+\b)",
            r"(;\s*(DROP|DELETE|UPDATE|INSERT))",
            r"(CHAR\s*\(|0x[0-9a-fA-F]+)",
        ]
        for req in requests:
            params = req.get("parameters", {})
            url = req.get("url", "")
            body = req.get("body", "")
            combined = f"{url} {str(params)} {body}"
            for pattern in sqli_patterns:
                if re.search(pattern, combined, re.IGNORECASE):
                    alert = Alert(
                        alert_id=str(uuid.uuid4()),
                        rule_id=rule.rule_id,
                        rule_name=rule.name,
                        severity=rule.severity,
                        message=f"SQL injection attempt detected in {req.get('method', 'GET')} {url}",
                        source_ip=req.get("source_ip", ""),
                        destination_ip=req.get("destination_ip", ""),
                        timestamp=datetime.utcnow(),
                        mitre_tactic=rule.mitre_tactic,
                        mitre_technique=rule.mitre_technique,
                        raw_event=req,
                    )
                    alerts.append(alert)
                    self.alerts.append(alert)
                    rule.detection_count += 1
                    rule.last_triggered = datetime.utcnow()
                    break
        return alerts

    def check_xss(self, requests: list[dict]) -> list[Alert]:
        alerts: list[Alert] = []
        rule = self.rules.get("XSS_011")
        if not rule or not rule.enabled:
            return alerts
        xss_patterns = [
            r"<script[^>]*>",
            r"javascript\s*:",
            r"on\w+\s*=",
            r"<iframe",
            r"<object",
            r"<embed",
            r"eval\s*\(",
            r"document\s*\.\s*(cookie|write|location)",
        ]
        for req in requests:
            params = req.get("parameters", {})
            url = req.get("url", "")
            body = req.get("body", "")
            combined = f"{url} {str(params)} {body}"
            for pattern in xss_patterns:
                if re.search(pattern, combined, re.IGNORECASE):
                    alert = Alert(
                        alert_id=str(uuid.uuid4()),
                        rule_id=rule.rule_id,
                        rule_name=rule.name,
                        severity=rule.severity,
                        message=f"XSS attempt detected in {req.get('method', 'GET')} {url}",
                        source_ip=req.get("source_ip", ""),
                        destination_ip=req.get("destination_ip", ""),
                        timestamp=datetime.utcnow(),
                        mitre_tactic=rule.mitre_tactic,
                        mitre_technique=rule.mitre_technique,
                        raw_event=req,
                    )
                    alerts.append(alert)
                    self.alerts.append(alert)
                    rule.detection_count += 1
                    rule.last_triggered = datetime.utcnow()
                    break
        return alerts

    def check_path_traversal(self, requests: list[dict]) -> list[Alert]:
        alerts: list[Alert] = []
        rule = self.rules.get("PATH_TRAV_012")
        if not rule or not rule.enabled:
            return alerts
        traversal_patterns = [
            r"\.\.\/",
            r"\.\.\\",
            r"%2e%2e%2f",
            r"%2e%2e%5c",
            r"\.\.%2f",
            r"\.\.%5c",
            r"%252e%252e",
        ]
        for req in requests:
            url = req.get("url", "")
            params = str(req.get("parameters", {}))
            combined = f"{url} {params}"
            for pattern in traversal_patterns:
                if re.search(pattern, combined, re.IGNORECASE):
                    alert = Alert(
                        alert_id=str(uuid.uuid4()),
                        rule_id=rule.rule_id,
                        rule_name=rule.name,
                        severity=rule.severity,
                        message=f"Path traversal attempt detected in {url}",
                        source_ip=req.get("source_ip", ""),
                        destination_ip=req.get("destination_ip", ""),
                        timestamp=datetime.utcnow(),
                        mitre_tactic=rule.mitre_tactic,
                        mitre_technique=rule.mitre_technique,
                        raw_event=req,
                    )
                    alerts.append(alert)
                    self.alerts.append(alert)
                    rule.detection_count += 1
                    rule.last_triggered = datetime.utcnow()
                    break
        return alerts

    def check_suspicious_process(self, events: list[dict]) -> list[Alert]:
        alerts: list[Alert] = []
        rule = self.rules.get("SUSP_PROC_013")
        if not rule or not rule.enabled:
            return alerts
        suspicious_processes = {
            "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe",
            "mshta.exe", "regsvr32.exe", "rundll32.exe", "certutil.exe",
            "bitsadmin.exe", "msiexec.exe", "installutil.exe", "msbuild.exe",
            "regasm.exe", "regsvcs.exe", "wmic.exe", "at.exe",
        }
        for event in events:
            process = event.get("process_name", "").lower()
            parent = event.get("parent_process", "").lower()
            if process in suspicious_processes:
                alert = Alert(
                    alert_id=str(uuid.uuid4()),
                    rule_id=rule.rule_id,
                    rule_name=rule.name,
                    severity=rule.severity,
                    message=f"Suspicious process execution: {process} (parent: {parent})",
                    source_ip=event.get("source_ip", ""),
                    destination_ip=event.get("destination_ip", ""),
                    timestamp=datetime.utcnow(),
                    mitre_tactic=rule.mitre_tactic,
                    mitre_technique=rule.mitre_technique,
                    raw_event=event,
                )
                alerts.append(alert)
                self.alerts.append(alert)
                rule.detection_count += 1
                rule.last_triggered = datetime.utcnow()
        return alerts

    def check_anomalous_login(self, events: list[dict], known_locations: dict[str, set[str]] | None = None) -> list[Alert]:
        alerts: list[Alert] = []
        rule = self.rules.get("ANOM_LOGIN_014")
        if not rule or not rule.enabled:
            return alerts
        known_locations = known_locations or {}
        for event in events:
            if event.get("event_type") != "successful_login":
                continue
            user = event.get("user", "")
            location = event.get("geo_location", "")
            hour = event.get("hour", -1)
            is_new_location = user in known_locations and location not in known_locations[user]
            is_odd_hour = hour < 6 or hour > 22
            if is_new_location or is_odd_hour:
                reason = []
                if is_new_location:
                    reason.append(f"new location '{location}'")
                if is_odd_hour:
                    reason.append(f"login at unusual hour ({hour}:00)")
                alert = Alert(
                    alert_id=str(uuid.uuid4()),
                    rule_id=rule.rule_id,
                    rule_name=rule.name,
                    severity=rule.severity,
                    message=f"Anomalous login for {user}: {', '.join(reason)}",
                    source_ip=event.get("source_ip", ""),
                    destination_ip=event.get("destination_ip", ""),
                    timestamp=datetime.utcnow(),
                    mitre_tactic=rule.mitre_tactic,
                    mitre_technique=rule.mitre_technique,
                    raw_event=event,
                )
                alerts.append(alert)
                self.alerts.append(alert)
                rule.detection_count += 1
                rule.last_triggered = datetime.utcnow()
        return alerts

    def check_unusual_dns(self, queries: list[dict], new_domain_days: int = 30) -> list[Alert]:
        alerts: list[Alert] = []
        rule = self.rules.get("UNUS_DNS_015")
        if not rule or not rule.enabled:
            return alerts
        for query in queries:
            qname = query.get("query_name", "")
            registration_date = query.get("domain_registration_date")
            if registration_date:
                days_old = (datetime.utcnow() - datetime.fromisoformat(registration_date)).days
                if days_old < new_domain_days:
                    alert = Alert(
                        alert_id=str(uuid.uuid4()),
                        rule_id=rule.rule_id,
                        rule_name=rule.name,
                        severity=rule.severity,
                        message=f"DNS query to newly registered domain ({days_old} days old): {qname}",
                        source_ip=query.get("source_ip", ""),
                        destination_ip=query.get("dns_server", ""),
                        timestamp=datetime.utcnow(),
                        mitre_tactic=rule.mitre_tactic,
                        mitre_technique=rule.mitre_technique,
                        raw_event=query,
                    )
                    alerts.append(alert)
                    self.alerts.append(alert)
                    rule.detection_count += 1
                    rule.last_triggered = datetime.utcnow()
        return alerts

    def check_large_transfer(self, events: list[dict], threshold_mb: float = 500) -> list[Alert]:
        alerts: list[Alert] = []
        rule = self.rules.get("LARGE_XFER_016")
        if not rule or not rule.enabled:
            return alerts
        for event in events:
            bytes_transferred = event.get("bytes_transferred", 0)
            size_mb = bytes_transferred / (CONST_1024 * CONST_1024)
            if size_mb > threshold_mb:
                alert = Alert(
                    alert_id=str(uuid.uuid4()),
                    rule_id=rule.rule_id,
                    rule_name=rule.name,
                    severity=rule.severity,
                    message=f"Large data transfer: {size_mb:.1f} MB from {event.get('source_ip', '')} to {event.get('destination_ip', '')}",
                    source_ip=event.get("source_ip", ""),
                    destination_ip=event.get("destination_ip", ""),
                    timestamp=datetime.utcnow(),
                    mitre_tactic=rule.mitre_tactic,
                    mitre_technique=rule.mitre_technique,
                    raw_event=event,
                )
                alerts.append(alert)
                self.alerts.append(alert)
                rule.detection_count += 1
                rule.last_triggered = datetime.utcnow()
        return alerts

    def check_scanning_activity(self, events: list[dict], target_threshold: int = CONST_5) -> list[Alert]:
        alerts: list[Alert] = []
        rule = self.rules.get("SCAN_ACT_017")
        if not rule or not rule.enabled:
            return alerts
        targets_by_source: dict[str, set[str]] = defaultdict(set)
        for event in events:
            src = event.get("source_ip", "")
            dst = event.get("destination_ip", "")
            targets_by_source[src].add(dst)
        for src_ip, targets in targets_by_source.items():
            if len(targets) >= target_threshold:
                alert = Alert(
                    alert_id=str(uuid.uuid4()),
                    rule_id=rule.rule_id,
                    rule_name=rule.name,
                    severity=rule.severity,
                    message=f"Internal scanning from {src_ip}: {len(targets)} unique targets",
                    source_ip=src_ip,
                    destination_ip="",
                    timestamp=datetime.utcnow(),
                    mitre_tactic=rule.mitre_tactic,
                    mitre_technique=rule.mitre_technique,
                    raw_event={"unique_targets": sorted(targets)},
                )
                alerts.append(alert)
                self.alerts.append(alert)
                rule.detection_count += 1
                rule.last_triggered = datetime.utcnow()
        return alerts

    def check_suspicious_user_agent(self, requests: list[dict]) -> list[Alert]:
        alerts: list[Alert] = []
        rule = self.rules.get("SUSP_UA_019")
        if not rule or not rule.enabled:
            return alerts
        suspicious_agents = [
            r"cobalt.?strike",
            r"meterpreter",
            r"empire",
            r"covenant",
            r"sliver",
            r"brute.?ratel",
            r"atomic.?red.?team",
        ]
        for req in requests:
            ua = req.get("user_agent", "").lower()
            for pattern in suspicious_agents:
                if re.search(pattern, ua, re.IGNORECASE):
                    alert = Alert(
                        alert_id=str(uuid.uuid4()),
                        rule_id=rule.rule_id,
                        rule_name=rule.name,
                        severity=rule.severity,
                        message=f"Suspicious user-agent detected: {req.get('user_agent', '')}",
                        source_ip=req.get("source_ip", ""),
                        destination_ip=req.get("destination_ip", ""),
                        timestamp=datetime.utcnow(),
                        mitre_tactic=rule.mitre_tactic,
                        mitre_technique=rule.mitre_technique,
                        raw_event=req,
                    )
                    alerts.append(alert)
                    self.alerts.append(alert)
                    rule.detection_count += 1
                    rule.last_triggered = datetime.utcnow()
                    break
        return alerts

    def check_known_iocs(self, events: list[dict], ioc_set: set[str]) -> list[Alert]:
        alerts: list[Alert] = []
        rule = self.rules.get("KNOWN_IOC_018")
        if not rule or not rule.enabled:
            return alerts
        for event in events:
            event_values = {str(v).lower() for v in event.values()}
            matches = event_values & {i.lower() for i in ioc_set}
            if matches:
                alert = Alert(
                    alert_id=str(uuid.uuid4()),
                    rule_id=rule.rule_id,
                    rule_name=rule.name,
                    severity=rule.severity,
                    message=f"Known IOC match: {', '.join(matches)}",
                    source_ip=event.get("source_ip", ""),
                    destination_ip=event.get("destination_ip", ""),
                    timestamp=datetime.utcnow(),
                    mitre_tactic=rule.mitre_tactic,
                    mitre_technique=rule.mitre_technique,
                    raw_event=event,
                    indicator_matches=list(matches),
                )
                alerts.append(alert)
                self.alerts.append(alert)
                rule.detection_count += 1
                rule.last_triggered = datetime.utcnow()
        return alerts

    def check_api_abuse(self, events: list[dict], rate_threshold: int = 100, window_seconds: int = CONST_60) -> list[Alert]:
        alerts: list[Alert] = []
        rule = self.rules.get("API_ABUSE_020")
        if not rule or not rule.enabled:
            return alerts
        requests_by_source: dict[str, list[dict]] = defaultdict(list)
        for event in events:
            src = event.get("source_ip", "")
            requests_by_source[src].append(event)
        for src_ip, reqs in requests_by_source.items():
            if len(reqs) >= rate_threshold:
                unique_endpoints = set(r.get("url", "") for r in reqs)
                alert = Alert(
                    alert_id=str(uuid.uuid4()),
                    rule_id=rule.rule_id,
                    rule_name=rule.name,
                    severity=rule.severity,
                    message=f"API abuse from {src_ip}: {len(reqs)} requests to {len(unique_endpoints)} endpoints",
                    source_ip=src_ip,
                    destination_ip=reqs[0].get("destination_ip", ""),
                    timestamp=datetime.utcnow(),
                    mitre_tactic=rule.mitre_tactic,
                    mitre_technique=rule.mitre_technique,
                    raw_event={"request_count": len(reqs), "endpoints": sorted(unique_endpoints)},
                )
                alerts.append(alert)
                self.alerts.append(alert)
                rule.detection_count += 1
                rule.last_triggered = datetime.utcnow()
        return alerts

    def check_credential_stuffing(self, events: list[dict], unique_users_threshold: int = 10) -> list[Alert]:
        alerts: list[Alert] = []
        rule = self.rules.get("CRED_STUFF_009")
        if not rule or not rule.enabled:
            return alerts
        failed_by_source: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
        for event in events:
            if event.get("event_type") == "failed_login":
                src = event.get("source_ip", "")
                user = event.get("user", "")
                failed_by_source[src][user] += 1
        for src_ip, users in failed_by_source.items():
            if len(users) >= unique_users_threshold:
                alert = Alert(
                    alert_id=str(uuid.uuid4()),
                    rule_id=rule.rule_id,
                    rule_name=rule.name,
                    severity=rule.severity,
                    message=f"Credential stuffing from {src_ip}: {len(users)} unique users targeted",
                    source_ip=src_ip,
                    destination_ip="",
                    timestamp=datetime.utcnow(),
                    mitre_tactic=rule.mitre_tactic,
                    mitre_technique=rule.mitre_technique,
                    raw_event={"targeted_users": list(users.keys())},
                )
                alerts.append(alert)
                self.alerts.append(alert)
                rule.detection_count += 1
                rule.last_triggered = datetime.utcnow()
        return alerts

    def check_coin_mining(self, events: list[dict]) -> list[Alert]:
        alerts: list[Alert] = []
        rule = self.rules.get("COAL_DOLL_021")
        if not rule or not rule.enabled:
            return alerts
        mining_indicators = [
            r"stratum\+tcp",
            r"stratum\+ssl",
            r":3333",
            r":4444",
            r":5555",
            r":7777",
            r":8888",
            r":9999",
            r"xmrig",
            r"minerd",
            r"cpuminer",
            r"ethminer",
            r"nicehash",
            r"pool\.minexmr",
        ]
        for event in events:
            combined = f"{event.get('process_name', '')} {event.get('command', '')} {event.get('url', '')}"
            for pattern in mining_indicators:
                if re.search(pattern, combined, re.IGNORECASE):
                    alert = Alert(
                        alert_id=str(uuid.uuid4()),
                        rule_id=rule.rule_id,
                        rule_name=rule.name,
                        severity=rule.severity,
                        message=f"Coin mining activity detected: {event.get('process_name', event.get('url', 'unknown'))}",
                        source_ip=event.get("source_ip", ""),
                        destination_ip=event.get("destination_ip", ""),
                        timestamp=datetime.utcnow(),
                        mitre_tactic=rule.mitre_tactic,
                        mitre_technique=rule.mitre_technique,
                        raw_event=event,
                    )
                    alerts.append(alert)
                    self.alerts.append(alert)
                    rule.detection_count += 1
                    rule.last_triggered = datetime.utcnow()
                    break
        return alerts

    def check_ransomware(self, events: list[dict]) -> list[Alert]:
        alerts: list[Alert] = []
        rule = self.rules.get("RANSOM_022")
        if not rule or not rule.enabled:
            return alerts
        ransomware_patterns = [
            r"\.encrypted",
            r"\.locked",
            r"\.crypto",
            r"\.wncry",
            r"\.cerber",
            r"\.zepto",
            r"\.odin",
            r"\.thor",
            r"restore_files",
            r"how_to_decrypt",
            r"vssadmin\s+delete\s+shadows",
            r"bcdedit\s+\/set\s+{default}\s+recoveryenabled\s+no",
            r"wmic\s+shadowcopy\s+delete",
        ]
        for event in events:
            combined = f"{event.get('process_name', '')} {event.get('command', '')} {event.get('file_name', '')} {event.get('file_path', '')}"
            for pattern in ransomware_patterns:
                if re.search(pattern, combined, re.IGNORECASE):
                    alert = Alert(
                        alert_id=str(uuid.uuid4()),
                        rule_id=rule.rule_id,
                        rule_name=rule.name,
                        severity=rule.severity,
                        message=f"Ransomware indicator detected: {pattern}",
                        source_ip=event.get("source_ip", ""),
                        destination_ip=event.get("destination_ip", ""),
                        timestamp=datetime.utcnow(),
                        mitre_tactic=rule.mitre_tactic,
                        mitre_technique=rule.mitre_technique,
                        raw_event=event,
                    )
                    alerts.append(alert)
                    self.alerts.append(alert)
                    rule.detection_count += 1
                    rule.last_triggered = datetime.utcnow()
                    break
        return alerts

    def _calculate_entropy(self, text: str) -> float:
        import math
        if not text:
            return 0.0
        freq: dict[str, int] = {}
        for char in text:
            freq[char] = freq.get(char, 0) + 1
        length = len(text)
        entropy = 0.0
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy

    def mark_false_positive(self, alert_id: str, reason: str, analyst: str) -> None:
        for alert in self.alerts:
            if alert.alert_id == alert_id:
                alert.is_false_positive = True
                alert.investigation_notes = reason
                rule = self.rules.get(alert.rule_id)
                if rule:
                    rule.false_positive_count += 1
                record = FalsePositiveRecord(
                    alert_id=alert_id,
                    rule_id=alert.rule_id,
                    reason=reason,
                    analyst=analyst,
                    timestamp=datetime.utcnow(),
                )
                self.false_positives.append(record)
                break

    def get_false_positive_rate(self, rule_id: str) -> float:
        rule = self.rules.get(rule_id)
        if not rule or rule.detection_count == 0:
            return 0.0
        return rule.false_positive_count / rule.detection_count

    def get_rule_stats(self) -> dict[str, dict[str, Any]]:
        stats: dict[str, dict[str, Any]] = {}
        for rule_id, rule in self.rules.items():
            stats[rule_id] = {
                "name": rule.name,
                "severity": rule.severity.value,
                "enabled": rule.enabled,
                "detection_count": rule.detection_count,
                "false_positive_count": rule.false_positive_count,
                "false_positive_rate": self.get_false_positive_rate(rule_id),
                "last_triggered": rule.last_triggered.isoformat() if rule.last_triggered else None,
            }
        return stats

    def get_alerts(self, severity: Severity | None = None, include_false_positives: bool = False) -> list[Alert]:
        result = self.alerts
        if severity:
            result = [a for a in result if a.severity == severity]
        if not include_false_positives:
            result = [a for a in result if not a.is_false_positive]
        return result

    def get_unresolved_alerts(self) -> list[Alert]:
        return [a for a in self.alerts if not a.is_false_positive and not a.investigation_notes]

    def get_all_rules(self) -> list[DetectionRule]:
        return list(self.rules.values())

    def get_mitre_coverage(self) -> dict[str, list[str]]:
        coverage: dict[str, list[str]] = defaultdict(list)
        for rule in self.rules.values():
            coverage[rule.mitre_tactic].append(f"{rule.name} ({rule.mitre_technique})")
        return dict(coverage)
