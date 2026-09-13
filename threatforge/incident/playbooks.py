from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class PlaybookPhase(Enum):
    PREPARATION = "preparation"
    DETECTION = "detection"
    CONTAINMENT = "containment"
    ERADICATION = "eradication"
    RECOVERY = "recovery"
    LESSONS_LEARNED = "lessons_learned"


@dataclass
class PlaybookStep:
    step_id: str
    phase: PlaybookPhase
    order: int
    title: str
    description: str
    tools: list[str] = field(default_factory=list)
    commands: list[str] = field(default_factory=list)
    contacts: list[str] = field(default_factory=list)
    containment_actions: list[str] = field(default_factory=list)
    expected_outcome: str = ""
    estimated_duration_minutes: int = 15
    requires_approval: bool = False
    approval_role: str = ""


@dataclass
class Playbook:
    playbook_id: str
    name: str
    description: str
    scenario: str
    severity适用: list[str] = field(default_factory=list)
    steps: list[PlaybookStep] = field(default_factory=list)
    enabled: bool = True
    version: str = "1.0"
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    tags: list[str] = field(default_factory=list)
    estimated_total_duration_minutes: int = 0
    last_used: datetime | None = None
    usage_count: int = 0


@dataclass
class PlaybookExecution:
    execution_id: str
    playbook_id: str
    incident_id: str
    started_at: datetime
    completed_at: datetime | None = None
    status: str = "running"
    completed_steps: list[str] = field(default_factory=list)
    current_step: str = ""
    notes: list[dict[str, Any]] = field(default_factory=list)


class PlaybookManager:
    def __init__(self) -> None:
        self.playbooks: dict[str, Playbook] = {}
        self.executions: dict[str, PlaybookExecution] = {}
        self._initialize_default_playbooks()

    def _initialize_default_playbooks(self) -> None:
        self._create_ransomware_playbook()
        self._create_phishing_playbook()
        self._create_data_breach_playbook()
        self._create_insider_threat_playbook()
        self._create_ddos_playbook()
        self._create_malware_playbook()
        self._create_account_compromise_playbook()
        self._create_lateral_movement_playbook()
        self._create_data_exfil_playbook()
        self._create_supply_chain_playbook()

    def _create_ransomware_playbook(self) -> Playbook:
        steps = [
            PlaybookStep(
                step_id=str(uuid.uuid4()), phase=PlaybookPhase.DETECTION, order=1,
                title="Verify ransomware activity",
                description="Confirm ransomware execution by checking for encrypted files, ransom notes, and shadow copy deletion",
                tools=["EDR console", "Volatility", "disk forensic tools"],
                commands=["vssadmin list shadows", "wmic shadowcopy list brief"],
                expected_outcome="Confirm ransomware variant and scope of encryption",
                estimated_duration_minutes=15,
            ),
            PlaybookStep(
                step_id=str(uuid.uuid4()), phase=PlaybookPhase.CONTAINMENT, order=2,
                title="Isolate affected systems",
                description="Network-isolate all affected and potentially affected systems immediately",
                tools=["Network switch management", "EDR isolation", "firewall rules"],
                containment_actions=[
                    "Disable network adapters on affected hosts",
                    "Block C2 IPs at perimeter firewall",
                    "Isolate VLAN segment if possible",
                    "Disable compromised accounts",
                ],
                expected_outcome="Affected systems are network-isolated to prevent spread",
                estimated_duration_minutes=10,
                requires_approval=True,
                approval_role="SOC Manager",
            ),
            PlaybookStep(
                step_id=str(uuid.uuid4()), phase=PlaybookPhase.CONTAINMENT, order=3,
                title="Preserve evidence",
                description="Collect memory dumps and critical logs before eradication",
                tools=["WinPmem", "FTK Imager", "Log Collector"],
                commands=[
                    "winpmem_mini_x64.exe memory.raw",
                    "wevtutil epl Security security.evtx",
                    "wevtutil epl System system.evtx",
                ],
                expected_outcome="Forensic images and logs preserved for investigation",
                estimated_duration_minutes=30,
            ),
            PlaybookStep(
                step_id=str(uuid.uuid4()), phase=PlaybookPhase.ERADICATION, order=4,
                title="Identify ransomware variant",
                description="Use ID Ransomware or No More Ransom to identify the variant and check for decryptors",
                tools=["ID Ransomware", "No More Ransom", "VirusTotal"],
                expected_outcome="Ransomware variant identified, decryption availability determined",
                estimated_duration_minutes=30,
            ),
            PlaybookStep(
                step_id=str(uuid.uuid4()), phase=PlaybookPhase.ERADICATION, order=5,
                title="Remove malware artifacts",
                description="Delete ransomware executables, scheduled tasks, and persistence mechanisms",
                tools=["EDR console", "Autoruns", "PowerShell"],
                commands=[
                    "Get-ScheduledTask | Where-Object {$_.Actions.Execute -like '*ransom*'} | Unregister-ScheduledTask",
                    "Remove-Item -Path $env:TEMP\\*.exe -Force",
                ],
                expected_outcome="All malware artifacts removed from affected systems",
                estimated_duration_minutes=60,
            ),
            PlaybookStep(
                step_id=str(uuid.uuid4()), phase=PlaybookPhase.RECOVERY, order=6,
                title="Restore from backups",
                description="Rebuild systems from known-good backups after verifying backup integrity",
                tools=["Backup solution", "System imaging tools"],
                commands=[
                    "wbadmin get versions",
                    "wbadmin start systemstaterecovery -version:<version>",
                ],
                expected_outcome="Systems restored to pre-incident state",
                estimated_duration_minutes=240,
            ),
            PlaybookStep(
                step_id=str(uuid.uuid4()), phase=PlaybookPhase.RECOVERY, order=7,
                title="Reset credentials and harden",
                description="Reset all potentially compromised credentials and apply security hardening",
                tools=["Active Directory", "Group Policy", "EDR"],
                commands=[
                    "Reset-ADAccount -Identity *",
                    "Invoke-GPUpdate -Force",
                ],
                containment_actions=[
                    "Reset all domain user passwords",
                    "Reset service account credentials",
                    "Enable MFA for all accounts",
                    "Apply emergency patches",
                ],
                expected_outcome="All credentials rotated and systems hardened",
                estimated_duration_minutes=120,
            ),
            PlaybookStep(
                step_id=str(uuid.uuid4()), phase=PlaybookPhase.LESSONS_LEARNED, order=8,
                title="Conduct lessons learned",
                description="Document findings, timeline, and improvements for future prevention",
                tools=["Documentation templates"],
                expected_outcome="Lessons learned document completed with actionable recommendations",
                estimated_duration_minutes=60,
            ),
        ]
        total_duration = sum(s.estimated_duration_minutes for s in steps)
        playbook = Playbook(
            playbook_id=str(uuid.uuid4()),
            name="Ransomware Response",
            description="Comprehensive playbook for responding to ransomware incidents including verification, containment, eradication, and recovery",
            scenario="ransomware",
            steps=steps,
            tags=["ransomware", "encryption", "malware", "critical"],
            estimated_total_duration_minutes=total_duration,
        )
        self.playbooks[playbook.playbook_id] = playbook
        return playbook

    def _create_phishing_playbook(self) -> Playbook:
        steps = [
            PlaybookStep(
                step_id=str(uuid.uuid4()), phase=PlaybookPhase.DETECTION, order=1,
                title="Analyze phishing email",
                description="Examine email headers, URLs, and attachments for malicious indicators",
                tools=["Email gateway", "URLScan.io", "VirusTotal", "sandbox"],
                expected_outcome="Phishing email analyzed, IOCs extracted",
                estimated_duration_minutes=20,
            ),
            PlaybookStep(
                step_id=str(uuid.uuid4()), phase=PlaybookPhase.CONTAINMENT, order=2,
                title="Block malicious indicators",
                description="Block phishing URLs, sender domains, and malicious attachments at all gateways",
                tools=["Email gateway", "DNS sinkhole", "proxy filter"],
                containment_actions=[
                    "Block sender domain at email gateway",
                    "Add malicious URLs to proxy blocklist",
                    "Quarantine all copies of phishing email",
                    "Block malicious attachment hashes",
                ],
                expected_outcome="All malicious indicators blocked across the organization",
                estimated_duration_minutes=10,
            ),
            PlaybookStep(
                step_id=str(uuid.uuid4()), phase=PlaybookPhase.CONTAINMENT, order=3,
                title="Identify and reset compromised accounts",
                description="Find users who clicked links or submitted credentials and reset their accounts",
                tools=["Email gateway logs", "AD console", "SSO logs"],
                expected_outcome="All potentially compromised accounts identified and reset",
                estimated_duration_minutes=30,
            ),
            PlaybookStep(
                step_id=str(uuid.uuid4()), phase=PlaybookPhase.ERADICATION, order=4,
                title="Remove malicious content",
                description="Delete phishing emails from all mailboxes and remove any installed malware",
                tools=["Email admin console", "EDR", "PowerShell"],
                commands=[
                    "Get-Mailbox -ResultSize Unlimited | Search-Mailbox -SearchQuery 'Subject:\"Phishing Subject\"' -DeleteContent",
                ],
                expected_outcome="All phishing content removed from environment",
                estimated_duration_minutes=30,
            ),
            PlaybookStep(
                step_id=str(uuid.uuid4()), phase=PlaybookPhase.RECOVERY, order=5,
                title="Verify and restore",
                description="Verify no persistent access was gained and restore any affected services",
                tools=["EDR", "AD audit tools"],
                expected_outcome="Environment verified clean, services restored",
                estimated_duration_minutes=60,
            ),
            PlaybookStep(
                step_id=str(uuid.uuid4()), phase=PlaybookPhase.LESSONS_LEARNED, order=6,
                title="Security awareness follow-up",
                description="Update training materials and conduct targeted awareness for affected users",
                tools=["Security awareness platform"],
                expected_outcome="Training materials updated, affected users retrained",
                estimated_duration_minutes=30,
            ),
        ]
        total_duration = sum(s.estimated_duration_minutes for s in steps)
        playbook = Playbook(
            playbook_id=str(uuid.uuid4()),
            name="Phishing Response",
            description="Playbook for responding to phishing campaigns including analysis, containment, and user remediation",
            scenario="phishing",
            steps=steps,
            tags=["phishing", "email", "social_engineering", "credential_theft"],
            estimated_total_duration_minutes=total_duration,
        )
        self.playbooks[playbook.playbook_id] = playbook
        return playbook

    def _create_data_breach_playbook(self) -> Playbook:
        steps = [
            PlaybookStep(
                step_id=str(uuid.uuid4()), phase=PlaybookPhase.DETECTION, order=1,
                title="Confirm data breach",
                description="Verify that sensitive data has been accessed or exfiltrated",
                tools=["DLP console", "Database audit logs", "Network forensic tools"],
                expected_outcome="Breach confirmed with scope of affected data",
                estimated_duration_minutes=30,
            ),
            PlaybookStep(
                step_id=str(uuid.uuid4()), phase=PlaybookPhase.CONTAINMENT, order=2,
                title="Contain the breach",
                description="Stop ongoing data exfiltration and isolate affected systems",
                tools=["DLP", "Firewall", "EDR"],
                containment_actions=[
                    "Block exfiltration channels",
                    "Isolate compromised systems",
                    "Revoke API keys and tokens",
                    "Disable compromised service accounts",
                ],
                expected_outcome="Data exfiltration stopped, affected systems isolated",
                estimated_duration_minutes=15,
            ),
            PlaybookStep(
                step_id=str(uuid.uuid4()), phase=PlaybookPhase.DETECTION, order=3,
                title="Assess data exposure",
                description="Determine what data was accessed, volume, and sensitivity classification",
                tools=["Database logs", "DLP logs", "Cloud access logs"],
                expected_outcome="Complete assessment of exposed data types and volume",
                estimated_duration_minutes=120,
            ),
            PlaybookStep(
                step_id=str(uuid.uuid4()), phase=PlaybookPhase.ERADICATION, order=4,
                title="Eradicate threat actor",
                description="Remove all threat actor access and persistence mechanisms",
                tools=["EDR", "AD audit tools", "Cloud IAM"],
                expected_outcome="Threat actor access fully removed",
                estimated_duration_minutes=60,
            ),
            PlaybookStep(
                step_id=str(uuid.uuid4()), phase=PlaybookPhase.RECOVERY, order=5,
                title="Notify stakeholders",
                description="Execute notification procedures per legal and regulatory requirements",
                tools=["Legal counsel", "PR team", "Regulatory filing tools"],
                contacts=["Legal", "Compliance", "Public Relations", "Executive Team"],
                expected_outcome="All required notifications completed within regulatory timelines",
                estimated_duration_minutes=60,
            ),
            PlaybookStep(
                step_id=str(uuid.uuid4()), phase=PlaybookPhase.LESSONS_LEARNED, order=6,
                title="Post-breach review",
                description="Conduct comprehensive review and update data protection controls",
                tools=["Documentation templates", "Risk assessment tools"],
                expected_outcome="Post-breach report with remediation plan completed",
                estimated_duration_minutes=120,
            ),
        ]
        total_duration = sum(s.estimated_duration_minutes for s in steps)
        playbook = Playbook(
            playbook_id=str(uuid.uuid4()),
            name="Data Breach Response",
            description="Playbook for data breach incidents including scope assessment, containment, and regulatory notification",
            scenario="data_breach",
            steps=steps,
            tags=["data_breach", "exfiltration", "sensitive_data", "regulatory"],
            estimated_total_duration_minutes=total_duration,
        )
        self.playbooks[playbook.playbook_id] = playbook
        return playbook

    def _create_insider_threat_playbook(self) -> Playbook:
        steps = [
            PlaybookStep(
                step_id=str(uuid.uuid4()), phase=PlaybookPhase.DETECTION, order=1,
                title="Validate insider threat indicators",
                description="Correlate behavioral indicators with technical evidence to confirm insider threat",
                tools=["UEBA", "DLP", "SIEM", "HR records"],
                expected_outcome="Insider threat validated with supporting evidence",
                estimated_duration_minutes=60,
            ),
            PlaybookStep(
                step_id=str(uuid.uuid4()), phase=PlaybookPhase.CONTAINMENT, order=2,
                title="Covert containment",
                description="Discreetly limit access without alerting the insider",
                tools=["AD console", "DLP", "Network monitoring"],
                containment_actions=[
                    "Implement covert monitoring",
                    "Restrict access during off-hours only",
                    "Enable enhanced logging",
                    "Coordinate with HR and Legal",
                ],
                expected_outcome="Insider threat contained discreetly",
                estimated_duration_minutes=30,
            ),
            PlaybookStep(
                step_id=str(uuid.uuid4()), phase=PlaybookPhase.ERADICATION, order=3,
                title="Collect evidence for HR/legal",
                description="Preserve all evidence in forensically sound manner for potential legal action",
                tools=["Forensic imaging tools", "Log archival"],
                expected_outcome="Evidence collected and chain of custody maintained",
                estimated_duration_minutes=120,
            ),
            PlaybookStep(
                step_id=str(uuid.uuid4()), phase=PlaybookPhase.ERADICATION, order=4,
                title="Execute separation",
                description="Coordinate with HR for employee separation and access revocation",
                tools=["AD console", "Badge system", "VPN system"],
                contacts=["HR", "Legal", "Physical Security"],
                expected_outcome="Employee separated, all access revoked",
                estimated_duration_minutes=60,
            ),
            PlaybookStep(
                step_id=str(uuid.uuid4()), phase=PlaybookPhase.RECOVERY, order=5,
                title="Assess and remediate damage",
                description="Evaluate what data or systems were compromised and remediate",
                tools=["DLP", "Database audit", "EDR"],
                expected_outcome="All insider damage assessed and remediated",
                estimated_duration_minutes=180,
            ),
            PlaybookStep(
                step_id=str(uuid.uuid4()), phase=PlaybookPhase.LESSONS_LEARNED, order=6,
                title="Improve insider threat program",
                description="Update detection rules, policies, and controls based on findings",
                tools=["SIEM", "Policy templates"],
                expected_outcome="Insider threat program enhanced with lessons learned",
                estimated_duration_minutes=60,
            ),
        ]
        total_duration = sum(s.estimated_duration_minutes for s in steps)
        playbook = Playbook(
            playbook_id=str(uuid.uuid4()),
            name="Insider Threat Response",
            description="Playbook for insider threat incidents with emphasis on evidence preservation and legal coordination",
            scenario="insider_threat",
            steps=steps,
            tags=["insider_threat", "data_theft", "sabotage", "hr"],
            estimated_total_duration_minutes=total_duration,
        )
        self.playbooks[playbook.playbook_id] = playbook
        return playbook

    def _create_ddos_playbook(self) -> Playbook:
        steps = [
            PlaybookStep(
                step_id=str(uuid.uuid4()), phase=PlaybookPhase.DETECTION, order=1,
                title="Identify DDoS attack type and vectors",
                description="Determine if volumetric, protocol, or application layer attack and identify attack vectors",
                tools=["Network monitoring", "Flow analysis", "WAF logs"],
                expected_outcome="Attack type, volume, and vectors identified",
                estimated_duration_minutes=10,
            ),
            PlaybookStep(
                step_id=str(uuid.uuid4()), phase=PlaybookPhase.CONTAINMENT, order=2,
                title="Activate DDoS mitigation",
                description="Engage upstream DDoS protection and configure scrubbing centers",
                tools=["CDN/DDoS provider", "ISP NOC", "BGP Flowspec"],
                contacts=["ISP", "DDoS mitigation provider", "CDN provider"],
                containment_actions=[
                    "Activate cloud DDoS scrubbing",
                    "Enable rate limiting",
                    "Deploy blackhole routing for worst-case",
                    "Scale infrastructure horizontally",
                ],
                expected_outcome="DDoS mitigation activated, traffic being scrubbed",
                estimated_duration_minutes=15,
            ),
            PlaybookStep(
                step_id=str(uuid.uuid4()), phase=PlaybookPhase.CONTAINMENT, order=3,
                title="Protect critical services",
                description="Ensure critical services remain available through failover and prioritization",
                tools=["Load balancer", "DNS management", "Cloud auto-scaling"],
                expected_outcome="Critical services maintained during attack",
                estimated_duration_minutes=15,
            ),
            PlaybookStep(
                step_id=str(uuid.uuid4()), phase=PlaybookPhase.RECOVERY, order=4,
                title="Monitor and tune mitigation",
                description="Continuously monitor attack traffic and tune mitigation rules",
                tools=["DDoS dashboard", "NetFlow", "WAF console"],
                expected_outcome="Attack traffic effectively mitigated",
                estimated_duration_minutes=60,
            ),
            PlaybookStep(
                step_id=str(uuid.uuid4()), phase=PlaybookPhase.LESSONS_LEARNED, order=5,
                title="Post-attack review",
                description="Document attack characteristics and improve DDoS resilience",
                tools=["Documentation templates"],
                expected_outcome="DDoS resilience improved based on attack learnings",
                estimated_duration_minutes=60,
            ),
        ]
        total_duration = sum(s.estimated_duration_minutes for s in steps)
        playbook = Playbook(
            playbook_id=str(uuid.uuid4()),
            name="DDoS Response",
            description="Playbook for DDoS attacks including detection, mitigation activation, and service protection",
            scenario="ddos",
            steps=steps,
            tags=["ddos", "availability", "network", "volumetric"],
            estimated_total_duration_minutes=total_duration,
        )
        self.playbooks[playbook.playbook_id] = playbook
        return playbook

    def _create_malware_playbook(self) -> Playbook:
        steps = [
            PlaybookStep(
                step_id=str(uuid.uuid4()), phase=PlaybookPhase.DETECTION, order=1,
                title="Identify malware type and scope",
                description="Determine malware family, infection vector, and breadth of compromise",
                tools=["EDR", "Sandbox", "VirusTotal", "YARA rules"],
                expected_outcome="Malware identified, infection vector determined",
                estimated_duration_minutes=30,
            ),
            PlaybookStep(
                step_id=str(uuid.uuid4()), phase=PlaybookPhase.CONTAINMENT, order=2,
                title="Isolate infected systems",
                description="Network-isolate all systems showing malware indicators",
                tools=["EDR isolation", "Network access control"],
                containment_actions=[
                    "Isolate infected endpoints",
                    "Block C2 communication",
                    "Quarantine malicious files",
                    "Disable auto-run for removable media",
                ],
                expected_outcome="Infected systems isolated, C2 blocked",
                estimated_duration_minutes=15,
            ),
            PlaybookStep(
                step_id=str(uuid.uuid4()), phase=PlaybookPhase.ERADICATION, order=3,
                title="Remove malware and persistence",
                description="Delete malware binaries, registry entries, scheduled tasks, and other persistence mechanisms",
                tools=["EDR", "Autoruns", "PowerShell", "Malware removal tools"],
                commands=[
                    "Get-Process | Where-Object {$_.Path -like '*malware*'} | Stop-Process -Force",
                    "Remove-Item -Recurse -Force $env:TEMP\\malware_dir",
                ],
                expected_outcome="Malware fully removed from all affected systems",
                estimated_duration_minutes=60,
            ),
            PlaybookStep(
                step_id=str(uuid.uuid4()), phase=PlaybookPhase.RECOVERY, order=4,
                title="Verify clean state",
                description="Scan all systems to verify malware removal and check for secondary payloads",
                tools=["EDR full scan", "Anti-malware scan", "File integrity monitoring"],
                expected_outcome="All systems verified clean",
                estimated_duration_minutes=120,
            ),
            PlaybookStep(
                step_id=str(uuid.uuid4()), phase=PlaybookPhase.LESSONS_LEARNED, order=5,
                title="Update defenses",
                description="Create detection signatures and update security controls based on findings",
                tools=["SIEM", "EDR policy", "Firewall rules"],
                expected_outcome="Detection and prevention capabilities updated",
                estimated_duration_minutes=60,
            ),
        ]
        total_duration = sum(s.estimated_duration_minutes for s in steps)
        playbook = Playbook(
            playbook_id=str(uuid.uuid4()),
            name="Malware Response",
            description="Playbook for general malware incidents including identification, containment, and removal",
            scenario="malware",
            steps=steps,
            tags=["malware", "endpoint", "trojan", "virus"],
            estimated_total_duration_minutes=total_duration,
        )
        self.playbooks[playbook.playbook_id] = playbook
        return playbook

    def _create_account_compromise_playbook(self) -> Playbook:
        steps = [
            PlaybookStep(
                step_id=str(uuid.uuid4()), phase=PlaybookPhase.DETECTION, order=1,
                title="Identify compromised account",
                description="Determine which accounts are compromised and how the compromise occurred",
                tools=["SIEM", "Azure AD logs", "VPN logs", "Email logs"],
                expected_outcome="Compromised accounts identified with compromise vector",
                estimated_duration_minutes=20,
            ),
            PlaybookStep(
                step_id=str(uuid.uuid4()), phase=PlaybookPhase.CONTAINMENT, order=2,
                title="Disable compromised accounts",
                description="Immediately disable or reset all compromised accounts",
                tools=["AD console", "Azure AD", "IAM system"],
                containment_actions=[
                    "Disable compromised accounts",
                    "Revoke active sessions",
                    "Revoke API tokens",
                    "Block attacker IPs",
                ],
                expected_outcome="All compromised accounts disabled and sessions revoked",
                estimated_duration_minutes=10,
            ),
            PlaybookStep(
                step_id=str(uuid.uuid4()), phase=PlaybookPhase.DETECTION, order=3,
                title="Assess attacker actions",
                description="Review logs to determine what actions the attacker performed",
                tools=["SIEM", "CloudTrail", "Azure AD audit logs"],
                expected_outcome="Complete timeline of attacker actions compiled",
                estimated_duration_minutes=60,
            ),
            PlaybookStep(
                step_id=str(uuid.uuid4()), phase=PlaybookPhase.ERADICATION, order=4,
                title="Remove attacker persistence",
                description="Remove any backdoors, forwarding rules, or OAuth apps created by attacker",
                tools=["AD console", "Azure AD", "Exchange admin"],
                commands=[
                    "Get-Mailbox | Where-Object {$_.ForwardingAddress -ne $null}",
                    "Get-AzADApplication | Where-Object {$_.CreatedDateTime -gt $attackStart}",
                ],
                expected_outcome="All attacker persistence mechanisms removed",
                estimated_duration_minutes=45,
            ),
            PlaybookStep(
                step_id=str(uuid.uuid4()), phase=PlaybookPhase.RECOVERY, order=5,
                title="Restore and harden",
                description="Re-enable accounts with new credentials and apply additional security controls",
                tools=["AD console", "MFA system"],
                expected_outcome="Accounts restored with enhanced security controls",
                estimated_duration_minutes=30,
            ),
            PlaybookStep(
                step_id=str(uuid.uuid4()), phase=PlaybookPhase.LESSONS_LEARNED, order=6,
                title="Improve detection",
                description="Create detection rules for the observed attack pattern",
                tools=["SIEM", "SOAR platform"],
                expected_outcome="Detection rules updated for account compromise patterns",
                estimated_duration_minutes=30,
            ),
        ]
        total_duration = sum(s.estimated_duration_minutes for s in steps)
        playbook = Playbook(
            playbook_id=str(uuid.uuid4()),
            name="Account Compromise Response",
            description="Playbook for compromised account incidents including identity containment and restoration",
            scenario="account_compromise",
            steps=steps,
            tags=["account_compromise", "identity", "credential_theft", "unauthorized_access"],
            estimated_total_duration_minutes=total_duration,
        )
        self.playbooks[playbook.playbook_id] = playbook
        return playbook

    def _create_lateral_movement_playbook(self) -> Playbook:
        steps = [
            PlaybookStep(
                step_id=str(uuid.uuid4()), phase=PlaybookPhase.DETECTION, order=1,
                title="Map lateral movement paths",
                description="Identify all systems the attacker has accessed and the techniques used",
                tools=["SIEM", "EDR", "Network forensic tools", "BloodHound"],
                expected_outcome="Complete map of lateral movement paths and techniques",
                estimated_duration_minutes=45,
            ),
            PlaybookStep(
                step_id=str(uuid.uuid4()), phase=PlaybookPhase.CONTAINMENT, order=2,
                title="Segment and isolate",
                description="Implement network segmentation to break lateral movement paths",
                tools=["Firewall", "NAC", "VLAN management"],
                containment_actions=[
                    "Implement micro-segmentation",
                    "Block lateral movement protocols",
                    "Isolate critical assets",
                    "Restrict admin tool execution",
                ],
                expected_outcome="Lateral movement paths disrupted",
                estimated_duration_minutes=30,
            ),
            PlaybookStep(
                step_id=str(uuid.uuid4()), phase=PlaybookPhase.DETECTION, order=3,
                title="Identify initial compromise",
                description="Determine how the attacker first gained access to the network",
                tools=["EDR", "SIEM", "Proxy logs"],
                expected_outcome="Initial compromise vector identified",
                estimated_duration_minutes=60,
            ),
            PlaybookStep(
                step_id=str(uuid.uuid4()), phase=PlaybookPhase.ERADICATION, order=4,
                title="Remove attacker access",
                description="Reset credentials and remove persistence on all compromised systems",
                tools=["EDR", "AD console", "PowerShell"],
                expected_outcome="Attacker access fully removed",
                estimated_duration_minutes=90,
            ),
            PlaybookStep(
                step_id=str(uuid.uuid4()), phase=PlaybookPhase.RECOVERY, order=5,
                title="Strengthen segmentation",
                description="Implement permanent network segmentation and access controls",
                tools=["Firewall", "NAC", "PAM system"],
                expected_outcome="Network segmentation hardened against future lateral movement",
                estimated_duration_minutes=120,
            ),
            PlaybookStep(
                step_id=str(uuid.uuid4()), phase=PlaybookPhase.LESSONS_LEARNED, order=6,
                title="Update detection rules",
                description="Create rules for lateral movement techniques observed in this incident",
                tools=["SIEM", "EDR rules"],
                expected_outcome="Detection rules for lateral movement updated",
                estimated_duration_minutes=30,
            ),
        ]
        total_duration = sum(s.estimated_duration_minutes for s in steps)
        playbook = Playbook(
            playbook_id=str(uuid.uuid4()),
            name="Lateral Movement Response",
            description="Playbook for lateral movement incidents including path mapping and network segmentation",
            scenario="lateral_movement",
            steps=steps,
            tags=["lateral_movement", "network", "credential_theft", "persistence"],
            estimated_total_duration_minutes=total_duration,
        )
        self.playbooks[playbook.playbook_id] = playbook
        return playbook

    def _create_data_exfil_playbook(self) -> Playbook:
        steps = [
            PlaybookStep(
                step_id=str(uuid.uuid4()), phase=PlaybookPhase.DETECTION, order=1,
                title="Confirm and scope exfiltration",
                description="Verify data exfiltration and determine what data was taken",
                tools=["DLP", "NetFlow", "Cloud access logs", "Database audit"],
                expected_outcome="Exfiltration confirmed with data type and volume assessment",
                estimated_duration_minutes=30,
            ),
            PlaybookStep(
                step_id=str(uuid.uuid4()), phase=PlaybookPhase.CONTAINMENT, order=2,
                title="Stop exfiltration channels",
                description="Block all identified exfiltration channels immediately",
                tools=["Firewall", "DLP", "Proxy", "Cloud access security broker"],
                containment_actions=[
                    "Block exfiltration destinations",
                    "Disable compromised accounts",
                    "Block cloud storage services temporarily",
                    "Implement strict egress filtering",
                ],
                expected_outcome="Exfiltration channels blocked",
                estimated_duration_minutes=10,
            ),
            PlaybookStep(
                step_id=str(uuid.uuid4()), phase=PlaybookPhase.DETECTION, order=3,
                title="Identify data source and method",
                description="Determine which system or database the data was exfiltrated from",
                tools=["Database audit", "File access logs", "EDR"],
                expected_outcome="Data source and exfiltration method identified",
                estimated_duration_minutes=60,
            ),
            PlaybookStep(
                step_id=str(uuid.uuid4()), phase=PlaybookPhase.ERADICATION, order=4,
                title="Remediate vulnerability",
                description="Fix the vulnerability or misconfiguration that enabled the exfiltration",
                tools=["Vulnerability scanner", "Configuration management"],
                expected_outcome="Root cause vulnerability remediated",
                estimated_duration_minutes=120,
            ),
            PlaybookStep(
                step_id=str(uuid.uuid4()), phase=PlaybookPhase.RECOVERY, order=5,
                title="Notify and monitor",
                description="Notify affected parties and implement enhanced monitoring for similar activity",
                tools=["SIEM", "DLP", "Notification templates"],
                contacts=["Legal", "Compliance", "Affected customers"],
                expected_outcome="Notifications sent, enhanced monitoring active",
                estimated_duration_minutes=60,
            ),
            PlaybookStep(
                step_id=str(uuid.uuid4()), phase=PlaybookPhase.LESSONS_LEARNED, order=6,
                title="Improve DLP controls",
                description="Update DLP rules and data classification based on incident findings",
                tools=["DLP console", "Data classification tools"],
                expected_outcome="DLP controls enhanced to prevent similar exfiltration",
                estimated_duration_minutes=60,
            ),
        ]
        total_duration = sum(s.estimated_duration_minutes for s in steps)
        playbook = Playbook(
            playbook_id=str(uuid.uuid4()),
            name="Data Exfiltration Response",
            description="Playbook for data exfiltration incidents including channel blocking and impact assessment",
            scenario="data_exfiltration",
            steps=steps,
            tags=["data_exfiltration", "dlp", "sensitive_data", "network"],
            estimated_total_duration_minutes=total_duration,
        )
        self.playbooks[playbook.playbook_id] = playbook
        return playbook

    def _create_supply_chain_playbook(self) -> Playbook:
        steps = [
            PlaybookStep(
                step_id=str(uuid.uuid4()), phase=PlaybookPhase.DETECTION, order=1,
                title="Identify compromised component",
                description="Determine which vendor, library, or update has been compromised",
                tools=["Software composition analysis", "Vulnerability scanner", "Vendor advisories"],
                expected_outcome="Compromised supply chain component identified",
                estimated_duration_minutes=60,
            ),
            PlaybookStep(
                step_id=str(uuid.uuid4()), phase=PlaybookPhase.CONTAINMENT, order=2,
                title="Isolate and block",
                description="Isolate systems running the compromised component and block its execution",
                tools=["EDR", "Application whitelisting", "Firewall"],
                containment_actions=[
                    "Block compromised software execution",
                    "Isolate affected systems",
                    "Revoke vendor access",
                    "Disable compromised update mechanisms",
                ],
                expected_outcome="Compromised component contained",
                estimated_duration_minutes=30,
            ),
            PlaybookStep(
                step_id=str(uuid.uuid4()), phase=PlaybookPhase.DETECTION, order=3,
                title="Assess impact scope",
                description="Determine all systems affected by the compromised component across the environment",
                tools=["Asset management", "SCCM", "Endpoint inventory"],
                expected_outcome="Complete inventory of affected systems",
                estimated_duration_minutes=120,
            ),
            PlaybookStep(
                step_id=str(uuid.uuid4()), phase=PlaybookPhase.ERADICATION, order=4,
                title="Remove compromised component",
                description="Remove the compromised component from all affected systems",
                tools=["SCCM", "Package manager", "Manual removal scripts"],
                expected_outcome="Compromised component removed from all systems",
                estimated_duration_minutes=240,
            ),
            PlaybookStep(
                step_id=str(uuid.uuid4()), phase=PlaybookPhase.RECOVERY, order=5,
                title="Restore with verified versions",
                description="Reinstall verified clean versions of the component from trusted sources",
                tools=["Package manager", "Vendor support"],
                contacts=["Vendor", "Legal", "Procurement"],
                expected_outcome="Clean versions installed, vendor relationship reviewed",
                estimated_duration_minutes=180,
            ),
            PlaybookStep(
                step_id=str(uuid.uuid4()), phase=PlaybookPhase.LESSONS_LEARNED, order=6,
                title="Strengthen supply chain security",
                description="Implement additional supply chain security controls and vendor assessment",
                tools=["Vendor risk assessment", "SBOM tools"],
                expected_outcome="Supply chain security posture improved",
                estimated_duration_minutes=120,
            ),
        ]
        total_duration = sum(s.estimated_duration_minutes for s in steps)
        playbook = Playbook(
            playbook_id=str(uuid.uuid4()),
            name="Supply Chain Compromise Response",
            description="Playbook for supply chain compromise incidents including vendor isolation and component remediation",
            scenario="supply_chain",
            steps=steps,
            tags=["supply_chain", "third_party", "vendor", "software_integrity"],
            estimated_total_duration_minutes=total_duration,
        )
        self.playbooks[playbook.playbook_id] = playbook
        return playbook

    def get_playbook(self, playbook_id: str) -> Playbook | None:
        return self.playbooks.get(playbook_id)

    def get_playbook_by_scenario(self, scenario: str) -> Playbook | None:
        for playbook in self.playbooks.values():
            if playbook.scenario == scenario:
                return playbook
        return None

    def get_all_playbooks(self, enabled_only: bool = True) -> list[Playbook]:
        playbooks = list(self.playbooks.values())
        if enabled_only:
            playbooks = [p for p in playbooks if p.enabled]
        return playbooks

    def add_custom_playbook(
        self,
        name: str,
        description: str,
        scenario: str,
        steps: list[dict[str, Any]],
        tags: list[str] | None = None,
    ) -> Playbook:
        playbook_steps: list[PlaybookStep] = []
        for i, step_data in enumerate(steps, 1):
            phase = PlaybookPhase(step_data.get("phase", "detection"))
            playbook_steps.append(PlaybookStep(
                step_id=str(uuid.uuid4()),
                phase=phase,
                order=i,
                title=step_data.get("title", f"Step {i}"),
                description=step_data.get("description", ""),
                tools=step_data.get("tools", []),
                commands=step_data.get("commands", []),
                contacts=step_data.get("contacts", []),
                containment_actions=step_data.get("containment_actions", []),
                expected_outcome=step_data.get("expected_outcome", ""),
                estimated_duration_minutes=step_data.get("estimated_duration_minutes", 15),
                requires_approval=step_data.get("requires_approval", False),
                approval_role=step_data.get("approval_role", ""),
            ))
        total_duration = sum(s.estimated_duration_minutes for s in playbook_steps)
        playbook = Playbook(
            playbook_id=str(uuid.uuid4()),
            name=name,
            description=description,
            scenario=scenario,
            steps=playbook_steps,
            tags=tags or [],
            estimated_total_duration_minutes=total_duration,
        )
        self.playbooks[playbook.playbook_id] = playbook
        return playbook

    def start_execution(self, playbook_id: str, incident_id: str) -> PlaybookExecution | None:
        playbook = self.playbooks.get(playbook_id)
        if not playbook:
            return None
        execution = PlaybookExecution(
            execution_id=str(uuid.uuid4()),
            playbook_id=playbook_id,
            incident_id=incident_id,
            started_at=datetime.utcnow(),
            current_step=playbook.steps[0].step_id if playbook.steps else "",
        )
        self.executions[execution.execution_id] = execution
        playbook.last_used = datetime.utcnow()
        playbook.usage_count += 1
        return execution

    def complete_step(self, execution_id: str, step_id: str, notes: str = "") -> bool:
        execution = self.executions.get(execution_id)
        if not execution:
            return False
        execution.completed_steps.append(step_id)
        execution.notes.append({
            "step_id": step_id,
            "completed_at": datetime.utcnow().isoformat(),
            "notes": notes,
        })
        playbook = self.playbooks.get(execution.playbook_id)
        if playbook:
            remaining = [s for s in playbook.steps if s.step_id not in execution.completed_steps]
            if remaining:
                execution.current_step = remaining[0].step_id
            else:
                execution.current_step = ""
                execution.status = "completed"
                execution.completed_at = datetime.utcnow()
        return True

    def get_execution(self, execution_id: str) -> PlaybookExecution | None:
        return self.executions.get(execution_id)

    def get_executions_for_incident(self, incident_id: str) -> list[PlaybookExecution]:
        return [e for e in self.executions.values() if e.incident_id == incident_id]

    def get_playbook_recommendation(self, incident_category: str, severity: str) -> list[Playbook]:
        recommendations: list[Playbook] = []
        category_map = {
            "ransomware": "ransomware",
            "phishing": "phishing",
            "data_breach": "data_breach",
            "insider_threat": "insider_threat",
            "ddos": "ddos",
            "malware": "malware",
            "account_compromise": "account_compromise",
            "lateral_movement": "lateral_movement",
            "data_exfiltration": "data_exfiltration",
            "supply_chain": "supply_chain",
        }
        scenario = category_map.get(incident_category.lower(), "")
        if scenario:
            playbook = self.get_playbook_by_scenario(scenario)
            if playbook:
                recommendations.append(playbook)
        if severity in ("critical", "high"):
            for playbook in self.playbooks.values():
                if playbook.scenario not in [r.scenario for r in recommendations]:
                    recommendations.append(playbook)
        return recommendations

    def get_statistics(self) -> dict[str, Any]:
        total = len(self.playbooks)
        enabled = sum(1 for p in self.playbooks.values() if p.enabled)
        total_executions = len(self.executions)
        active_executions = sum(1 for e in self.executions.values() if e.status == "running")
        total_steps = sum(len(p.steps) for p in self.playbooks.values())
        avg_duration = 0
        if total > 0:
            avg_duration = sum(p.estimated_total_duration_minutes for p in self.playbooks.values()) / total
        return {
            "total_playbooks": total,
            "enabled_playbooks": enabled,
            "total_executions": total_executions,
            "active_executions": active_executions,
            "total_steps": total_steps,
            "average_duration_minutes": round(avg_duration, 1),
            "scenarios": [p.scenario for p in self.playbooks.values()],
        }
