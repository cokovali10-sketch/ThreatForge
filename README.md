# ThreatForge

**Open-source SOC (Security Operations Center) platform — 10,000+ lines of Python**

A complete security operations center in a box. Monitor networks, detect threats, respond to incidents, perform forensics — all from one platform.

## Features

### Network Monitoring
- **Packet Sniffer** — Capture and analyze TCP/UDP/ICMP/HTTP/DNS traffic
- **Network Analyzer** — Traffic flow analysis, connection tracking, bandwidth monitoring
- **Port Scanner** — SYN/TCP/UDP scans, service detection, OS fingerprinting

### Threat Detection
- **22 Detection Rules** — Brute force, port scan, DNS tunneling, C2 beacon, lateral movement, data exfil, privilege escalation, SQL injection, XSS, and more
- **MITRE ATT&CK Mapping** — Every rule mapped to ATT&CK techniques
- **IOC Management** — Import/analyze IOCs (IP, domain, hash, URL, email)
- **Threat Intelligence** — Aggregate feeds, correlate IOCs, STIX export

### Incident Response
- **Incident Lifecycle** — Detection → Triage → Containment → Eradication → Recovery → Lessons
- **10 Playbooks** — Ransomware, Phishing, Data Breach, Insider Threat, DDoS, Malware, Account Compromise, Lateral Movement, Data Exfil, Supply Chain
- **Timeline Tracking** — Full incident timeline with evidence chain of custody

### Forensics
- **Memory Analysis** — Extract processes, network connections, suspicious artifacts
- **Disk Analysis** — Browser history, registry persistence, prefetch, USB history
- **Log Correlation** — Correlate logs across multiple sources
- **Timeline Reconstruction** — Build attack timeline from artifacts

### Dashboard
- **Real-time SOC Dashboard** — Dark theme, glassmorphism UI
- **9 Sections** — Dashboard, Alerts, Events, Incidents, Network, Threats, Forensics, Logs, Settings
- **WebSocket Real-time** — Live alerts and events
- **Charts** — Alerts over time, top threats, severity distribution, network traffic

## Quick Start

```bash
# Install dependencies
pip install aiohttp aiosqlite scapy

# Run ThreatForge
python -m threatforge

# Or with custom config
python -m threatforge --port 9090 --db threatforge.db
```

## Architecture

```
threatforge/
├── core/           # Database, config, logging
├── network/        # Packet sniffer, analyzer, scanner
├── threats/        # Detection engine, IOC, threat intel
├── incident/       # Incident manager, playbooks
├── forensics/      # Memory, disk, log analysis
├── api/            # REST API (25+ endpoints)
├── templates/      # Dashboard HTML
├── static/         # CSS, JavaScript
└── server.py       # Main server
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/health` | GET | Health check |
| `/api/stats` | GET | System statistics |
| `/api/alerts` | GET | List alerts |
| `/api/alerts/{id}/acknowledge` | POST | Acknowledge alert |
| `/api/alerts/{id}/resolve` | POST | Resolve alert |
| `/api/events` | GET | List events |
| `/api/events/search` | GET | Search events |
| `/api/incidents` | GET/POST | List/create incidents |
| `/api/incidents/{id}` | GET/PUT | Get/update incident |
| `/api/network/stats` | GET | Network statistics |
| `/api/network/connections` | GET | Active connections |
| `/api/network/top-talkers` | GET | Top talkers |
| `/api/threats/ioc` | GET/POST | IOC management |
| `/api/threats/feeds` | GET/POST | Threat feeds |
| `/api/forensics/analyze` | GET | Analyze artifact |
| `/api/logs` | GET | Search logs |
| `/api/scan` | POST | Trigger port scan |
| `/api/playbooks` | GET/POST | Playbook management |
| `/ws/events` | WS | Real-time events |
| `/ws/alerts` | WS | Real-time alerts |

## Detection Rules (MITRE ATT&CK)

| Rule | Severity | ATT&CK |
|------|----------|--------|
| Brute Force Detection | HIGH | T1110 |
| Port Scan Detection | MEDIUM | T1046 |
| DNS Tunneling | CRITICAL | T1071.004 |
| C2 Beaconing | CRITICAL | T1071.001 |
| Lateral Movement | CRITICAL | T1021 |
| Data Exfiltration | CRITICAL | T1041 |
| Privilege Escalation | CRITICAL | T1068 |
| SQL Injection | HIGH | T1190 |
| XSS Detection | HIGH | T1189 |
| Path Traversal | HIGH | T1083 |
| Suspicious Process | MEDIUM | T1059 |
| Anomalous Login | HIGH | T1078 |
| Credential Stuffing | HIGH | T1110.004 |
| API Abuse | MEDIUM | T1190 |
| Coin Mining | MEDIUM | T1496 |
| Ransomware Behavior | CRITICAL | T1486 |

## Statistics

- **10,492 lines** of Python code
- **25+ REST API endpoints**
- **2 WebSocket channels**
- **22 detection rules**
- **10 incident playbooks**
- **8 database tables**
- **9 dashboard sections**

## Technologies

- **Python 3.10+**
- **aiohttp** — Async web server
- **aiosqlite** — Async SQLite
- **scapy** — Packet capture
- **Chart.js** — Dashboard charts
- **WebSocket** — Real-time updates

## Author

**Satuarb** — 15-year-old systems programmer from Kazakhstan
- GitHub: [@cokovali10-sketch](https://github.com/cokovali10-sketch)
- Building security tools and AI agents

## License

MIT
