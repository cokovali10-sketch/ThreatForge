"""Main server for ThreatForge SOC platform."""

import argparse
import asyncio
import logging
import os
import sys
import time
import uuid
from pathlib import Path
from typing import Optional

from aiohttp import web

from threatforge.api.routes import setup_routes
from threatforge.core.config import Config
from threatforge.core.database import Database
from threatforge.core.logger import Logger


class ThreatForgeServer:
    """Main aiohttp server for ThreatForge."""

    def __init__(self, host: str = "0.0.0.0", port: int = 8443,
                 database_path: str = None) -> None:
        self.config = Config()
        if database_path:
            self.config.set("database.path", database_path)
        self.host = host or self.config.server_host
        self.port = port or self.config.server_port
        self.logger = Logger()
        self.db = Database()
        self.app = web.Application(middlewares=[
            self.error_middleware,
            self.logging_middleware,
            self.cors_middleware,
        ])
        self._background_tasks = []

    @web.middleware
    async def error_middleware(self, request: web.Request, handler):
        try:
            return await handler(request)
        except web.HTTPException as ex:
            self.logger.error(f"HTTP {ex.status}: {request.method} {request.path}")
            raise
        except Exception as ex:
            self.logger.error(f"Unhandled error: {ex}")
            return web.json_response(
                {"error": "Internal server error", "message": str(ex)}, status=500
            )

    @web.middleware
    async def logging_middleware(self, request: web.Request, handler):
        start = time.time()
        response = await handler(request)
        elapsed = time.time() - start
        self.logger.debug(f"{request.method} {request.path} -> {response.status} ({elapsed:.3f}s)")
        return response

    @web.middleware
    async def cors_middleware(self, request: web.Request, handler):
        if request.method == "OPTIONS":
            response = web.Response()
        else:
            response = await handler(request)
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
        return response

    async def _background_packet_capture(self) -> None:
        self.logger.log_server("Background packet capture started")
        while True:
            await asyncio.sleep(5)

    async def _background_threat_detection(self) -> None:
        self.logger.log_server("Background threat detection started")
        while True:
            await asyncio.sleep(10)

    async def _background_log_collection(self) -> None:
        self.logger.log_server("Background log collection started")
        while True:
            await asyncio.sleep(15)

    async def _seed_demo_data(self) -> None:
        existing = self.db.fetch_one("SELECT COUNT(*) as count FROM alerts")
        if existing and existing["count"] > 0:
            return
        self.logger.log_server("Seeding demo data...")
        severities = ["critical", "high", "medium", "low", "info"]
        statuses = ["active", "acknowledged", "resolved"]
        alert_titles = [
            "Brute force login attempt detected",
            "Suspicious outbound DNS traffic",
            "Malware signature detected in memory",
            "Unauthorized access to admin panel",
            "Data exfiltration attempt blocked",
            "Ransomware behavior detected",
            "Privilege escalation attempt",
            "SQL injection attack detected",
            "XSS attack blocked by WAF",
            "DDoS attack mitigation active",
        ]
        for i, title in enumerate(alert_titles):
            sev = severities[i % len(severities)]
            status = statuses[i % len(statuses)]
            self.db.execute(
                """INSERT INTO alerts (id, title, description, severity, source, status,
                   created_at, metadata) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (str(uuid.uuid4()), title, f"Automated detection: {title}",
                 sev, "threat-detector", status, time.time() - (i * 3600), "{}"),
            )
        event_types = ["login", "connection", "process", "file", "network", "dns"]
        for i in range(20):
            self.db.create_event(
                event_type=event_types[i % len(event_types)],
                source_ip=f"192.168.1.{i + 1}",
                destination_ip=f"10.0.0.{(i % 254) + 1}",
                source_port=1024 + i,
                destination_port=[80, 443, 22, 53][i % 4],
                protocol=["TCP", "UDP"][i % 2],
                severity=severities[i % len(severities)],
            )
        incident_titles = [
            "Active ransomware investigation",
            "Compromised workstation analysis",
            "Data breach notification required",
            "Phishing campaign response",
        ]
        for i, title in enumerate(incident_titles):
            self.db.create_incident(
                title=title,
                description=f"Incident response for: {title}",
                severity=severities[i % len(severities)],
                assigned_to="analyst_" + str(i + 1),
            )
        for i in range(15):
            self.db.execute(
                """INSERT INTO network_connections (id, source_ip, destination_ip,
                   source_port, destination_port, protocol, bytes_sent, bytes_received,
                   status, started_at, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (str(uuid.uuid4()), f"192.168.1.{i + 1}", f"10.0.0.{(i % 254) + 1}",
                 1024 + i, [80, 443, 22, 53][i % 4], ["TCP", "UDP"][i % 2],
                 (i + 1) * 1024, (i + 1) * 512, "active",
                 time.time() - i * 60, time.time() - i * 10),
            )
        ioc_data = [
            ("ip", "185.220.101.45", 85, "critical", "Known TOR exit node"),
            ("domain", "malware-c2.evil.com", 90, "high", "C2 server domain"),
            ("hash", "d41d8cd98f00b204e9800998ecf8427e", 75, "high", "Malware sample hash"),
            ("ip", "45.33.32.156", 60, "medium", "Suspicious SSH scanner"),
            ("url", "https://phishing.example.com/login", 95, "critical", "Phishing URL"),
        ]
        for ioc in ioc_data:
            self.db.add_ioc(ioc[0], ioc[1], ioc[2], ioc[3], "threat-intel", ioc[4])
        self.logger.log_server("Demo data seeded successfully")

    async def start_background_tasks(self) -> None:
        self._background_tasks.append(asyncio.create_task(self._background_packet_capture()))
        self._background_tasks.append(asyncio.create_task(self._background_threat_detection()))
        self._background_tasks.append(asyncio.create_task(self._background_log_collection()))

    async def cleanup_background_tasks(self, app: web.Application) -> None:
        for task in self._background_tasks:
            task.cancel()
        await asyncio.gather(*self._background_tasks, return_exceptions=True)

    def create_app(self) -> web.Application:
        setup_routes(self.app)
        self.app.on_startup.append(lambda app: asyncio.create_task(self.start_background_tasks()))
        self.app.on_startup.append(lambda app: asyncio.create_task(self._seed_demo_data()))
        self.app.on_cleanup.append(self.cleanup_background_tasks)
        static_path = Path(__file__).parent / "static"
        template_path = Path(__file__).parent / "templates"
        if static_path.exists():
            self.app.router.add_static("/static", static_path)
        if template_path.exists():
            self.app.router.add_get("/", self._serve_dashboard)
            self.app.router.add_get("/{path:^(?!api|ws|static).*}$", self._serve_dashboard)
        return self.app

    async def _serve_dashboard(self, request: web.Request) -> web.Response:
        template_path = Path(__file__).parent / "templates" / "index.html"
        if template_path.exists():
            content = template_path.read_text(encoding="utf-8")
            return web.Response(text=content, content_type="text/html")
        return web.Response(text="Dashboard not found", status=404)

    def run(self) -> None:
        app = self.create_app()
        self.logger.log_server(f"Starting ThreatForge server on {self.host}:{self.port}")
        web.run_app(app, host=self.host, port=self.port, print=None)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="ThreatForge - Professional SOC Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  threatforge serve                    # Start with defaults
  threatforge serve -p 9000           # Custom port
  threatforge serve -H 127.0.0.1     # Bind to localhost
  threatforge serve --db custom.db   # Custom database
        """,
    )
    subparsers = parser.add_subparsers(dest="command", help="Command to run")
    serve_parser = subparsers.add_parser("serve", help="Start the ThreatForge server")
    serve_parser.add_argument("-H", "--host", default="0.0.0.0", help="Host to bind to (default: 0.0.0.0)")
    serve_parser.add_argument("-p", "--port", type=int, default=8443, help="Port to listen on (default: 8443)")
    serve_parser.add_argument("--db", default=None, help="Database file path")
    serve_parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    subparsers.add_parser("version", help="Show version information")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.command == "version" or args.command is None:
        print("ThreatForge v1.0.0")
        print("Professional SOC Platform for Security Operations")
        return
    if args.command == "serve":
        if args.debug:
            Config().set("server.debug", True)
            logging.basicConfig(level=logging.DEBUG)
        server = ThreatForgeServer(
            host=args.host,
            port=args.port,
            database_path=args.db,
        )
        server.run()


if __name__ == "__main__":
    main()
