"""REST API routes for ThreatForge SOC platform."""

import json
import time
from typing import Dict, List

from aiohttp import web, WSMsgType

from threatforge.core.database import Database
from threatforge.core.logger import Logger
from threatforge.network.scanner import PortScanner
# --- константы вынесены FORGE refactor ---
CONST_50 = 50
CONST_201 = 201
CONST_400 = 400
CONST_404 = 404



class APIRoutes:
    """All API route handlers for ThreatForge."""

    def __init__(self) -> None:
        self.db = Database()
        self.logger = Logger()
        self.scanner = PortScanner()
        self._ws_clients: Dict[str, List[web.WebSocketResponse]] = {
            "events": [],
            "alerts": [],
        }

    async def broadcast_websocket(self, channel: str, data: dict) -> None:
        if channel not in self._ws_clients:
            return
        dead = []
        for ws in self._ws_clients[channel]:
            try:
                await ws.send_json(data)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self._ws_clients[channel].remove(ws)

    # Health & Stats

    async def health_check(self, request: web.Request) -> web.Response:
        return web.json_response({"status": "healthy", "timestamp": time.time(), "version": "1.0.0"})

    async def get_stats(self, request: web.Request) -> web.Response:
        stats = self.db.get_stats()
        return web.json_response(stats)

    # Alerts

    async def list_alerts(self, request: web.Request) -> web.Response:
        status = request.query.get("status")
        severity = request.query.get("severity")
        limit = int(request.query.get("limit", CONST_50))
        offset = int(request.query.get("offset", 0))
        query = "SELECT * FROM alerts WHERE 1=1"
        params = []
        if status:
            query += " AND status = ?"
            params.append(status)
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        alerts = self.db.fetch_all(query, tuple(params))
        total = self.db.fetch_one("SELECT COUNT(*) as count FROM alerts")["count"]
        return web.json_response({"alerts": alerts, "total": total, "limit": limit, "offset": offset})

    async def acknowledge_alert(self, request: web.Request) -> web.Response:
        alert_id = request.match_info["id"]
        alert = self.db.fetch_one("SELECT * FROM alerts WHERE id = ?", (alert_id,))
        if not alert:
            return web.json_response({"error": "Alert not found"}, status=CONST_404)
        updated = self.db.update_alert(alert_id, status="acknowledged", acknowledged_at=time.time())
        await self.broadcast_websocket("alerts", {"type": "acknowledged", "alert": updated})
        return web.json_response(updated)

    async def resolve_alert(self, request: web.Request) -> web.Response:
        alert_id = request.match_info["id"]
        alert = self.db.fetch_one("SELECT * FROM alerts WHERE id = ?", (alert_id,))
        if not alert:
            return web.json_response({"error": "Alert not found"}, status=CONST_404)
        updated = self.db.update_alert(alert_id, status="resolved", resolved_at=time.time())
        await self.broadcast_websocket("alerts", {"type": "resolved", "alert": updated})
        return web.json_response(updated)

    # Events

    async def list_events(self, request: web.Request) -> web.Response:
        limit = int(request.query.get("limit", CONST_50))
        offset = int(request.query.get("offset", 0))
        event_type = request.query.get("type")
        query = "SELECT * FROM events WHERE 1=1"
        params = []
        if event_type:
            query += " AND event_type = ?"
            params.append(event_type)
        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        events = self.db.fetch_all(query, tuple(params))
        total = self.db.fetch_one("SELECT COUNT(*) as count FROM events")["count"]
        return web.json_response({"events": events, "total": total, "limit": limit, "offset": offset})

    async def search_events(self, request: web.Request) -> web.Response:
        q = request.query.get("q", "")
        limit = int(request.query.get("limit", CONST_50))
        query = """SELECT * FROM events WHERE
                   event_type LIKE ? OR source_ip LIKE ? OR destination_ip LIKE ? OR payload LIKE ?
                   ORDER BY timestamp DESC LIMIT ?"""
        pattern = f"%{q}%"
        events = self.db.fetch_all(query, (pattern, pattern, pattern, pattern, limit))
        return web.json_response({"events": events, "query": q})

    # Incidents

    async def list_incidents(self, request: web.Request) -> web.Response:
        status = request.query.get("status")
        severity = request.query.get("severity")
        limit = int(request.query.get("limit", CONST_50))
        query = "SELECT * FROM incidents WHERE 1=1"
        params = []
        if status:
            query += " AND status = ?"
            params.append(status)
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        incidents = self.db.fetch_all(query, tuple(params))
        return web.json_response({"incidents": incidents})

    async def create_incident(self, request: web.Request) -> web.Response:
        try:
            data = await request.json()
        except json.JSONDecodeError:
            return web.json_response({"error": "Invalid JSON"}, status=CONST_400)
        title = data.get("title")
        if not title:
            return web.json_response({"error": "Title is required"}, status=CONST_400)
        incident = self.db.create_incident(
            title=title,
            description=data.get("description", ""),
            severity=data.get("severity", "medium"),
            assigned_to=data.get("assigned_to"),
            tags=data.get("tags", []),
            metadata=data.get("metadata", {}),
        )
        await self.broadcast_websocket("alerts", {"type": "new_incident", "incident": incident})
        self.logger.log_incident(incident["id"], "created", title)
        return web.json_response(incident, status=CONST_201)

    async def get_incident(self, request: web.Request) -> web.Response:
        incident_id = request.match_info["id"]
        incident = self.db.fetch_one("SELECT * FROM incidents WHERE id = ?", (incident_id,))
        if not incident:
            return web.json_response({"error": "Incident not found"}, status=CONST_404)
        return web.json_response(incident)

    async def update_incident(self, request: web.Request) -> web.Response:
        incident_id = request.match_info["id"]
        incident = self.db.fetch_one("SELECT * FROM incidents WHERE id = ?", (incident_id,))
        if not incident:
            return web.json_response({"error": "Incident not found"}, status=CONST_404)
        try:
            data = await request.json()
        except json.JSONDecodeError:
            return web.json_response({"error": "Invalid JSON"}, status=CONST_400)
        updated = self.db.update_incident(incident_id, **data)
        self.logger.log_incident(incident_id, "updated", updated["title"])
        return web.json_response(updated)

    async def get_incident_timeline(self, request: web.Request) -> web.Response:
        incident_id = request.match_info["id"]
        incident = self.db.fetch_one("SELECT * FROM incidents WHERE id = ?", (incident_id,))
        if not incident:
            return web.json_response({"error": "Incident not found"}, status=CONST_404)
        timeline = json.loads(incident.get("timeline", "[]"))
        timeline.append({
            "timestamp": incident["created_at"],
            "event": "Incident created",
            "user": "system",
        })
        if incident.get("updated_at"):
            timeline.append({
                "timestamp": incident["updated_at"],
                "event": "Incident updated",
                "user": "system",
            })
        if incident.get("closed_at"):
            timeline.append({
                "timestamp": incident["closed_at"],
                "event": "Incident closed",
                "user": "system",
            })
        timeline.sort(key=lambda x: x["timestamp"])
        return web.json_response({"timeline": timeline})

    # Network

    async def network_stats(self, request: web.Request) -> web.Response:
        stats = {
            "active_connections": self.db.fetch_one(
                "SELECT COUNT(*) as count FROM network_connections WHERE status = 'active'"
            )["count"],
            "total_bytes_sent": 0,
            "total_bytes_received": 0,
            "protocol_distribution": {},
        }
        return web.json_response(stats)

    async def network_connections(self, request: web.Request) -> web.Response:
        limit = int(request.query.get("limit", 100))
        connections = self.db.fetch_all(
            "SELECT * FROM network_connections ORDER BY last_seen DESC LIMIT ?", (limit,)
        )
        return web.json_response({"connections": connections})

    async def network_top_talkers(self, request: web.Request) -> web.Response:
        limit = int(request.query.get("limit", 10))
        talkers = self.db.fetch_all(
            """SELECT source_ip as ip, SUM(bytes_sent + bytes_received) as total_bytes
               FROM network_connections GROUP BY source_ip ORDER BY total_bytes DESC LIMIT ?""",
            (limit,),
        )
        return web.json_response({"top_talkers": talkers})

    # Threat Intelligence

    async def list_iocs(self, request: web.Request) -> web.Response:
        ioc_type = request.query.get("type")
        query = "SELECT * FROM iocs WHERE active = 1"
        params = []
        if ioc_type:
            query += " AND type = ?"
            params.append(ioc_type)
        query += " ORDER BY first_seen DESC"
        iocs = self.db.fetch_all(query, tuple(params))
        return web.json_response({"iocs": iocs})

    async def add_ioc(self, request: web.Request) -> web.Response:
        try:
            data = await request.json()
        except json.JSONDecodeError:
            return web.json_response({"error": "Invalid JSON"}, status=CONST_400)
        ioc_type = data.get("type")
        value = data.get("value")
        if not ioc_type or not value:
            return web.json_response({"error": "type and value are required"}, status=CONST_400)
        ioc = self.db.add_ioc(
            ioc_type=ioc_type,
            value=value,
            confidence=data.get("confidence", CONST_50),
            severity=data.get("severity", "medium"),
            source=data.get("source", ""),
            description=data.get("description", ""),
            tags=data.get("tags", []),
        )
        self.logger.log_threat(ioc_type, value, ioc.get("confidence", CONST_50))
        await self.broadcast_websocket("alerts", {"type": "new_ioc", "ioc": ioc})
        return web.json_response(ioc, status=CONST_201)

    async def remove_ioc(self, request: web.Request) -> web.Response:
        ioc_id = request.match_info["id"]
        ioc = self.db.fetch_one("SELECT * FROM iocs WHERE id = ?", (ioc_id,))
        if not ioc:
            return web.json_response({"error": "IOC not found"}, status=CONST_404)
        self.db.remove_ioc(ioc_id)
        return web.json_response({"message": "IOC removed"})

    async def list_threat_feeds(self, request: web.Request) -> web.Response:
        feeds = self.db.fetch_all("SELECT * FROM threat_feeds ORDER BY name")
        return web.json_response({"feeds": feeds})

    async def add_threat_feed(self, request: web.Request) -> web.Response:
        try:
            data = await request.json()
        except json.JSONDecodeError:
            return web.json_response({"error": "Invalid JSON"}, status=CONST_400)
        name = data.get("name")
        url = data.get("url")
        feed_type = data.get("feed_type")
        if not name or not url or not feed_type:
            return web.json_response({"error": "name, url, and feed_type are required"}, status=CONST_400)
        feed = self.db.add_threat_feed(
            name=name, url=url, feed_type=feed_type,
            update_interval=data.get("update_interval", 3600),
        )
        return web.json_response(feed, status=CONST_201)

    # Forensics

    async def analyze_artifact(self, request: web.Request) -> web.Response:
        artifact_name = request.query.get("name", "unknown")
        artifact_type = request.query.get("type", "unknown")
        result = {
            "artifact": artifact_name,
            "type": artifact_type,
            "analysis": {
                "threat_level": "low",
                "signatures": [],
                "behavior": [],
                "network_activity": [],
                "recommendations": [],
            },
            "timestamp": time.time(),
        }
        self.logger.log_forensics(artifact_name, "analyzed")
        return web.json_response(result)

    # Logs

    async def search_logs(self, request: web.Request) -> web.Response:
        level = request.query.get("level")
        source = request.query.get("source")
        q = request.query.get("q", "")
        limit = int(request.query.get("limit", 100))
        query = "SELECT * FROM logs WHERE 1=1"
        params = []
        if level:
            query += " AND level = ?"
            params.append(level)
        if source:
            query += " AND source = ?"
            params.append(source)
        if q:
            query += " AND message LIKE ?"
            params.append(f"%{q}%")
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        logs = self.db.fetch_all(query, tuple(params))
        return web.json_response({"logs": logs})

    # Scan

    async def trigger_scan(self, request: web.Request) -> web.Response:
        try:
            data = await request.json()
        except json.JSONDecodeError:
            return web.json_response({"error": "Invalid JSON"}, status=CONST_400)
        target = data.get("target")
        ports = data.get("ports")
        if not target:
            return web.json_response({"error": "target is required"}, status=CONST_400)
        result = await self.scanner.scan_host(target, ports)
        return web.json_response(result)

    # Playbooks

    async def list_playbooks(self, request: web.Request) -> web.Response:
        playbooks = self.db.fetch_all("SELECT * FROM playbooks ORDER BY name")
        return web.json_response({"playbooks": playbooks})

    async def execute_playbook(self, request: web.Request) -> web.Response:
        playbook_id = request.match_info["id"]
        playbook = self.db.fetch_one("SELECT * FROM playbooks WHERE id = ?", (playbook_id,))
        if not playbook:
            return web.json_response({"error": "Playbook not found"}, status=CONST_404)
        self.db.execute(
            "UPDATE playbooks SET last_executed = ?, execution_count = execution_count + 1 WHERE id = ?",
            (time.time(), playbook_id),
        )
        result = {
            "playbook_id": playbook_id,
            "name": playbook["name"],
            "status": "executed",
            "executed_at": time.time(),
            "steps_completed": len(json.loads(playbook.get("steps", "[]"))),
        }
        self.logger.log_server(f"Playbook executed: {playbook['name']}")
        return web.json_response(result)

    # WebSocket

    async def websocket_events(self, request: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        self._ws_clients["events"].append(ws)
        self.logger.log_server("WebSocket client connected to events channel")
        try:
            async for msg in ws:
                if msg.type == WSMsgType.ERROR:
                    break
        finally:
            if ws in self._ws_clients["events"]:
                self._ws_clients["events"].remove(ws)
        return ws

    async def websocket_alerts(self, request: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        self._ws_clients["alerts"].append(ws)
        self.logger.log_server("WebSocket client connected to alerts channel")
        try:
            async for msg in ws:
                if msg.type == WSMsgType.ERROR:
                    break
        finally:
            if ws in self._ws_clients["alerts"]:
                self._ws_clients["alerts"].remove(ws)
        return ws


def setup_routes(app: web.Application) -> None:
    api = APIRoutes()
    app["api"] = api

    app.router.add_get("/api/health", api.health_check)
    app.router.add_get("/api/stats", api.get_stats)
    app.router.add_get("/api/alerts", api.list_alerts)
    app.router.add_post("/api/alerts/{id}/acknowledge", api.acknowledge_alert)
    app.router.add_post("/api/alerts/{id}/resolve", api.resolve_alert)
    app.router.add_get("/api/events", api.list_events)
    app.router.add_get("/api/events/search", api.search_events)
    app.router.add_get("/api/incidents", api.list_incidents)
    app.router.add_post("/api/incidents", api.create_incident)
    app.router.add_get("/api/incidents/{id}", api.get_incident)
    app.router.add_put("/api/incidents/{id}", api.update_incident)
    app.router.add_get("/api/incidents/{id}/timeline", api.get_incident_timeline)
    app.router.add_get("/api/network/stats", api.network_stats)
    app.router.add_get("/api/network/connections", api.network_connections)
    app.router.add_get("/api/network/top-talkers", api.network_top_talkers)
    app.router.add_get("/api/threats/ioc", api.list_iocs)
    app.router.add_post("/api/threats/ioc", api.add_ioc)
    app.router.add_delete("/api/threats/ioc/{id}", api.remove_ioc)
    app.router.add_get("/api/threats/feeds", api.list_threat_feeds)
    app.router.add_post("/api/threats/feeds", api.add_threat_feed)
    app.router.add_get("/api/forensics/analyze", api.analyze_artifact)
    app.router.add_get("/api/logs", api.search_logs)
    app.router.add_post("/api/scan", api.trigger_scan)
    app.router.add_get("/api/playbooks", api.list_playbooks)
    app.router.add_post("/api/playbooks/{id}/execute", api.execute_playbook)
    app.router.add_get("/ws/events", api.websocket_events)
    app.router.add_get("/ws/alerts", api.websocket_alerts)
