"""
SQLite database module for ThreatForge SOC platform.

Provides the Database class with full CRUD operations for all SOC tables
including alerts, events, incidents, packets, logs, IOCs, users, and audit logs.
Optimized with WAL mode, proper indexes, and connection pooling.
"""

import json
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from threatforge.core.config import Config


class DatabaseError(Exception):
    """Base exception for database operations."""


class Database:
    """
    SQLite database manager for ThreatForge.

    Thread-safe connection management with WAL mode, proper indexes,
    and full CRUD methods for all SOC tables.
    """

    SCHEMA_VERSION = 1

    def __init__(self, config: Optional[Config] = None):
        self.config = config or Config()
        self.db_path = Path(self.config.database.path)
        self._local = threading.local()
        self._lock = threading.Lock()
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        """Get or create a thread-local database connection."""
        if not hasattr(self._local, "conn") or self._local.conn is None:
            conn = sqlite3.connect(
                str(self.db_path),
                timeout=self.config.database.busy_timeout / 1000,
                check_same_thread=False,
            )
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute(
                f"PRAGMA journal_size_limit={self.config.database.journal_size_limit}"
            )
            conn.execute(f"PRAGMA cache_size={self.config.database.cache_size}")
            conn.execute(
                f"PRAGMA busy_timeout={self.config.database.busy_timeout}"
            )
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("PRAGMA synchronous=NORMAL")
            self._local.conn = conn
        return self._local.conn

    @contextmanager
    def transaction(self):
        """Context manager for database transactions."""
        conn = self._get_connection()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise

    @contextmanager
    def cursor(self):
        """Context manager for database cursors with auto-commit."""
        conn = self._get_connection()
        cur = conn.cursor()
        try:
            yield cur
            conn.commit()
        except Exception:
            conn.rollback()
            raise

    def _init_db(self) -> None:
        """Initialize database schema with all tables and indexes."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        with self.cursor() as cur:
            cur.executescript(self._SCHEMA)

    _SCHEMA = """
    CREATE TABLE IF NOT EXISTS alerts (
        id TEXT PRIMARY KEY,
        timestamp TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        severity TEXT NOT NULL CHECK(severity IN ('critical', 'high', 'medium', 'low', 'info')),
        category TEXT NOT NULL,
        title TEXT NOT NULL,
        description TEXT,
        source_ip TEXT,
        destination_ip TEXT,
        source_port INTEGER,
        destination_port INTEGER,
        protocol TEXT,
        indicators TEXT,
        status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open', 'investigating', 'resolved', 'false_positive', 'escalated')),
        assignee TEXT,
        resolution_notes TEXT,
        mitre_attack_id TEXT,
        confidence REAL DEFAULT 0.0,
        tags TEXT,
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
    );

    CREATE TABLE IF NOT EXISTS events (
        id TEXT PRIMARY KEY,
        timestamp TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        event_type TEXT NOT NULL,
        source TEXT NOT NULL,
        source_ip TEXT,
        destination_ip TEXT,
        source_port INTEGER,
        destination_port INTEGER,
        protocol TEXT,
        payload_size INTEGER DEFAULT 0,
        raw_data TEXT,
        parsed_data TEXT,
        geo_source TEXT,
        geo_destination TEXT,
        risk_score REAL DEFAULT 0.0,
        tags TEXT,
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
    );

    CREATE TABLE IF NOT EXISTS incidents (
        id TEXT PRIMARY KEY,
        title TEXT NOT NULL,
        description TEXT,
        severity TEXT NOT NULL CHECK(severity IN ('critical', 'high', 'medium', 'low')),
        status TEXT NOT NULL DEFAULT 'new' CHECK(status IN ('new', 'investigating', 'containment', 'eradication', 'recovery', 'closed')),
        priority TEXT DEFAULT 'medium' CHECK(priority IN ('critical', 'high', 'medium', 'low')),
        category TEXT,
        assignee TEXT,
        reporter TEXT,
        source_alert_ids TEXT,
        affected_assets TEXT,
        indicators TEXT,
        timeline TEXT,
        resolution TEXT,
        lessons_learned TEXT,
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        closed_at TEXT,
        sla_deadline TEXT
    );

    CREATE TABLE IF NOT EXISTS packets (
        id TEXT PRIMARY KEY,
        timestamp TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        capture_id TEXT,
        source_ip TEXT NOT NULL,
        destination_ip TEXT NOT NULL,
        source_port INTEGER,
        destination_port INTEGER,
        protocol TEXT NOT NULL,
        protocol_number INTEGER,
        length INTEGER DEFAULT 0,
        flags TEXT,
        ttl INTEGER,
        window_size INTEGER,
        payload_size INTEGER DEFAULT 0,
        payload_preview TEXT,
        headers TEXT,
        anomalies TEXT,
        geo_source TEXT,
        geo_destination TEXT,
        threat_intel_match TEXT,
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
    );

    CREATE TABLE IF NOT EXISTS logs (
        id TEXT PRIMARY KEY,
        timestamp TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        source TEXT NOT NULL,
        level TEXT NOT NULL DEFAULT 'info' CHECK(level IN ('debug', 'info', 'warning', 'error', 'critical')),
        category TEXT,
        message TEXT NOT NULL,
        details TEXT,
        source_ip TEXT,
        user_name TEXT,
        session_id TEXT,
        event_id TEXT,
        raw_log TEXT,
        parsed_fields TEXT,
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
    );

    CREATE TABLE IF NOT EXISTS ioc (
        id TEXT PRIMARY KEY,
        type TEXT NOT NULL CHECK(type IN ('ip', 'domain', 'url', 'hash_md5', 'hash_sha1', 'hash_sha256', 'email', 'file_name', 'mutex', 'registry_key', 'cidr')),
        value TEXT NOT NULL,
        threat_type TEXT,
        malware_family TEXT,
        confidence REAL DEFAULT 0.0,
        severity TEXT DEFAULT 'medium' CHECK(severity IN ('critical', 'high', 'medium', 'low', 'info')),
        source TEXT,
        source_url TEXT,
        first_seen TEXT,
        last_seen TEXT,
        tags TEXT,
        whois_data TEXT,
        dns_data TEXT,
        status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active', 'expired', 'revoked', 'false_positive')),
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
    );

    CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        username TEXT NOT NULL UNIQUE,
        email TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        salt TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'analyst' CHECK(role IN ('admin', 'analyst', 'viewer', 'api')),
        display_name TEXT,
        is_active INTEGER NOT NULL DEFAULT 1,
        last_login TEXT,
        failed_login_attempts INTEGER DEFAULT 0,
        locked_until TEXT,
        mfa_enabled INTEGER DEFAULT 0,
        mfa_secret TEXT,
        api_key TEXT,
        api_key_created TEXT,
        preferences TEXT,
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
    );

    CREATE TABLE IF NOT EXISTS audit_log (
        id TEXT PRIMARY KEY,
        timestamp TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        user_id TEXT,
        username TEXT,
        action TEXT NOT NULL,
        resource_type TEXT,
        resource_id TEXT,
        old_value TEXT,
        new_value TEXT,
        source_ip TEXT,
        user_agent TEXT,
        session_id TEXT,
        result TEXT DEFAULT 'success' CHECK(result IN ('success', 'failure', 'error')),
        details TEXT,
        FOREIGN KEY (user_id) REFERENCES users(id)
    );

    CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
    CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
    CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
    CREATE INDEX IF NOT EXISTS idx_alerts_source_ip ON alerts(source_ip);
    CREATE INDEX IF NOT EXISTS idx_alerts_destination_ip ON alerts(destination_ip);
    CREATE INDEX IF NOT EXISTS idx_alerts_category ON alerts(category);

    CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
    CREATE INDEX IF NOT EXISTS idx_events_event_type ON events(event_type);
    CREATE INDEX IF NOT EXISTS idx_events_source ON events(source);
    CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events(source_ip);
    CREATE INDEX IF NOT EXISTS idx_events_destination_ip ON events(destination_ip);
    CREATE INDEX IF NOT EXISTS idx_events_risk_score ON events(risk_score);

    CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
    CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity);
    CREATE INDEX IF NOT EXISTS idx_incidents_priority ON incidents(priority);
    CREATE INDEX IF NOT EXISTS idx_incidents_assignee ON incidents(assignee);
    CREATE INDEX IF NOT EXISTS idx_incidents_created_at ON incidents(created_at);

    CREATE INDEX IF NOT EXISTS idx_packets_timestamp ON packets(timestamp);
    CREATE INDEX IF NOT EXISTS idx_packets_source_ip ON packets(source_ip);
    CREATE INDEX IF NOT EXISTS idx_packets_destination_ip ON packets(destination_ip);
    CREATE INDEX IF NOT EXISTS idx_packets_protocol ON packets(protocol);
    CREATE INDEX IF NOT EXISTS idx_packets_source_port ON packets(source_port);
    CREATE INDEX IF NOT EXISTS idx_packets_destination_port ON packets(destination_port);
    CREATE INDEX IF NOT EXISTS idx_packets_capture_id ON packets(capture_id);

    CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(timestamp);
    CREATE INDEX IF NOT EXISTS idx_logs_source ON logs(source);
    CREATE INDEX IF NOT EXISTS idx_logs_level ON logs(level);
    CREATE INDEX IF NOT EXISTS idx_logs_category ON logs(category);
    CREATE INDEX IF NOT EXISTS idx_logs_user_name ON logs(user_name);
    CREATE INDEX IF NOT EXISTS idx_logs_session_id ON logs(session_id);

    CREATE INDEX IF NOT EXISTS idx_ioc_type ON ioc(type);
    CREATE INDEX IF NOT EXISTS idx_ioc_value ON ioc(value);
    CREATE INDEX IF NOT EXISTS idx_ioc_status ON ioc(status);
    CREATE INDEX IF NOT EXISTS idx_ioc_severity ON ioc(severity);
    CREATE INDEX IF NOT EXISTS idx_ioc_confidence ON ioc(confidence);
    CREATE UNIQUE INDEX IF NOT EXISTS idx_ioc_type_value ON ioc(type, value);

    CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
    CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
    CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);
    CREATE INDEX IF NOT EXISTS idx_users_api_key ON users(api_key);

    CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
    CREATE INDEX IF NOT EXISTS idx_audit_user_id ON audit_log(user_id);
    CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action);
    CREATE INDEX IF NOT EXISTS idx_audit_resource ON audit_log(resource_type, resource_id);
    CREATE INDEX IF NOT EXISTS idx_audit_result ON audit_log(result);
    """

    # ---- Alerts CRUD ----

    def create_alert(self, **kwargs) -> dict:
        """Create a new alert."""
        alert_id = kwargs.get("id", str(uuid.uuid4()))
        fields = {
            "id": alert_id,
            "severity": kwargs.get("severity", "info"),
            "category": kwargs.get("category", "unknown"),
            "title": kwargs.get("title", "Untitled Alert"),
            "description": kwargs.get("description", ""),
            "source_ip": kwargs.get("source_ip"),
            "destination_ip": kwargs.get("destination_ip"),
            "source_port": kwargs.get("source_port"),
            "destination_port": kwargs.get("destination_port"),
            "protocol": kwargs.get("protocol"),
            "indicators": self._serialize(kwargs.get("indicators")),
            "status": kwargs.get("status", "open"),
            "assignee": kwargs.get("assignee"),
            "resolution_notes": kwargs.get("resolution_notes"),
            "mitre_attack_id": kwargs.get("mitre_attack_id"),
            "confidence": kwargs.get("confidence", 0.0),
            "tags": self._serialize(kwargs.get("tags")),
        }

        columns = ", ".join(fields.keys())
        placeholders = ", ".join(["?"] * len(fields))

        with self.cursor() as cur:
            cur.execute(
                f"INSERT INTO alerts ({columns}) VALUES ({placeholders})",
                list(fields.values()),
            )

        return self.get_alert(alert_id)

    def get_alert(self, alert_id: str) -> Optional[dict]:
        """Get an alert by ID."""
        conn = self._get_connection()
        row = conn.execute(
            "SELECT * FROM alerts WHERE id = ?", (alert_id,)
        ).fetchone()
        return self._row_to_dict(row) if row else None

    def get_alerts(
        self,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        source_ip: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
        order_by: str = "created_at DESC",
    ) -> list[dict]:
        """Get alerts with optional filtering."""
        conn = self._get_connection()
        query = "SELECT * FROM alerts WHERE 1=1"
        params: list[Any] = []

        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if status:
            query += " AND status = ?"
            params.append(status)
        if source_ip:
            query += " AND source_ip = ?"
            params.append(source_ip)

        query += f" ORDER BY {order_by} LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        rows = conn.execute(query, params).fetchall()
        return [self._row_to_dict(row) for row in rows]

    def update_alert(self, alert_id: str, **kwargs) -> Optional[dict]:
        """Update an alert."""
        allowed_fields = {
            "severity", "category", "title", "description", "source_ip",
            "destination_ip", "source_port", "destination_port", "protocol",
            "indicators", "status", "assignee", "resolution_notes",
            "mitre_attack_id", "confidence", "tags",
        }

        updates = {}
        for key, value in kwargs.items():
            if key in allowed_fields:
                updates[key] = self._serialize(value) if key in ("indicators", "tags") else value

        if not updates:
            return self.get_alert(alert_id)

        updates["updated_at"] = datetime.now(timezone.utc).isoformat()
        set_clause = ", ".join(f"{k} = ?" for k in updates)
        params = list(updates.values()) + [alert_id]

        with self.cursor() as cur:
            cur.execute(f"UPDATE alerts SET {set_clause} WHERE id = ?", params)

        return self.get_alert(alert_id)

    def delete_alert(self, alert_id: str) -> bool:
        """Delete an alert."""
        with self.cursor() as cur:
            cur.execute("DELETE FROM alerts WHERE id = ?", (alert_id,))
            return cur.rowcount > 0

    def count_alerts(self, severity: Optional[str] = None, status: Optional[str] = None) -> int:
        """Count alerts with optional filters."""
        conn = self._get_connection()
        query = "SELECT COUNT(*) FROM alerts WHERE 1=1"
        params: list[Any] = []

        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if status:
            query += " AND status = ?"
            params.append(status)

        return conn.execute(query, params).fetchone()[0]

    # ---- Events CRUD ----

    def create_event(self, **kwargs) -> dict:
        """Create a new event."""
        event_id = kwargs.get("id", str(uuid.uuid4()))
        fields = {
            "id": event_id,
            "event_type": kwargs.get("event_type", "unknown"),
            "source": kwargs.get("source", "unknown"),
            "source_ip": kwargs.get("source_ip"),
            "destination_ip": kwargs.get("destination_ip"),
            "source_port": kwargs.get("source_port"),
            "destination_port": kwargs.get("destination_port"),
            "protocol": kwargs.get("protocol"),
            "payload_size": kwargs.get("payload_size", 0),
            "raw_data": kwargs.get("raw_data"),
            "parsed_data": self._serialize(kwargs.get("parsed_data")),
            "geo_source": kwargs.get("geo_source"),
            "geo_destination": kwargs.get("geo_destination"),
            "risk_score": kwargs.get("risk_score", 0.0),
            "tags": self._serialize(kwargs.get("tags")),
        }

        columns = ", ".join(fields.keys())
        placeholders = ", ".join(["?"] * len(fields))

        with self.cursor() as cur:
            cur.execute(
                f"INSERT INTO events ({columns}) VALUES ({placeholders})",
                list(fields.values()),
            )

        return self.get_event(event_id)

    def get_event(self, event_id: str) -> Optional[dict]:
        """Get an event by ID."""
        conn = self._get_connection()
        row = conn.execute(
            "SELECT * FROM events WHERE id = ?", (event_id,)
        ).fetchone()
        return self._row_to_dict(row) if row else None

    def get_events(
        self,
        event_type: Optional[str] = None,
        source: Optional[str] = None,
        source_ip: Optional[str] = None,
        min_risk_score: Optional[float] = None,
        limit: int = 100,
        offset: int = 0,
        order_by: str = "timestamp DESC",
    ) -> list[dict]:
        """Get events with optional filtering."""
        conn = self._get_connection()
        query = "SELECT * FROM events WHERE 1=1"
        params: list[Any] = []

        if event_type:
            query += " AND event_type = ?"
            params.append(event_type)
        if source:
            query += " AND source = ?"
            params.append(source)
        if source_ip:
            query += " AND source_ip = ?"
            params.append(source_ip)
        if min_risk_score is not None:
            query += " AND risk_score >= ?"
            params.append(min_risk_score)

        query += f" ORDER BY {order_by} LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        rows = conn.execute(query, params).fetchall()
        return [self._row_to_dict(row) for row in rows]

    def delete_event(self, event_id: str) -> bool:
        """Delete an event."""
        with self.cursor() as cur:
            cur.execute("DELETE FROM events WHERE id = ?", (event_id,))
            return cur.rowcount > 0

    # ---- Incidents CRUD ----

    def create_incident(self, **kwargs) -> dict:
        """Create a new incident."""
        incident_id = kwargs.get("id", str(uuid.uuid4()))
        fields = {
            "id": incident_id,
            "title": kwargs.get("title", "Untitled Incident"),
            "description": kwargs.get("description", ""),
            "severity": kwargs.get("severity", "medium"),
            "status": kwargs.get("status", "new"),
            "priority": kwargs.get("priority", "medium"),
            "category": kwargs.get("category"),
            "assignee": kwargs.get("assignee"),
            "reporter": kwargs.get("reporter"),
            "source_alert_ids": self._serialize(kwargs.get("source_alert_ids")),
            "affected_assets": self._serialize(kwargs.get("affected_assets")),
            "indicators": self._serialize(kwargs.get("indicators")),
            "timeline": self._serialize(kwargs.get("timeline", [])),
            "resolution": kwargs.get("resolution"),
            "lessons_learned": kwargs.get("lessons_learned"),
            "sla_deadline": kwargs.get("sla_deadline"),
        }

        columns = ", ".join(fields.keys())
        placeholders = ", ".join(["?"] * len(fields))

        with self.cursor() as cur:
            cur.execute(
                f"INSERT INTO incidents ({columns}) VALUES ({placeholders})",
                list(fields.values()),
            )

        return self.get_incident(incident_id)

    def get_incident(self, incident_id: str) -> Optional[dict]:
        """Get an incident by ID."""
        conn = self._get_connection()
        row = conn.execute(
            "SELECT * FROM incidents WHERE id = ?", (incident_id,)
        ).fetchone()
        return self._row_to_dict(row) if row else None

    def get_incidents(
        self,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        priority: Optional[str] = None,
        assignee: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
        order_by: str = "created_at DESC",
    ) -> list[dict]:
        """Get incidents with optional filtering."""
        conn = self._get_connection()
        query = "SELECT * FROM incidents WHERE 1=1"
        params: list[Any] = []

        if status:
            query += " AND status = ?"
            params.append(status)
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if priority:
            query += " AND priority = ?"
            params.append(priority)
        if assignee:
            query += " AND assignee = ?"
            params.append(assignee)

        query += f" ORDER BY {order_by} LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        rows = conn.execute(query, params).fetchall()
        return [self._row_to_dict(row) for row in rows]

    def update_incident(self, incident_id: str, **kwargs) -> Optional[dict]:
        """Update an incident."""
        allowed_fields = {
            "title", "description", "severity", "status", "priority",
            "category", "assignee", "reporter", "source_alert_ids",
            "affected_assets", "indicators", "timeline", "resolution",
            "lessons_learned", "sla_deadline",
        }

        updates = {}
        serializable = {"source_alert_ids", "affected_assets", "indicators", "timeline"}
        for key, value in kwargs.items():
            if key in allowed_fields:
                updates[key] = self._serialize(value) if key in serializable else value

        if not updates:
            return self.get_incident(incident_id)

        updates["updated_at"] = datetime.now(timezone.utc).isoformat()

        if updates.get("status") == "closed" and "closed_at" not in updates:
            updates["closed_at"] = datetime.now(timezone.utc).isoformat()

        set_clause = ", ".join(f"{k} = ?" for k in updates)
        params = list(updates.values()) + [incident_id]

        with self.cursor() as cur:
            cur.execute(f"UPDATE incidents SET {set_clause} WHERE id = ?", params)

        return self.get_incident(incident_id)

    def delete_incident(self, incident_id: str) -> bool:
        """Delete an incident."""
        with self.cursor() as cur:
            cur.execute("DELETE FROM incidents WHERE id = ?", (incident_id,))
            return cur.rowcount > 0

    # ---- Packets CRUD ----

    def create_packet(self, **kwargs) -> dict:
        """Create a new packet record."""
        packet_id = kwargs.get("id", str(uuid.uuid4()))
        fields = {
            "id": packet_id,
            "capture_id": kwargs.get("capture_id"),
            "source_ip": kwargs.get("source_ip", "0.0.0.0"),
            "destination_ip": kwargs.get("destination_ip", "0.0.0.0"),
            "source_port": kwargs.get("source_port"),
            "destination_port": kwargs.get("destination_port"),
            "protocol": kwargs.get("protocol", "unknown"),
            "protocol_number": kwargs.get("protocol_number"),
            "length": kwargs.get("length", 0),
            "flags": kwargs.get("flags"),
            "ttl": kwargs.get("ttl"),
            "window_size": kwargs.get("window_size"),
            "payload_size": kwargs.get("payload_size", 0),
            "payload_preview": kwargs.get("payload_preview"),
            "headers": self._serialize(kwargs.get("headers")),
            "anomalies": self._serialize(kwargs.get("anomalies")),
            "geo_source": kwargs.get("geo_source"),
            "geo_destination": kwargs.get("geo_destination"),
            "threat_intel_match": self._serialize(kwargs.get("threat_intel_match")),
        }

        columns = ", ".join(fields.keys())
        placeholders = ", ".join(["?"] * len(fields))

        with self.cursor() as cur:
            cur.execute(
                f"INSERT INTO packets ({columns}) VALUES ({placeholders})",
                list(fields.values()),
            )

        return self.get_packet(packet_id)

    def get_packet(self, packet_id: str) -> Optional[dict]:
        """Get a packet by ID."""
        conn = self._get_connection()
        row = conn.execute(
            "SELECT * FROM packets WHERE id = ?", (packet_id,)
        ).fetchone()
        return self._row_to_dict(row) if row else None

    def get_packets(
        self,
        source_ip: Optional[str] = None,
        destination_ip: Optional[str] = None,
        protocol: Optional[str] = None,
        capture_id: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
        order_by: str = "timestamp DESC",
    ) -> list[dict]:
        """Get packets with optional filtering."""
        conn = self._get_connection()
        query = "SELECT * FROM packets WHERE 1=1"
        params: list[Any] = []

        if source_ip:
            query += " AND source_ip = ?"
            params.append(source_ip)
        if destination_ip:
            query += " AND destination_ip = ?"
            params.append(destination_ip)
        if protocol:
            query += " AND protocol = ?"
            params.append(protocol)
        if capture_id:
            query += " AND capture_id = ?"
            params.append(capture_id)

        query += f" ORDER BY {order_by} LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        rows = conn.execute(query, params).fetchall()
        return [self._row_to_dict(row) for row in rows]

    def create_packets_batch(self, packets: list[dict]) -> int:
        """Batch insert packets for performance."""
        if not packets:
            return 0

        columns = [
            "id", "capture_id", "source_ip", "destination_ip", "source_port",
            "destination_port", "protocol", "protocol_number", "length", "flags",
            "ttl", "window_size", "payload_size", "payload_preview", "headers",
            "anomalies", "geo_source", "geo_destination", "threat_intel_match",
        ]

        rows = []
        for pkt in packets:
            row = [pkt.get("id", str(uuid.uuid4()))]
            for col in columns[1:]:
                val = pkt.get(col)
                if col in ("headers", "anomalies", "threat_intel_match"):
                    val = self._serialize(val)
                row.append(val)
            rows.append(row)

        placeholders = ", ".join(["?"] * len(columns))
        col_names = ", ".join(columns)

        with self.cursor() as cur:
            cur.executemany(
                f"INSERT OR IGNORE INTO packets ({col_names}) VALUES ({placeholders})",
                rows,
            )
            return cur.rowcount

    # ---- Logs CRUD ----

    def create_log(self, **kwargs) -> dict:
        """Create a new log entry."""
        log_id = kwargs.get("id", str(uuid.uuid4()))
        fields = {
            "id": log_id,
            "source": kwargs.get("source", "unknown"),
            "level": kwargs.get("level", "info"),
            "category": kwargs.get("category"),
            "message": kwargs.get("message", ""),
            "details": self._serialize(kwargs.get("details")),
            "source_ip": kwargs.get("source_ip"),
            "user_name": kwargs.get("user_name"),
            "session_id": kwargs.get("session_id"),
            "event_id": kwargs.get("event_id"),
            "raw_log": kwargs.get("raw_log"),
            "parsed_fields": self._serialize(kwargs.get("parsed_fields")),
        }

        columns = ", ".join(fields.keys())
        placeholders = ", ".join(["?"] * len(fields))

        with self.cursor() as cur:
            cur.execute(
                f"INSERT INTO logs ({columns}) VALUES ({placeholders})",
                list(fields.values()),
            )

        return self.get_log(log_id)

    def get_log(self, log_id: str) -> Optional[dict]:
        """Get a log entry by ID."""
        conn = self._get_connection()
        row = conn.execute(
            "SELECT * FROM logs WHERE id = ?", (log_id,)
        ).fetchone()
        return self._row_to_dict(row) if row else None

    def get_logs(
        self,
        source: Optional[str] = None,
        level: Optional[str] = None,
        category: Optional[str] = None,
        user_name: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
        order_by: str = "timestamp DESC",
    ) -> list[dict]:
        """Get logs with optional filtering."""
        conn = self._get_connection()
        query = "SELECT * FROM logs WHERE 1=1"
        params: list[Any] = []

        if source:
            query += " AND source = ?"
            params.append(source)
        if level:
            query += " AND level = ?"
            params.append(level)
        if category:
            query += " AND category = ?"
            params.append(category)
        if user_name:
            query += " AND user_name = ?"
            params.append(user_name)

        query += f" ORDER BY {order_by} LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        rows = conn.execute(query, params).fetchall()
        return [self._row_to_dict(row) for row in rows]

    def create_logs_batch(self, logs: list[dict]) -> int:
        """Batch insert logs for performance."""
        if not logs:
            return 0

        columns = [
            "id", "source", "level", "category", "message", "details",
            "source_ip", "user_name", "session_id", "event_id", "raw_log",
            "parsed_fields",
        ]

        rows = []
        for log in logs:
            row = [log.get("id", str(uuid.uuid4()))]
            for col in columns[1:]:
                val = log.get(col)
                if col in ("details", "parsed_fields"):
                    val = self._serialize(val)
                row.append(val)
            rows.append(row)

        placeholders = ", ".join(["?"] * len(columns))
        col_names = ", ".join(columns)

        with self.cursor() as cur:
            cur.executemany(
                f"INSERT INTO logs ({col_names}) VALUES ({placeholders})",
                rows,
            )
            return cur.rowcount

    # ---- IOC CRUD ----

    def create_ioc(self, **kwargs) -> dict:
        """Create a new indicator of compromise."""
        ioc_id = kwargs.get("id", str(uuid.uuid4()))
        fields = {
            "id": ioc_id,
            "type": kwargs.get("type", "ip"),
            "value": kwargs.get("value", ""),
            "threat_type": kwargs.get("threat_type"),
            "malware_family": kwargs.get("malware_family"),
            "confidence": kwargs.get("confidence", 0.0),
            "severity": kwargs.get("severity", "medium"),
            "source": kwargs.get("source"),
            "source_url": kwargs.get("source_url"),
            "first_seen": kwargs.get("first_seen"),
            "last_seen": kwargs.get("last_seen"),
            "tags": self._serialize(kwargs.get("tags")),
            "whois_data": self._serialize(kwargs.get("whois_data")),
            "dns_data": self._serialize(kwargs.get("dns_data")),
            "status": kwargs.get("status", "active"),
        }

        columns = ", ".join(fields.keys())
        placeholders = ", ".join(["?"] * len(fields))

        with self.cursor() as cur:
            cur.execute(
                f"INSERT INTO ioc ({columns}) VALUES ({placeholders})",
                list(fields.values()),
            )

        return self.get_ioc(ioc_id)

    def get_ioc(self, ioc_id: str) -> Optional[dict]:
        """Get an IOC by ID."""
        conn = self._get_connection()
        row = conn.execute(
            "SELECT * FROM ioc WHERE id = ?", (ioc_id,)
        ).fetchone()
        return self._row_to_dict(row) if row else None

    def get_ioc_by_value(self, ioc_type: str, value: str) -> Optional[dict]:
        """Get an IOC by type and value."""
        conn = self._get_connection()
        row = conn.execute(
            "SELECT * FROM ioc WHERE type = ? AND value = ?", (ioc_type, value)
        ).fetchone()
        return self._row_to_dict(row) if row else None

    def get_iocs(
        self,
        ioc_type: Optional[str] = None,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        min_confidence: Optional[float] = None,
        search: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
        order_by: str = "created_at DESC",
    ) -> list[dict]:
        """Get IOCs with optional filtering."""
        conn = self._get_connection()
        query = "SELECT * FROM ioc WHERE 1=1"
        params: list[Any] = []

        if ioc_type:
            query += " AND type = ?"
            params.append(ioc_type)
        if status:
            query += " AND status = ?"
            params.append(status)
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if min_confidence is not None:
            query += " AND confidence >= ?"
            params.append(min_confidence)
        if search:
            query += " AND (value LIKE ? OR malware_family LIKE ? OR threat_type LIKE ?)"
            pattern = f"%{search}%"
            params.extend([pattern, pattern, pattern])

        query += f" ORDER BY {order_by} LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        rows = conn.execute(query, params).fetchall()
        return [self._row_to_dict(row) for row in rows]

    def update_ioc(self, ioc_id: str, **kwargs) -> Optional[dict]:
        """Update an IOC."""
        allowed_fields = {
            "threat_type", "malware_family", "confidence", "severity",
            "source", "source_url", "first_seen", "last_seen", "tags",
            "whois_data", "dns_data", "status",
        }

        updates = {}
        serializable = {"tags", "whois_data", "dns_data"}
        for key, value in kwargs.items():
            if key in allowed_fields:
                updates[key] = self._serialize(value) if key in serializable else value

        if not updates:
            return self.get_ioc(ioc_id)

        updates["updated_at"] = datetime.now(timezone.utc).isoformat()
        set_clause = ", ".join(f"{k} = ?" for k in updates)
        params = list(updates.values()) + [ioc_id]

        with self.cursor() as cur:
            cur.execute(f"UPDATE ioc SET {set_clause} WHERE id = ?", params)

        return self.get_ioc(ioc_id)

    def delete_ioc(self, ioc_id: str) -> bool:
        """Delete an IOC."""
        with self.cursor() as cur:
            cur.execute("DELETE FROM ioc WHERE id = ?", (ioc_id,))
            return cur.rowcount > 0

    def check_ioc_match(self, value: str) -> list[dict]:
        """Check if a value matches any active IOCs."""
        conn = self._get_connection()
        rows = conn.execute(
            "SELECT * FROM ioc WHERE value = ? AND status = 'active'",
            (value,),
        ).fetchall()
        return [self._row_to_dict(row) for row in rows]

    # ---- Users CRUD ----

    def create_user(self, **kwargs) -> dict:
        """Create a new user."""
        user_id = kwargs.get("id", str(uuid.uuid4()))
        fields = {
            "id": user_id,
            "username": kwargs.get("username", ""),
            "email": kwargs.get("email", ""),
            "password_hash": kwargs.get("password_hash", ""),
            "salt": kwargs.get("salt", ""),
            "role": kwargs.get("role", "analyst"),
            "display_name": kwargs.get("display_name"),
            "is_active": kwargs.get("is_active", 1),
            "mfa_enabled": kwargs.get("mfa_enabled", 0),
            "mfa_secret": kwargs.get("mfa_secret"),
            "api_key": kwargs.get("api_key"),
            "preferences": self._serialize(kwargs.get("preferences")),
        }

        columns = ", ".join(fields.keys())
        placeholders = ", ".join(["?"] * len(fields))

        with self.cursor() as cur:
            cur.execute(
                f"INSERT INTO users ({columns}) VALUES ({placeholders})",
                list(fields.values()),
            )

        return self.get_user(user_id)

    def get_user(self, user_id: str) -> Optional[dict]:
        """Get a user by ID."""
        conn = self._get_connection()
        row = conn.execute(
            "SELECT * FROM users WHERE id = ?", (user_id,)
        ).fetchone()
        return self._row_to_dict(row) if row else None

    def get_user_by_username(self, username: str) -> Optional[dict]:
        """Get a user by username."""
        conn = self._get_connection()
        row = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        return self._row_to_dict(row) if row else None

    def get_user_by_api_key(self, api_key: str) -> Optional[dict]:
        """Get a user by API key."""
        conn = self._get_connection()
        row = conn.execute(
            "SELECT * FROM users WHERE api_key = ? AND is_active = 1",
            (api_key,),
        ).fetchone()
        return self._row_to_dict(row) if row else None

    def update_user(self, user_id: str, **kwargs) -> Optional[dict]:
        """Update a user."""
        allowed_fields = {
            "email", "password_hash", "salt", "role", "display_name",
            "is_active", "last_login", "failed_login_attempts", "locked_until",
            "mfa_enabled", "mfa_secret", "api_key", "api_key_created", "preferences",
        }

        updates = {}
        for key, value in kwargs.items():
            if key in allowed_fields:
                updates[key] = self._serialize(value) if key == "preferences" else value

        if not updates:
            return self.get_user(user_id)

        updates["updated_at"] = datetime.now(timezone.utc).isoformat()
        set_clause = ", ".join(f"{k} = ?" for k in updates)
        params = list(updates.values()) + [user_id]

        with self.cursor() as cur:
            cur.execute(f"UPDATE users SET {set_clause} WHERE id = ?", params)

        return self.get_user(user_id)

    def delete_user(self, user_id: str) -> bool:
        """Soft-delete a user by deactivating."""
        return self.update_user(user_id, is_active=0) is not None

    # ---- Audit Log CRUD ----

    def create_audit_log(self, **kwargs) -> dict:
        """Create an audit log entry."""
        log_id = kwargs.get("id", str(uuid.uuid4()))
        fields = {
            "id": log_id,
            "user_id": kwargs.get("user_id"),
            "username": kwargs.get("username"),
            "action": kwargs.get("action", ""),
            "resource_type": kwargs.get("resource_type"),
            "resource_id": kwargs.get("resource_id"),
            "old_value": self._serialize(kwargs.get("old_value")),
            "new_value": self._serialize(kwargs.get("new_value")),
            "source_ip": kwargs.get("source_ip"),
            "user_agent": kwargs.get("user_agent"),
            "session_id": kwargs.get("session_id"),
            "result": kwargs.get("result", "success"),
            "details": self._serialize(kwargs.get("details")),
        }

        columns = ", ".join(fields.keys())
        placeholders = ", ".join(["?"] * len(fields))

        with self.cursor() as cur:
            cur.execute(
                f"INSERT INTO audit_log ({columns}) VALUES ({placeholders})",
                list(fields.values()),
            )

        return self.get_audit_log(log_id)

    def get_audit_log(self, log_id: str) -> Optional[dict]:
        """Get an audit log entry by ID."""
        conn = self._get_connection()
        row = conn.execute(
            "SELECT * FROM audit_log WHERE id = ?", (log_id,)
        ).fetchone()
        return self._row_to_dict(row) if row else None

    def get_audit_logs(
        self,
        user_id: Optional[str] = None,
        action: Optional[str] = None,
        resource_type: Optional[str] = None,
        result: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
        order_by: str = "timestamp DESC",
    ) -> list[dict]:
        """Get audit logs with optional filtering."""
        conn = self._get_connection()
        query = "SELECT * FROM audit_log WHERE 1=1"
        params: list[Any] = []

        if user_id:
            query += " AND user_id = ?"
            params.append(user_id)
        if action:
            query += " AND action = ?"
            params.append(action)
        if resource_type:
            query += " AND resource_type = ?"
            params.append(resource_type)
        if result:
            query += " AND result = ?"
            params.append(result)

        query += f" ORDER BY {order_by} LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        rows = conn.execute(query, params).fetchall()
        return [self._row_to_dict(row) for row in rows]

    # ---- Utility Methods ----

    def execute_query(self, query: str, params: Optional[list] = None) -> list[dict]:
        """Execute a raw query and return results."""
        conn = self._get_connection()
        rows = conn.execute(query, params or []).fetchall()
        return [self._row_to_dict(row) for row in rows]

    def get_table_stats(self) -> dict[str, int]:
        """Get row counts for all tables."""
        tables = [
            "alerts", "events", "incidents", "packets",
            "logs", "ioc", "users", "audit_log",
        ]
        conn = self._get_connection()
        stats = {}
        for table in tables:
            row = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()
            stats[table] = row[0] if row else 0
        return stats

    def backup(self, backup_path: Optional[str] = None) -> str:
        """Create a database backup."""
        if backup_path is None:
            backup_dir = Path(self.config.database.backup_path)
            backup_dir.mkdir(parents=True, exist_ok=True)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = str(backup_dir / f"threatforge_backup_{timestamp}.db")

        conn = self._get_connection()
        conn.execute(f"VACUUM INTO '{backup_path}'")
        return backup_path

    def close(self) -> None:
        """Close the current thread's database connection."""
        if hasattr(self._local, "conn") and self._local.conn is not None:
            self._local.conn.close()
            self._local.conn = None

    def _serialize(self, value: Any) -> Optional[str]:
        """Serialize a value to JSON string for storage."""
        if value is None:
            return None
        if isinstance(value, str):
            return value
        return json.dumps(value, default=str)

    def _deserialize(self, value: Optional[str]) -> Any:
        """Deserialize a JSON string from storage."""
        if value is None:
            return None
        try:
            return json.loads(value)
        except (json.JSONDecodeError, TypeError):
            return value

    def _row_to_dict(self, row: sqlite3.Row) -> dict:
        """Convert a sqlite3.Row to a dictionary with deserialization."""
        if row is None:
            return {}

        result = dict(row)

        json_fields = {
            "indicators", "tags", "parsed_data", "headers", "anomalies",
            "threat_intel_match", "source_alert_ids", "affected_assets",
            "timeline", "details", "parsed_fields", "whois_data",
            "dns_data", "preferences", "old_value", "new_value",
        }

        for field_name in json_fields:
            if field_name in result and result[field_name] is not None:
                result[field_name] = self._deserialize(result[field_name])

        return result
