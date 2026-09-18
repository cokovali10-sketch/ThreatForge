"""Full audit trail for all ThreatForge operations."""

import datetime
import enum
import json
import logging
import sqlite3
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class AuditAction(enum.Enum):
    """Audit action types."""
    # Authentication
    LOGIN = "login"
    LOGOUT = "logout"
    LOGIN_FAILED = "login_failed"
    TOKEN_REFRESH = "token_refresh"

    # Incidents
    INCIDENT_CREATED = "incident_created"
    INCIDENT_UPDATED = "incident_updated"
    INCIDENT_DELETED = "incident_deleted"
    INCIDENT_STATE_CHANGED = "incident_state_changed"
    INCIDENT_ASSIGNED = "incident_assigned"

    # Threats
    THREAT_LOGGED = "threat_logged"
    THREAT_UPDATED = "threat_updated"
    THREAT_DELETED = "threat_deleted"

    # IOCs
    IOC_ADDED = "ioc_added"
    IOC_REMOVED = "ioc_removed"
    IOC_QUARANTINED = "ioc_quarantined"

    # Forensics
    FORENSICS_LOGGED = "forensics_logged"

    # Configuration
    CONFIG_CHANGED = "config_changed"
    USER_CREATED = "user_created"
    USER_DELETED = "user_deleted"

    # System
    SYSTEM_START = "system_start"
    SYSTEM_STOP = "system_stop"
    BACKUP_CREATED = "backup_created"


class AuditEntry:
    """Single audit trail entry."""

    def __init__(
        self,
        action: AuditAction,
        actor: str,
        target_type: Optional[str] = None,
        target_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        ip_address: Optional[str] = None,
    ):
        self.id = ""
        self.timestamp = datetime.datetime.now(datetime.timezone.utc)
        self.action = action
        self.actor = actor
        self.target_type = target_type
        self.target_id = target_id
        self.details = details or {}
        self.ip_address = ip_address

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "action": self.action.value,
            "actor": self.actor,
            "target_type": self.target_type,
            "target_id": self.target_id,
            "details": self.details,
            "ip_address": self.ip_address,
        }


class AuditTrail:
    """Persistent audit trail with SQLite storage."""

    def __init__(self, db_path: str = "audit.db"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_trail (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                action TEXT NOT NULL,
                actor TEXT NOT NULL,
                target_type TEXT,
                target_id TEXT,
                details TEXT,
                ip_address TEXT
            )
        """)
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_trail(timestamp)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_trail(action)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_trail(actor)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_audit_target ON audit_trail(target_type, target_id)"
        )
        conn.commit()
        conn.close()

    def log(
        self,
        action: AuditAction,
        actor: str,
        target_type: Optional[str] = None,
        target_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        ip_address: Optional[str] = None,
    ) -> AuditEntry:
        entry = AuditEntry(action, actor, target_type, target_id, details, ip_address)

        conn = sqlite3.connect(self.db_path)
        cursor = conn.execute(
            """INSERT INTO audit_trail
               (timestamp, action, actor, target_type, target_id, details, ip_address)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                entry.timestamp.isoformat(),
                entry.action.value,
                entry.actor,
                entry.target_type,
                entry.target_id,
                json.dumps(entry.details) if entry.details else None,
                entry.ip_address,
            ),
        )
        entry.id = str(cursor.lastrowid)
        conn.commit()
        conn.close()

        logger.debug("Audit: %s by %s on %s/%s", action.value, actor, target_type, target_id)
        return entry

    def query(
        self,
        action: Optional[AuditAction] = None,
        actor: Optional[str] = None,
        target_type: Optional[str] = None,
        target_id: Optional[str] = None,
        since: Optional[datetime.datetime] = None,
        until: Optional[datetime.datetime] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[AuditEntry]:
        conn = sqlite3.connect(self.db_path)
        conditions = []
        params = []

        if action:
            conditions.append("action = ?")
            params.append(action.value)
        if actor:
            conditions.append("actor = ?")
            params.append(actor)
        if target_type:
            conditions.append("target_type = ?")
            params.append(target_type)
        if target_id:
            conditions.append("target_id = ?")
            params.append(target_id)
        if since:
            conditions.append("timestamp >= ?")
            params.append(since.isoformat())
        if until:
            conditions.append("timestamp <= ?")
            params.append(until.isoformat())

        where = " AND ".join(conditions) if conditions else "1=1"
        query = f"""
            SELECT id, timestamp, action, actor, target_type, target_id, details, ip_address
            FROM audit_trail
            WHERE {where}
            ORDER BY timestamp DESC
            LIMIT ? OFFSET ?
        """
        params.extend([limit, offset])

        rows = conn.execute(query, params).fetchall()
        conn.close()

        entries = []
        for row in rows:
            entry = AuditEntry(
                action=AuditAction(row[2]),
                actor=row[3],
                target_type=row[4],
                target_id=row[5],
                details=json.loads(row[6]) if row[6] else None,
                ip_address=row[7],
            )
            entry.id = str(row[0])
            entry.timestamp = datetime.datetime.fromisoformat(row[1])
            entries.append(entry)

        return entries

    def get_count(
        self,
        action: Optional[AuditAction] = None,
        actor: Optional[str] = None,
        since: Optional[datetime.datetime] = None,
    ) -> int:
        conn = sqlite3.connect(self.db_path)
        conditions = []
        params = []

        if action:
            conditions.append("action = ?")
            params.append(action.value)
        if actor:
            conditions.append("actor = ?")
            params.append(actor)
        if since:
            conditions.append("timestamp >= ?")
            params.append(since.isoformat())

        where = " AND ".join(conditions) if conditions else "1=1"
        query = f"SELECT COUNT(*) FROM audit_trail WHERE {where}"

        count = conn.execute(query, params).fetchone()[0]
        conn.close()
        return count

    def get_recent(self, limit: int = 50) -> List[AuditEntry]:
        return self.query(limit=limit)
