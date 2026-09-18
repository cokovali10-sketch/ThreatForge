"""Tests for audit trail."""

import datetime
import os
import tempfile
import pytest
from threatforge.core.audit import AuditTrail, AuditAction, AuditEntry


@pytest.fixture
def audit_db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    trail = AuditTrail(path)
    yield trail
    os.unlink(path)


class TestAuditEntry:
    def test_create_entry(self):
        entry = AuditEntry(
            AuditAction.LOGIN, "user1",
            target_type="session", target_id="sess-123",
            details={"browser": "Chrome"}, ip_address="192.168.1.1"
        )
        assert entry.action == AuditAction.LOGIN
        assert entry.actor == "user1"
        assert entry.details == {"browser": "Chrome"}

    def test_to_dict(self):
        entry = AuditEntry(AuditAction.LOGIN, "user1")
        d = entry.to_dict()
        assert d["action"] == "login"
        assert d["actor"] == "user1"


class TestAuditTrail:
    def test_log_and_query(self, audit_db):
        audit_db.log(AuditAction.LOGIN, "user1", ip_address="1.2.3.4")
        audit_db.log(AuditAction.LOGOUT, "user1")

        entries = audit_db.query(actor="user1")
        assert len(entries) == 2

    def test_query_by_action(self, audit_db):
        audit_db.log(AuditAction.LOGIN, "user1")
        audit_db.log(AuditAction.LOGIN_FAILED, "hacker")
        audit_db.log(AuditAction.LOGIN, "user2")

        logins = audit_db.query(action=AuditAction.LOGIN)
        assert len(logins) == 2

    def test_query_by_target(self, audit_db):
        audit_db.log(AuditAction.INCIDENT_CREATED, "analyst", target_type="incident", target_id="inc-1")
        audit_db.log(AuditAction.INCIDENT_UPDATED, "analyst", target_type="incident", target_id="inc-2")
        audit_db.log(AuditAction.THREAT_LOGGED, "analyst", target_type="threat", target_id="thr-1")

        incidents = audit_db.query(target_type="incident")
        assert len(incidents) == 2

    def test_query_by_time(self, audit_db):
        audit_db.log(AuditAction.LOGIN, "user1")
        since = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=1)
        recent = audit_db.query(since=since)
        assert len(recent) == 1

    def test_query_pagination(self, audit_db):
        for i in range(20):
            audit_db.log(AuditAction.LOGIN, f"user{i}")

        page1 = audit_db.query(limit=10, offset=0)
        page2 = audit_db.query(limit=10, offset=10)
        assert len(page1) == 10
        assert len(page2) == 10

    def test_get_count(self, audit_db):
        audit_db.log(AuditAction.LOGIN, "user1")
        audit_db.log(AuditAction.LOGIN, "user2")
        audit_db.log(AuditAction.LOGOUT, "user1")

        assert audit_db.get_count(action=AuditAction.LOGIN) == 2
        assert audit_db.get_count(actor="user1") == 2

    def test_get_recent(self, audit_db):
        for i in range(5):
            audit_db.log(AuditAction.LOGIN, f"user{i}")
        recent = audit_db.get_recent(limit=3)
        assert len(recent) == 3

    def test_persistence(self, audit_db):
        audit_db.log(AuditAction.LOGIN, "user1")
        audit_db.log(AuditAction.LOGIN, "user2")

        new_trail = AuditTrail(audit_db.db_path)
        entries = new_trail.query()
        assert len(entries) == 2
