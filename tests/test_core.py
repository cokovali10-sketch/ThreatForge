"""Tests for ThreatForge network module."""

import os
import tempfile
import pytest
from threatforge.core.config import Config
from threatforge.core.database import Database
# --- константы вынесены FORGE refactor ---
CONST_3 = 3



@pytest.fixture
def tmp_db():
    """Create a temporary database for testing."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    Config._instance = None
    config = Config()
    config.set("database.path", db_path)
    db = Database(config)
    yield db
    db.close()
    os.unlink(db_path)


def test_config_singleton():
    Config._instance = None
    c1 = Config()
    c2 = Config()
    assert c1 is c2


def test_config_defaults():
    Config._instance = None
    config = Config()
    assert config.server_host == "0.0.0.0"
    assert config.server_port == 8443


def test_database_creation(tmp_db):
    assert tmp_db is not None


def test_create_alert(tmp_db):
    alert = tmp_db.create_alert(
        title="Test Alert",
        severity="high",
        category="test",
        source_ip="192.168.1.1",
    )
    assert alert["title"] == "Test Alert"
    assert alert["severity"] == "high"
    assert alert["status"] == "open"


def test_get_alerts(tmp_db):
    for i in range(5):
        tmp_db.create_alert(title=f"Alert {i}", severity="medium")
    alerts = tmp_db.get_alerts(limit=CONST_3)
    assert len(alerts) == CONST_3


def test_create_event(tmp_db):
    event = tmp_db.create_event(
        event_type="network",
        source="test",
        source_ip="10.0.0.1",
    )
    assert event["event_type"] == "network"


def test_create_incident(tmp_db):
    incident = tmp_db.create_incident(
        title="Test Incident",
        severity="critical",
    )
    assert incident["title"] == "Test Incident"
    assert incident["severity"] == "critical"


def test_create_ioc(tmp_db):
    ioc = tmp_db.create_ioc(
        type="ip",
        value="1.2.3.4",
        confidence=80,
        severity="high",
    )
    assert ioc["type"] == "ip"
    assert ioc["value"] == "1.2.3.4"


def test_bridge_fetch_all(tmp_db):
    tmp_db.create_alert(title="Fetch Test", severity="low")
    results = tmp_db.fetch_all("SELECT * FROM alerts WHERE title = ?", ("Fetch Test",))
    assert len(results) == 1
    assert results[0]["title"] == "Fetch Test"


def test_bridge_fetch_one(tmp_db):
    tmp_db.create_alert(title="One Test", severity="low")
    result = tmp_db.fetch_one("SELECT * FROM alerts WHERE title = ?", ("One Test",))
    assert result is not None
    assert result["title"] == "One Test"


def test_bridge_get_stats(tmp_db):
    tmp_db.create_alert(title="Stats Alert", severity="info")
    stats = tmp_db.get_stats()
    assert "alerts" in stats
    assert stats["alerts"] >= 1


def test_bridge_add_ioc(tmp_db):
    ioc = tmp_db.add_ioc("ip", "5.6.7.8", 90, "critical", "test", "Test IOC")
    assert ioc["type"] == "ip"
    assert ioc["value"] == "5.6.7.8"


def test_bridge_remove_ioc(tmp_db):
    ioc = tmp_db.create_ioc(type="ip", value="9.9.9.9")
    result = tmp_db.remove_ioc(ioc["id"])
    assert result is True
    assert tmp_db.get_ioc(ioc["id"]) is None


def test_bridge_log_methods(tmp_db):
    tmp_db.log_incident("test-incident", "created", "Test")
    tmp_db.log_threat("malware", "bad.exe", 85)
    tmp_db.log_forensics("memory.dump", "analyzed")
    tmp_db.log_server("Server started")


def test_alert_update(tmp_db):
    alert = tmp_db.create_alert(title="Update Test", severity="medium")
    updated = tmp_db.update_alert(alert["id"], status="acknowledged")
    assert updated["status"] == "acknowledged"


def test_incident_lifecycle(tmp_db):
    incident = tmp_db.create_incident(title="Lifecycle Test", severity="high")
    assert incident["status"] == "new"

    updated = tmp_db.update_incident(incident["id"], status="investigating")
    assert updated["status"] == "investigating"

    closed = tmp_db.update_incident(incident["id"], status="closed")
    assert closed["status"] == "closed"
    assert closed["closed_at"] is not None
