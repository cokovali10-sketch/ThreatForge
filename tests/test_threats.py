"""Tests for ThreatForge threats module."""

import os
import tempfile
import pytest
from threatforge.core.config import Config
from threatforge.core.database import Database


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


def test_ioc_types(tmp_db):
    ioc_types = ["ip", "domain", "url", "hash_md5", "hash_sha1", "hash_sha256", "email"]
    for ioc_type in ioc_types:
        ioc = tmp_db.create_ioc(type=ioc_type, value=f"test.{ioc_type}")
        assert ioc["type"] == ioc_type


def test_ioc_filtering(tmp_db):
    tmp_db.create_ioc(type="ip", value="1.1.1.1", severity="high")
    tmp_db.create_ioc(type="domain", value="evil.com", severity="critical")
    tmp_db.create_ioc(type="ip", value="2.2.2.2", severity="low")

    ip_iocs = tmp_db.get_iocs(ioc_type="ip")
    assert len(ip_iocs) == 2

    high_iocs = tmp_db.get_iocs(severity="high")
    assert len(high_iocs) == 1


def test_ioc_search(tmp_db):
    tmp_db.create_ioc(type="domain", value="malware.example.com")
    tmp_db.create_ioc(type="domain", value="clean.example.org")

    results = tmp_db.get_iocs(search="malware")
    assert len(results) == 1
    assert results[0]["value"] == "malware.example.com"


def test_ioc_check_match(tmp_db):
    tmp_db.create_ioc(type="ip", value="10.0.0.1", status="active")
    tmp_db.create_ioc(type="ip", value="10.0.0.2", status="revoked")

    matches = tmp_db.check_ioc_match("10.0.0.1")
    assert len(matches) == 1

    no_match = tmp_db.check_ioc_match("10.0.0.2")
    assert len(no_match) == 0


def test_alert_severity_levels(tmp_db):
    severities = ["critical", "high", "medium", "low", "info"]
    for sev in severities:
        alert = tmp_db.create_alert(title=f"Alert {sev}", severity=sev)
        assert alert["severity"] == sev


def test_alert_status_workflow(tmp_db):
    alert = tmp_db.create_alert(title="Workflow Test", severity="medium")
    assert alert["status"] == "open"

    acked = tmp_db.update_alert(alert["id"], status="acknowledged")
    assert acked["status"] == "acknowledged"

    resolved = tmp_db.update_alert(alert["id"], status="resolved")
    assert resolved["status"] == "resolved"


def test_incident_severity_levels(tmp_db):
    severities = ["critical", "high", "medium", "low"]
    for sev in severities:
        incident = tmp_db.create_incident(title=f"Incident {sev}", severity=sev)
        assert incident["severity"] == sev


def test_incident_status_workflow(tmp_db):
    statuses = ["new", "investigating", "containment", "eradication", "recovery", "closed"]
    incident = tmp_db.create_incident(title="Status Workflow", severity="high")

    for status in statuses:
        updated = tmp_db.update_incident(incident["id"], status=status)
        assert updated["status"] == status


def test_event_risk_scoring(tmp_db):
    for score in [0.1, 0.5, 0.9]:
        event = tmp_db.create_event(
            event_type="network",
            source="test",
            risk_score=score,
        )
        assert event["risk_score"] == score


def test_incident_evidence_chain(tmp_db):
    incident = tmp_db.create_incident(title="Evidence Test", severity="critical")
    
    timeline = [
        {"timestamp": "2024-01-01T10:00:00Z", "event": "Alert created"},
        {"timestamp": "2024-01-01T10:05:00Z", "event": "Investigation started"},
    ]
    updated = tmp_db.update_incident(incident["id"], timeline=timeline)
    assert updated["timeline"] == timeline
