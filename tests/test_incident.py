"""Tests for ThreatForge incident module."""

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


def test_incident_creation(tmp_db):
    incident = tmp_db.create_incident(
        title="Test Incident",
        description="Testing incident creation",
        severity="high",
        priority="critical",
        category="malware",
        assignee="analyst_1",
        reporter="system",
    )
    assert incident["title"] == "Test Incident"
    assert incident["description"] == "Testing incident creation"
    assert incident["severity"] == "high"
    assert incident["priority"] == "critical"
    assert incident["category"] == "malware"
    assert incident["assignee"] == "analyst_1"
    assert incident["reporter"] == "system"


def test_incident_filtering(tmp_db):
    tmp_db.create_incident(title="Critical Incident", severity="critical", status="new")
    tmp_db.create_incident(title="Low Incident", severity="low", status="closed")
    tmp_db.create_incident(title="Another Critical", severity="critical", status="investigating")

    critical = tmp_db.get_incidents(severity="critical")
    assert len(critical) == 2

    closed = tmp_db.get_incidents(status="closed")
    assert len(closed) == 1

    assigned = tmp_db.get_incidents(assignee="analyst_1")
    assert len(assigned) == 0


def test_incident_update_fields(tmp_db):
    incident = tmp_db.create_incident(title="Update Test", severity="medium")

    updated = tmp_db.update_incident(
        incident["id"],
        title="Updated Title",
        description="Updated description",
        assignee="analyst_2",
        priority="high",
    )
    assert updated["title"] == "Updated Title"
    assert updated["description"] == "Updated description"
    assert updated["assignee"] == "analyst_2"
    assert updated["priority"] == "high"


def test_incident_close_sets_timestamp(tmp_db):
    incident = tmp_db.create_incident(title="Close Test", severity="medium")
    assert incident["closed_at"] is None

    closed = tmp_db.update_incident(incident["id"], status="closed")
    assert closed["closed_at"] is not None


def test_incident_delete(tmp_db):
    incident = tmp_db.create_incident(title="Delete Test", severity="low")
    result = tmp_db.delete_incident(incident["id"])
    assert result is True
    assert tmp_db.get_incident(incident["id"]) is None


def test_incident_source_alerts(tmp_db):
    alert_ids = ["alert-1", "alert-2", "alert-3"]
    incident = tmp_db.create_incident(
        title="Alerts Test",
        severity="high",
        source_alert_ids=alert_ids,
    )
    assert incident["source_alert_ids"] == alert_ids


def test_incident_affected_assets(tmp_db):
    assets = ["workstation-01", "server-03", "database-01"]
    incident = tmp_db.create_incident(
        title="Assets Test",
        severity="critical",
        affected_assets=assets,
    )
    assert incident["affected_assets"] == assets


def test_incident_lessons_learned(tmp_db):
    incident = tmp_db.create_incident(title="Lessons Test", severity="medium")
    updated = tmp_db.update_incident(
        incident["id"],
        lessons_learned="Need better monitoring",
        resolution="Patched vulnerability",
    )
    assert updated["lessons_learned"] == "Need better monitoring"
    assert updated["resolution"] == "Patched vulnerability"


def test_incident_sla_deadline(tmp_db):
    incident = tmp_db.create_incident(
        title="SLA Test",
        severity="critical",
        sla_deadline="2024-01-02T00:00:00Z",
    )
    assert incident["sla_deadline"] == "2024-01-02T00:00:00Z"
