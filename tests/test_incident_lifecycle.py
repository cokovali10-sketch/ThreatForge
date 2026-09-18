"""Tests for incident lifecycle management."""

import datetime
import pytest
from threatforge.core.incident import (
    Incident,
    IncidentManager,
    IncidentState,
    AuditEntry,
    VALID_TRANSITIONS,
)


class TestIncidentState:
    def test_from_string_valid(self):
        assert IncidentState.from_string("new") == IncidentState.NEW
        assert IncidentState.from_string("TRIAGED") == IncidentState.TRIAGED
        assert IncidentState.from_string("investigating") == IncidentState.INVESTIGATING
        assert IncidentState.from_string("contained") == IncidentState.CONTAINED
        assert IncidentState.from_string("resolved") == IncidentState.RESOLVED
        assert IncidentState.from_string("closed") == IncidentState.CLOSED

    def test_from_string_invalid(self):
        assert IncidentState.from_string("unknown") == IncidentState.NEW

    def test_is_terminal(self):
        assert IncidentState.CLOSED.is_terminal() is True
        assert IncidentState.NEW.is_terminal() is False
        assert IncidentState.INVESTIGATING.is_terminal() is False

    def test_valid_transitions(self):
        assert IncidentState.NEW.can_transition_to(IncidentState.TRIAGED) is True
        assert IncidentState.TRIAGED.can_transition_to(IncidentState.INVESTIGATING) is True
        assert IncidentState.INVESTIGATING.can_transition_to(IncidentState.CONTAINED) is True
        assert IncidentState.CONTAINED.can_transition_to(IncidentState.ERADICATING) is True
        assert IncidentState.ERADICATING.can_transition_to(IncidentState.RECOVERING) is True
        assert IncidentState.RECOVERING.can_transition_to(IncidentState.RESOLVED) is True
        assert IncidentState.RESOLVED.can_transition_to(IncidentState.CLOSED) is True
        assert IncidentState.CLOSED.can_transition_to(IncidentState.REOPENED) is True
        assert IncidentState.REOPENED.can_transition_to(IncidentState.INVESTIGATING) is True

    def test_invalid_transitions(self):
        assert IncidentState.NEW.can_transition_to(IncidentState.CLOSED) is False
        assert IncidentState.NEW.can_transition_to(IncidentState.RESOLVED) is False
        assert IncidentState.CLOSED.can_transition_to(IncidentState.NEW) is False
        assert IncidentState.INVESTIGATING.can_transition_to(IncidentState.NEW) is False


class TestIncident:
    def test_create_incident(self):
        inc = Incident("Test Incident", "Test description", "high")
        assert inc.title == "Test Incident"
        assert inc.description == "Test description"
        assert inc.severity == "high"
        assert inc.state == IncidentState.NEW
        assert inc.id.startswith("inc-")
        assert inc.created_at is not None
        assert inc.audit_trail[0].action == "created"

    def test_transition_valid(self):
        inc = Incident("Test", "Description")
        result = inc.transition(IncidentState.TRIAGED, "analyst1", "Triaged by analyst")
        assert result is True
        assert inc.state == IncidentState.TRIAGED
        assert inc.audit_trail[-1].action == "state_transition"
        assert inc.audit_trail[-1].old_value == "NEW"
        assert inc.audit_trail[-1].new_value == "TRIAGED"

    def test_transition_invalid(self):
        inc = Incident("Test", "Description")
        result = inc.transition(IncidentState.CLOSED, "analyst1")
        assert result is False
        assert inc.state == IncidentState.NEW

    def test_full_lifecycle(self):
        inc = Incident("Test", "Description")
        inc.transition(IncidentState.TRIAGED, "a1")
        inc.transition(IncidentState.INVESTIGATING, "a1")
        inc.transition(IncidentState.CONTAINED, "a1")
        inc.transition(IncidentState.ERADICATING, "a1")
        inc.transition(IncidentState.RECOVERING, "a1")
        inc.transition(IncidentState.RESOLVED, "a1")
        inc.transition(IncidentState.CLOSED, "a1")
        assert inc.state == IncidentState.CLOSED
        assert inc.closed_at is not None
        assert len(inc.audit_trail) == 8

    def test_assign(self):
        inc = Incident("Test", "Description")
        inc.assign("analyst2", "admin")
        assert inc.assignee == "analyst2"
        assert inc.audit_trail[-1].action == "assigned"

    def test_add_comment(self):
        inc = Incident("Test", "Description")
        inc.add_comment("analyst1", "Found suspicious activity")
        assert len(inc.comments) == 1
        assert inc.comments[0]["author"] == "analyst1"

    def test_link_chain(self):
        inc = Incident("Test", "Description")
        inc.link_chain("chain-123", "analyst1")
        assert "chain-123" in inc.chain_ids
        inc.link_chain("chain-123", "analyst1")
        assert inc.chain_ids.count("chain-123") == 1

    def test_add_mitre_technique(self):
        inc = Incident("Test", "Description")
        inc.add_mitre_technique("T1059", "analyst1")
        assert "T1059" in inc.mitre_techniques

    def test_update_severity(self):
        inc = Incident("Test", "Description", "low")
        inc.update_severity("critical", "admin", "Escalated")
        assert inc.severity == "critical"
        assert inc.audit_trail[-1].old_value == "low"
        assert inc.audit_trail[-1].new_value == "critical"

    def test_to_dict(self):
        inc = Incident("Test", "Description", "high")
        d = inc.to_dict()
        assert d["title"] == "Test"
        assert d["severity"] == "high"
        assert d["state"] == "NEW"
        assert "audit_trail" in d
        assert "timeline" in d


class TestIncidentManager:
    def test_create_and_get(self):
        mgr = IncidentManager()
        inc = mgr.create_incident("Inc1", "Desc1", "high")
        assert inc.id in mgr.incidents
        assert mgr.get_incident(inc.id) is inc

    def test_get_incidents_filter(self):
        mgr = IncidentManager()
        mgr.create_incident("Inc1", "Desc1", "high")
        mgr.create_incident("Inc2", "Desc2", "low")
        mgr.create_incident("Inc3", "Desc3", "high")

        high = mgr.get_incidents(severity="high")
        assert len(high) == 2

    def test_get_stats(self):
        mgr = IncidentManager()
        mgr.create_incident("Inc1", "Desc1", "high")
        mgr.create_incident("Inc2", "Desc2", "low")
        stats = mgr.get_stats()
        assert stats["total"] == 2
        assert stats["active"] == 2
        assert stats["by_severity"]["high"] == 1
        assert stats["by_severity"]["low"] == 1
