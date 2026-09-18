"""Incident lifecycle management for ThreatForge SOC platform."""

import datetime
import enum
import json
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class IncidentState(enum.Enum):
    """Incident lifecycle states."""
    NEW = "NEW"
    TRIAGED = "TRIAGED"
    INVESTIGATING = "INVESTIGATING"
    CONTAINED = "CONTAINED"
    ERADICATING = "ERADICATING"
    RECOVERING = "RECOVERING"
    RESOLVED = "RESOLVED"
    CLOSED = "CLOSED"
    REOPENED = "REOPENED"

    @classmethod
    def from_string(cls, s: str) -> "IncidentState":
        try:
            return cls(s.upper())
        except ValueError:
            return cls.NEW

    def can_transition_to(self, next_state: "IncidentState") -> bool:
        """Check if transition is allowed."""
        return (self, next_state) in VALID_TRANSITIONS

    def is_terminal(self) -> bool:
        """Check if this is a terminal state."""
        return self == IncidentState.CLOSED


VALID_TRANSITIONS = {
    (IncidentState.NEW, IncidentState.TRIAGED),
    (IncidentState.TRIAGED, IncidentState.INVESTIGATING),
    (IncidentState.INVESTIGATING, IncidentState.CONTAINED),
    (IncidentState.CONTAINED, IncidentState.ERADICATING),
    (IncidentState.ERADICATING, IncidentState.RECOVERING),
    (IncidentState.RECOVERING, IncidentState.RESOLVED),
    (IncidentState.RESOLVED, IncidentState.CLOSED),
    (IncidentState.CLOSED, IncidentState.REOPENED),
    (IncidentState.REOPENED, IncidentState.INVESTIGATING),
    (IncidentState.INVESTIGATING, IncidentState.RESOLVED),
    (IncidentState.TRIAGED, IncidentState.RESOLVED),
}


class AuditEntry:
    """Audit trail entry for incident actions."""

    def __init__(
        self,
        action: str,
        actor: str,
        old_value: Optional[str] = None,
        new_value: Optional[str] = None,
        notes: Optional[str] = None,
    ):
        self.timestamp = datetime.datetime.now(datetime.timezone.utc)
        self.action = action
        self.actor = actor
        self.old_value = old_value
        self.new_value = new_value
        self.notes = notes

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "action": self.action,
            "actor": self.actor,
            "old_value": self.old_value,
            "new_value": self.new_value,
            "notes": self.notes,
        }


class Incident:
    """Incident with lifecycle management and audit trail."""

    _counter = 0

    def __init__(
        self,
        title: str,
        description: str,
        severity: str = "medium",
        assignee: Optional[str] = None,
    ):
        Incident._counter += 1
        self.id = f"inc-{int(datetime.datetime.now(datetime.timezone.utc).timestamp())}-{Incident._counter:04d}"
        self.title = title
        self.description = description
        self.severity = severity
        self.state = IncidentState.NEW
        self.assignee = assignee
        self.created_at = datetime.datetime.now(datetime.timezone.utc)
        self.updated_at = self.created_at
        self.closed_at: Optional[datetime.datetime] = None
        self.chain_ids: List[str] = []
        self.timeline: List[Dict[str, Any]] = []
        self.audit_trail: List[AuditEntry] = []
        self.mitre_techniques: List[str] = []
        self.comments: List[Dict[str, Any]] = []

        self._add_audit("created", "system", notes="Incident created")

    def _add_audit(
        self,
        action: str,
        actor: str,
        old_value: Optional[str] = None,
        new_value: Optional[str] = None,
        notes: Optional[str] = None,
    ):
        entry = AuditEntry(action, actor, old_value, new_value, notes)
        self.audit_trail.append(entry)
        self.timeline.append(entry.to_dict())

    def transition(
        self,
        next_state: IncidentState,
        actor: str,
        notes: Optional[str] = None,
    ) -> bool:
        """Transition to next state with audit trail."""
        if not self.state.can_transition_to(next_state):
            logger.warning(
                "Invalid transition: %s -> %s for incident %s",
                self.state.value,
                next_state.value,
                self.id,
            )
            return False

        old_state = self.state.value
        self.state = next_state
        self.updated_at = datetime.datetime.now(datetime.timezone.utc)

        self._add_audit(
            action="state_transition",
            actor=actor,
            old_value=old_state,
            new_value=next_state.value,
            notes=notes,
        )

        if next_state == IncidentState.CLOSED:
            self.closed_at = datetime.datetime.now(datetime.timezone.utc)

        return True

    def assign(self, assignee: str, actor: str):
        """Assign incident to analyst."""
        old_assignee = self.assignee
        self.assignee = assignee
        self.updated_at = datetime.datetime.now(datetime.timezone.utc)

        self._add_audit(
            action="assigned",
            actor=actor,
            old_value=old_assignee,
            new_value=assignee,
        )

    def add_comment(self, author: str, content: str):
        """Add comment to incident."""
        comment = {
            "author": author,
            "content": content,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }
        self.comments.append(comment)
        self.updated_at = datetime.datetime.now(datetime.timezone.utc)

        self._add_audit(
            action="comment_added",
            actor=author,
            notes=content[:100],
        )

    def link_chain(self, chain_id: str, actor: str):
        """Link an event chain to this incident."""
        if chain_id not in self.chain_ids:
            self.chain_ids.append(chain_id)
            self.updated_at = datetime.datetime.now(datetime.timezone.utc)

            self._add_audit(
                action="chain_linked",
                actor=actor,
                new_value=chain_id,
            )

    def add_mitre_technique(self, technique: str, actor: str):
        """Add MITRE ATT&CK technique."""
        if technique not in self.mitre_techniques:
            self.mitre_techniques.append(technique)
            self.updated_at = datetime.datetime.now(datetime.timezone.utc)

            self._add_audit(
                action="mitre_added",
                actor=actor,
                new_value=technique,
            )

    def update_severity(self, new_severity: str, actor: str, reason: str = ""):
        """Update incident severity."""
        old_severity = self.severity
        self.severity = new_severity
        self.updated_at = datetime.datetime.now(datetime.timezone.utc)

        self._add_audit(
            action="severity_changed",
            actor=actor,
            old_value=old_severity,
            new_value=new_severity,
            notes=reason,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "state": self.state.value,
            "assignee": self.assignee,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "closed_at": self.closed_at.isoformat() if self.closed_at else None,
            "chain_ids": self.chain_ids,
            "mitre_techniques": self.mitre_techniques,
            "timeline": self.timeline,
            "audit_trail": [e.to_dict() for e in self.audit_trail],
            "comments": self.comments,
        }


class IncidentManager:
    """Manages all incidents with full lifecycle support."""

    def __init__(self):
        self.incidents: Dict[str, Incident] = {}

    def create_incident(
        self,
        title: str,
        description: str,
        severity: str = "medium",
        assignee: Optional[str] = None,
    ) -> Incident:
        incident = Incident(title, description, severity, assignee)
        self.incidents[incident.id] = incident
        logger.info("Created incident %s: %s", incident.id, title)
        return incident

    def get_incident(self, incident_id: str) -> Optional[Incident]:
        return self.incidents.get(incident_id)

    def get_incidents(
        self,
        state: Optional[IncidentState] = None,
        severity: Optional[str] = None,
        assignee: Optional[str] = None,
    ) -> List[Incident]:
        results = list(self.incidents.values())

        if state:
            results = [i for i in results if i.state == state]
        if severity:
            results = [i for i in results if i.severity == severity]
        if assignee:
            results = [i for i in results if i.assignee == assignee]

        return results

    def get_stats(self) -> Dict[str, Any]:
        by_state = {}
        by_severity = {}
        for inc in self.incidents.values():
            by_state[inc.state.value] = by_state.get(inc.state.value, 0) + 1
            by_severity[inc.severity] = by_severity.get(inc.severity, 0) + 1

        return {
            "total": len(self.incidents),
            "active": len([i for i in self.incidents.values() if not i.state.is_terminal()]),
            "by_state": by_state,
            "by_severity": by_severity,
        }
