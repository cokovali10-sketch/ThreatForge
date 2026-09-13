from __future__ import annotations

import json
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class IncidentSeverity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class IncidentStatus(Enum):
    DETECTED = "detected"
    TRIAGED = "triaged"
    CONTAINED = "contained"
    ERADICATING = "eradicating"
    RECOVERING = "recovering"
    CLOSED = "closed"
    REOPENED = "reopened"


class IncidentPriority(Enum):
    P1 = 1
    P2 = 2
    P3 = 3
    P4 = 4


@dataclass
class TimelineEntry:
    entry_id: str
    timestamp: datetime
    event_type: str
    description: str
    actor: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class Evidence:
    evidence_id: str
    name: str
    evidence_type: str
    description: str
    collected_by: str
    collected_at: datetime
    file_path: str = ""
    hash_value: str = ""
    chain_of_custody: list[dict[str, Any]] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)


@dataclass
class Incident:
    incident_id: str
    title: str
    description: str
    severity: IncidentSeverity
    status: IncidentStatus = IncidentStatus.DETECTED
    priority: IncidentPriority = IncidentPriority.P3
    assignee: str = ""
    escalation_contact: str = ""
    category: str = ""
    source: str = ""
    playbook_id: str | None = None
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    detected_at: datetime = field(default_factory=datetime.utcnow)
    contained_at: datetime | None = None
    eradicated_at: datetime | None = None
    recovered_at: datetime | None = None
    closed_at: datetime | None = None
    timeline: list[TimelineEntry] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    affected_systems: list[str] = field(default_factory=list)
    indicators: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    lessons_learned: str = ""
    root_cause: str = ""
    recommendations: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class Assignment:
    assignment_id: str
    incident_id: str
    assignee: str
    role: str
    assigned_at: datetime
    notes: str = ""


class IncidentManager:
    def __init__(self) -> None:
        self.incidents: dict[str, Incident] = {}
        self.assignments: dict[str, list[Assignment]] = defaultdict(list)
        self._status_transitions: dict[str, list[str]] = {
            IncidentStatus.DETECTED.value: [IncidentStatus.TRIAGED.value],
            IncidentStatus.TRIAGED.value: [IncidentStatus.CONTAINED.value],
            IncidentStatus.CONTAINED.value: [IncidentStatus.ERADICATING.value],
            IncidentStatus.ERADICATING.value: [IncidentStatus.RECOVERING.value],
            IncidentStatus.RECOVERING.value: [IncidentStatus.CLOSED.value],
            IncidentStatus.CLOSED.value: [IncidentStatus.REOPENED.value],
            IncidentStatus.REOPENED.value: [IncidentStatus.TRIAGED.value, IncidentStatus.CONTAINED.value],
        }

    def create_incident(
        self,
        title: str,
        description: str,
        severity: IncidentSeverity,
        category: str = "",
        source: str = "",
        affected_systems: list[str] | None = None,
        indicators: list[str] | None = None,
        tags: list[str] | None = None,
        assignee: str = "",
        priority: IncidentPriority | None = None,
    ) -> Incident:
        incident_id = str(uuid.uuid4())
        if priority is None:
            priority = self._calculate_priority(severity)
        incident = Incident(
            incident_id=incident_id,
            title=title,
            description=description,
            severity=severity,
            priority=priority,
            category=category,
            source=source,
            affected_systems=affected_systems or [],
            indicators=indicators or [],
            tags=tags or [],
            assignee=assignee,
        )
        self.incidents[incident_id] = incident
        self._add_timeline_entry(
            incident_id,
            "incident_created",
            f"Incident created: {title} (Severity: {severity.value})",
            "system",
        )
        if assignee:
            self.assign_incident(incident_id, assignee, "primary_responder")
        return incident

    def update_status(self, incident_id: str, new_status: IncidentStatus, notes: str = "", actor: str = "system") -> bool:
        incident = self.incidents.get(incident_id)
        if not incident:
            return False
        allowed = self._status_transitions.get(incident.status.value, [])
        if new_status.value not in allowed:
            return False
        old_status = incident.status
        incident.status = new_status
        incident.updated_at = datetime.utcnow()
        now = datetime.utcnow()
        if new_status == IncidentStatus.CONTAINED:
            incident.contained_at = now
        elif new_status == IncidentStatus.ERADICATING:
            incident.eradicated_at = now
        elif new_status == IncidentStatus.RECOVERING:
            incident.recovered_at = now
        elif new_status == IncidentStatus.CLOSED:
            incident.closed_at = now
        self._add_timeline_entry(
            incident_id,
            "status_change",
            f"Status changed from {old_status.value} to {new_status.value}" + (f": {notes}" if notes else ""),
            actor,
        )
        return True

    def assign_incident(self, incident_id: str, assignee: str, role: str = "responder", notes: str = "") -> Assignment | None:
        incident = self.incidents.get(incident_id)
        if not incident:
            return None
        assignment = Assignment(
            assignment_id=str(uuid.uuid4()),
            incident_id=incident_id,
            assignee=assignee,
            role=role,
            assigned_at=datetime.utcnow(),
            notes=notes,
        )
        self.assignments[incident_id].append(assignment)
        incident.assignee = assignee
        incident.updated_at = datetime.utcnow()
        self._add_timeline_entry(
            incident_id,
            "assignment",
            f"Incident assigned to {assignee} as {role}",
            "system",
        )
        return assignment

    def escalate_incident(self, incident_id: str, escalation_contact: str, reason: str, actor: str = "system") -> bool:
        incident = self.incidents.get(incident_id)
        if not incident:
            return False
        incident.escalation_contact = escalation_contact
        incident.updated_at = datetime.utcnow()
        self._add_timeline_entry(
            incident_id,
            "escalation",
            f"Incident escalated to {escalation_contact}. Reason: {reason}",
            actor,
        )
        return True

    def add_evidence(
        self,
        incident_id: str,
        name: str,
        evidence_type: str,
        description: str,
        collected_by: str,
        file_path: str = "",
        hash_value: str = "",
        tags: list[str] | None = None,
    ) -> Evidence | None:
        incident = self.incidents.get(incident_id)
        if not incident:
            return None
        evidence = Evidence(
            evidence_id=str(uuid.uuid4()),
            name=name,
            evidence_type=evidence_type,
            description=description,
            collected_by=collected_by,
            collected_at=datetime.utcnow(),
            file_path=file_path,
            hash_value=hash_value,
            tags=tags or [],
            chain_of_custody=[{
                "action": "collected",
                "by": collected_by,
                "timestamp": datetime.utcnow().isoformat(),
                "notes": description,
            }],
        )
        incident.evidence.append(evidence)
        incident.updated_at = datetime.utcnow()
        self._add_timeline_entry(
            incident_id,
            "evidence_collected",
            f"Evidence collected: {name} ({evidence_type})",
            collected_by,
        )
        return evidence

    def transfer_evidence(self, evidence_id: str, from_person: str, to_person: str, notes: str = "") -> bool:
        for incident in self.incidents.values():
            for evidence in incident.evidence:
                if evidence.evidence_id == evidence_id:
                    evidence.chain_of_custody.append({
                        "action": "transferred",
                        "from": from_person,
                        "to": to_person,
                        "timestamp": datetime.utcnow().isoformat(),
                        "notes": notes,
                    })
                    self._add_timeline_entry(
                        incident.incident_id,
                        "evidence_transfer",
                        f"Evidence '{evidence.name}' transferred from {from_person} to {to_person}",
                        from_person,
                    )
                    return True
        return False

    def add_timeline_entry(self, incident_id: str, event_type: str, description: str, actor: str, metadata: dict[str, Any] | None = None) -> TimelineEntry | None:
        incident = self.incidents.get(incident_id)
        if not incident:
            return None
        entry = self._add_timeline_entry(incident_id, event_type, description, actor, metadata or {})
        return entry

    def _add_timeline_entry(self, incident_id: str, event_type: str, description: str, actor: str, metadata: dict[str, Any] | None = None) -> TimelineEntry:
        incident = self.incidents.get(incident_id)
        entry = TimelineEntry(
            entry_id=str(uuid.uuid4()),
            timestamp=datetime.utcnow(),
            event_type=event_type,
            description=description,
            actor=actor,
            metadata=metadata or {},
        )
        if incident:
            incident.timeline.append(entry)
        return entry

    def _calculate_priority(self, severity: IncidentSeverity) -> IncidentPriority:
        mapping = {
            IncidentSeverity.CRITICAL: IncidentPriority.P1,
            IncidentSeverity.HIGH: IncidentPriority.P2,
            IncidentSeverity.MEDIUM: IncidentPriority.P3,
            IncidentSeverity.LOW: IncidentPriority.P4,
        }
        return mapping.get(severity, IncidentPriority.P3)

    def close_incident(self, incident_id: str, root_cause: str, lessons_learned: str, recommendations: list[str] | None = None, actor: str = "system") -> bool:
        incident = self.incidents.get(incident_id)
        if not incident:
            return False
        incident.root_cause = root_cause
        incident.lessons_learned = lessons_learned
        incident.recommendations = recommendations or []
        incident.status = IncidentStatus.CLOSED
        incident.closed_at = datetime.utcnow()
        incident.updated_at = datetime.utcnow()
        self._add_timeline_entry(
            incident_id,
            "incident_closed",
            f"Incident closed. Root cause: {root_cause}",
            actor,
        )
        return True

    def reopen_incident(self, incident_id: str, reason: str, actor: str = "system") -> bool:
        incident = self.incidents.get(incident_id)
        if not incident or incident.status != IncidentStatus.CLOSED:
            return False
        incident.status = IncidentStatus.REOPENED
        incident.updated_at = datetime.utcnow()
        self._add_timeline_entry(
            incident_id,
            "incident_reopened",
            f"Incident reopened. Reason: {reason}",
            actor,
        )
        return True

    def get_incident(self, incident_id: str) -> Incident | None:
        return self.incidents.get(incident_id)

    def get_all_incidents(self, status: IncidentStatus | None = None, severity: IncidentSeverity | None = None) -> list[Incident]:
        results = list(self.incidents.values())
        if status:
            results = [i for i in results if i.status == status]
        if severity:
            results = [i for i in results if i.severity == severity]
        return sorted(results, key=lambda x: (x.priority.value, x.created_at), reverse=False)

    def get_open_incidents(self) -> list[Incident]:
        open_statuses = {IncidentStatus.DETECTED, IncidentStatus.TRIAGED, IncidentStatus.CONTAINED, IncidentStatus.ERADICATING, IncidentStatus.RECOVERING}
        return [i for i in self.incidents.values() if i.status in open_statuses]

    def get_incidents_by_assignee(self, assignee: str) -> list[Incident]:
        return [i for i in self.incidents.values() if i.assignee == assignee and i.status != IncidentStatus.CLOSED]

    def get_incidents_by_category(self, category: str) -> list[Incident]:
        return [i for i in self.incidents.values() if i.category == category]

    def get_incidents_by_timeframe(self, start: datetime, end: datetime) -> list[Incident]:
        return [
            i for i in self.incidents.values()
            if start <= i.created_at <= end
        ]

    def get_statistics(self) -> dict[str, Any]:
        total = len(self.incidents)
        by_status: dict[str, int] = defaultdict(int)
        by_severity: dict[str, int] = defaultdict(int)
        by_priority: dict[int, int] = defaultdict(int)
        mttr_values: list[float] = []
        for incident in self.incidents.values():
            by_status[incident.status.value] += 1
            by_severity[incident.severity.value] += 1
            by_priority[incident.priority.value] += 1
            if incident.closed_at and incident.detected_at:
                mttr = (incident.closed_at - incident.detected_at).total_seconds() / 3600
                mttr_values.append(mttr)
        avg_mttr = sum(mttr_values) / len(mttr_values) if mttr_values else 0.0
        return {
            "total_incidents": total,
            "by_status": dict(by_status),
            "by_severity": dict(by_severity),
            "by_priority": dict(by_priority),
            "mean_time_to_resolve_hours": round(avg_mttr, 2),
            "open_incidents": len(self.get_open_incidents()),
        }

    def search_incidents(self, query: str) -> list[Incident]:
        query_lower = query.lower()
        return [
            i for i in self.incidents.values()
            if query_lower in i.title.lower()
            or query_lower in i.description.lower()
            or query_lower in i.category.lower()
            or query_lower in i.root_cause.lower()
            or any(query_lower in tag.lower() for tag in i.tags)
            or any(query_lower in sys.lower() for sys in i.affected_systems)
        ]

    def export_incident_report(self, incident_id: str) -> str | None:
        incident = self.incidents.get(incident_id)
        if not incident:
            return None
        report = {
            "incident_id": incident.incident_id,
            "title": incident.title,
            "description": incident.description,
            "severity": incident.severity.value,
            "status": incident.status.value,
            "priority": incident.priority.value,
            "category": incident.category,
            "source": incident.source,
            "assignee": incident.assignee,
            "created_at": incident.created_at.isoformat(),
            "detected_at": incident.detected_at.isoformat(),
            "contained_at": incident.contained_at.isoformat() if incident.contained_at else None,
            "eradicated_at": incident.eradicated_at.isoformat() if incident.eradicated_at else None,
            "recovered_at": incident.recovered_at.isoformat() if incident.recovered_at else None,
            "closed_at": incident.closed_at.isoformat() if incident.closed_at else None,
            "affected_systems": incident.affected_systems,
            "indicators": incident.indicators,
            "tags": incident.tags,
            "root_cause": incident.root_cause,
            "lessons_learned": incident.lessons_learned,
            "recommendations": incident.recommendations,
            "timeline": [
                {
                    "entry_id": entry.entry_id,
                    "timestamp": entry.timestamp.isoformat(),
                    "event_type": entry.event_type,
                    "description": entry.description,
                    "actor": entry.actor,
                    "metadata": entry.metadata,
                }
                for entry in incident.timeline
            ],
            "evidence": [
                {
                    "evidence_id": ev.evidence_id,
                    "name": ev.name,
                    "type": ev.evidence_type,
                    "description": ev.description,
                    "collected_by": ev.collected_by,
                    "collected_at": ev.collected_at.isoformat(),
                    "file_path": ev.file_path,
                    "hash_value": ev.hash_value,
                    "chain_of_custody": ev.chain_of_custody,
                    "tags": ev.tags,
                }
                for ev in incident.evidence
            ],
        }
        return json.dumps(report, indent=2)

    def get_timeline_summary(self, incident_id: str) -> list[dict[str, Any]]:
        incident = self.incidents.get(incident_id)
        if not incident:
            return []
        return [
            {
                "timestamp": entry.timestamp.isoformat(),
                "event_type": entry.event_type,
                "description": entry.description,
                "actor": entry.actor,
            }
            for entry in sorted(incident.timeline, key=lambda e: e.timestamp)
        ]

    def get_evidence_summary(self, incident_id: str) -> list[dict[str, Any]]:
        incident = self.incidents.get(incident_id)
        if not incident:
            return []
        return [
            {
                "evidence_id": ev.evidence_id,
                "name": ev.name,
                "type": ev.evidence_type,
                "collected_by": ev.collected_by,
                "collected_at": ev.collected_at.isoformat(),
                "chain_of_custody_length": len(ev.chain_of_custody),
            }
            for ev in incident.evidence
        ]

    def get_escalation_report(self) -> list[dict[str, Any]]:
        escalated = []
        for incident in self.incidents.values():
            if incident.escalation_contact:
                escalated.append({
                    "incident_id": incident.incident_id,
                    "title": incident.title,
                    "severity": incident.severity.value,
                    "status": incident.status.value,
                    "escalation_contact": incident.escalation_contact,
                    "assignee": incident.assignee,
                })
        return escalated
