from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any

from .ioc import IOCManager, IOCType
# --- константы вынесены FORGE refactor ---
CONST_0_15 = 0.15
CONST_0_5 = 0.5
CONST_24 = 24



class FeedStatus(Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    ERROR = "error"
    UPDATING = "updating"


@dataclass
class ThreatFeed:
    feed_id: str
    name: str
    url: str
    feed_type: str
    status: FeedStatus = FeedStatus.ACTIVE
    last_fetched: datetime | None = None
    fetch_interval_hours: int = CONST_24
    ioc_count: int = 0
    enabled: bool = True
    auth_config: dict[str, str] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)
    reliability_score: float = CONST_0_5
    error_message: str = ""
    created_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class ThreatActor:
    actor_id: str
    name: str
    aliases: list[str] = field(default_factory=list)
    description: str = ""
    motivation: str = ""
    sophistication: str = ""
    target_sectors: list[str] = field(default_factory=list)
    target_countries: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    ttps: list[str] = field(default_factory=list)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    associated_iocs: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)


@dataclass
class ThreatCampaign:
    campaign_id: str
    name: str
    description: str = ""
    threat_actor_id: str = ""
    ttps: list[str] = field(default_factory=list)
    target_sectors: list[str] = field(default_factory=list)
    iocs: list[str] = field(default_factory=list)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    status: str = "active"
    references: list[str] = field(default_factory=list)


@dataclass
class CorrelationResult:
    correlation_id: str
    ioc_ids: list[str]
    campaign_id: str | None
    actor_id: str | None
    confidence: float
    description: str
    timestamp: datetime = field(default_factory=datetime.utcnow)


class ThreatIntel:
    def __init__(self) -> None:
        self.feeds: dict[str, ThreatFeed] = {}
        self.actors: dict[str, ThreatActor] = {}
        self.campaigns: dict[str, ThreatCampaign] = {}
        self.correlations: list[CorrelationResult] = []
        self.ioc_manager = IOCManager()
        self._feed_parsers: dict[str, Any] = {}
        self._initialize_default_parsers()

    def _initialize_default_parsers(self) -> None:
        self._feed_parsers["csv"] = self._parse_csv_feed
        self._feed_parsers["json"] = self._parse_json_feed
        self._feed_parsers["stix"] = self._parse_stix_feed
        self._feed_parsers["text"] = self._parse_text_feed
        self._feed_parsers["misp"] = self._parse_misp_feed

    def add_feed(
        self,
        name: str,
        url: str,
        feed_type: str = "json",
        fetch_interval_hours: int = CONST_24,
        auth_config: dict[str, str] | None = None,
        tags: list[str] | None = None,
        reliability_score: float = CONST_0_5,
    ) -> ThreatFeed:
        feed_id = str(uuid.uuid4())
        feed = ThreatFeed(
            feed_id=feed_id,
            name=name,
            url=url,
            feed_type=feed_type,
            fetch_interval_hours=fetch_interval_hours,
            auth_config=auth_config or {},
            tags=tags or [],
            reliability_score=reliability_score,
        )
        self.feeds[feed_id] = feed
        return feed

    def remove_feed(self, feed_id: str) -> bool:
        return self.feeds.pop(feed_id, None) is not None

    def enable_feed(self, feed_id: str) -> bool:
        feed = self.feeds.get(feed_id)
        if feed:
            feed.enabled = True
            feed.status = FeedStatus.ACTIVE
            return True
        return False

    def disable_feed(self, feed_id: str) -> bool:
        feed = self.feeds.get(feed_id)
        if feed:
            feed.enabled = False
            feed.status = FeedStatus.INACTIVE
            return True
        return False

    def get_feeds_due_for_update(self) -> list[ThreatFeed]:
        now = datetime.utcnow()
        due: list[ThreatFeed] = []
        for feed in self.feeds.values():
            if not feed.enabled:
                continue
            if feed.last_fetched is None:
                due.append(feed)
            else:
                next_fetch = feed.last_fetched + timedelta(hours=feed.fetch_interval_hours)
                if now >= next_fetch:
                    due.append(feed)
        return due

    def update_feed_status(self, feed_id: str, status: FeedStatus, error_message: str = "") -> None:
        feed = self.feeds.get(feed_id)
        if feed:
            feed.status = status
            feed.error_message = error_message
            if status == FeedStatus.ACTIVE:
                feed.last_fetched = datetime.utcnow()

    def ingest_feed_data(self, feed_id: str, raw_data: str) -> int:
        feed = self.feeds.get(feed_id)
        if not feed:
            return 0
        parser = self._feed_parsers.get(feed.feed_type)
        if not parser:
            return 0
        try:
            iocs = parser(raw_data, feed)
            feed.ioc_count += len(iocs)
            feed.last_fetched = datetime.utcnow()
            feed.status = FeedStatus.ACTIVE
            return len(iocs)
        except Exception as e:
            feed.status = FeedStatus.ERROR
            feed.error_message = str(e)
            return 0

    def _parse_csv_feed(self, raw_data: str, feed: ThreatFeed) -> list:
        return self.ioc_manager.import_from_csv(raw_data, source=feed.name)

    def _parse_json_feed(self, raw_data: str, feed: ThreatFeed) -> list:
        return self.ioc_manager.import_from_json(raw_data, source=feed.name)

    def _parse_stix_feed(self, raw_data: str, feed: ThreatFeed) -> list:
        return self.ioc_manager.import_from_stix(raw_data)

    def _parse_text_feed(self, raw_data: str, feed: ThreatFeed) -> list:
        return self.ioc_manager.import_from_text(raw_data, source=feed.name)

    def _parse_misp_feed(self, raw_data: str, feed: ThreatFeed) -> list:
        iocs = []
        try:
            data = json.loads(raw_data)
        except json.JSONDecodeError:
            return iocs
        events = data if isinstance(data, list) else data.get("response", [])
        for event_wrapper in events:
            event = event_wrapper.get("Event", event_wrapper) if isinstance(event_wrapper, dict) else {}
            for attr in event.get("Attribute", []):
                attr_type = attr.get("type", "").lower()
                value = attr.get("value", "")
                if not value:
                    continue
                ioc_type = self._map_misp_type(attr_type)
                if ioc_type:
                    ioc = self.ioc_manager.add_ioc(
                        ioc_type=ioc_type,
                        value=value,
                        confidence=float(attr.get("to_ids", False)),
                        source=feed.name,
                        description=attr.get("comment", ""),
                        tags=[t.get("name", "") for t in attr.get("Tag", [])],
                    )
                    iocs.append(ioc)
        return iocs

    def _map_misp_type(self, misp_type: str) -> IOCType | None:
        mapping = {
            "ip-src": IOCType.IP,
            "ip-dst": IOCType.IP,
            "domain": IOCType.DOMAIN,
            "hostname": IOCType.DOMAIN,
            "url": IOCType.URL,
            "link": IOCType.URL,
            "md5": IOCType.HASH,
            "sha1": IOCType.HASH,
            "sha256": IOCType.HASH,
            "email-src": IOCType.EMAIL,
            "email-dst": IOCType.EMAIL,
        }
        return mapping.get(misp_type)

    def add_actor(
        self,
        name: str,
        aliases: list[str] | None = None,
        description: str = "",
        motivation: str = "",
        sophistication: str = "",
        target_sectors: list[str] | None = None,
        target_countries: list[str] | None = None,
        tools: list[str] | None = None,
        ttps: list[str] | None = None,
    ) -> ThreatActor:
        actor_id = str(uuid.uuid4())
        actor = ThreatActor(
            actor_id=actor_id,
            name=name,
            aliases=aliases or [],
            description=description,
            motivation=motivation,
            sophistication=sophistication,
            target_sectors=target_sectors or [],
            target_countries=target_countries or [],
            tools=tools or [],
            ttps=ttps or [],
            first_seen=datetime.utcnow(),
        )
        self.actors[actor_id] = actor
        return actor

    def add_campaign(
        self,
        name: str,
        description: str = "",
        threat_actor_id: str = "",
        ttps: list[str] | None = None,
        target_sectors: list[str] | None = None,
        iocs: list[str] | None = None,
    ) -> ThreatCampaign:
        campaign_id = str(uuid.uuid4())
        campaign = ThreatCampaign(
            campaign_id=campaign_id,
            name=name,
            description=description,
            threat_actor_id=threat_actor_id,
            ttps=ttps or [],
            target_sectors=target_sectors or [],
            iocs=iocs or [],
            first_seen=datetime.utcnow(),
        )
        self.campaigns[campaign_id] = campaign
        return campaign

    def correlate_iocs(self, time_window_hours: int = CONST_24) -> list[CorrelationResult]:
        correlations: list[CorrelationResult] = []
        active_iocs = self.ioc_manager.get_by_type(IOCType.IP, active_only=True)
        ip_groups: dict[str, list[str]] = {}
        for ioc in active_iocs:
            source = ioc.source
            if source not in ip_groups:
                ip_groups[source] = []
            ip_groups[source].append(ioc.ioc_id)
        for source, ioc_ids in ip_groups.items():
            if len(ioc_ids) >= 3:
                correlation = CorrelationResult(
                    correlation_id=str(uuid.uuid4()),
                    ioc_ids=ioc_ids,
                    campaign_id=None,
                    actor_id=None,
                    confidence=0.6,
                    description=f"Multiple IOCs from same source: {source}",
                )
                correlations.append(correlation)
                self.correlations.append(correlation)

        domain_iocs = self.ioc_manager.get_by_type(IOCType.DOMAIN, active_only=True)
        for ioc in domain_iocs:
            for actor in self.actors.values():
                if any(ttp in actor.ttps for ttp in ioc.mitre_tactics):
                    ioc.related_iocs.append(actor.actor_id)

        return correlations

    def calculate_threat_score(self, ioc_ids: list[str] | None = None) -> float:
        if ioc_ids:
            iocs = [self.ioc_manager.iocs.get(iid) for iid in ioc_ids if self.ioc_manager.iocs.get(iid)]
        else:
            iocs = [ioc for ioc in self.ioc_manager.iocs.values() if ioc.status.value == "active"]
        if not iocs:
            return 0.0

        scores = [self.ioc_manager.calculate_score(ioc) for ioc in iocs]
        base_score = sum(scores) / len(scores)

        actor_factor = min(1.0, len(self.actors) / 10)
        campaign_factor = min(1.0, len(self.campaigns) / 5)
        correlation_factor = min(1.0, len(self.correlations) / 10)

        threat_score = base_score * CONST_0_5 + actor_factor * 0.2 + campaign_factor * CONST_0_15 + correlation_factor * CONST_0_15
        return round(min(1.0, max(0.0, threat_score)), 4)

    def export_stix(self, include_iocs: bool = True, include_actors: bool = True, include_campaigns: bool = True) -> str:
        stix_objects: list[dict[str, Any]] = []
        identity_id = str(uuid.uuid4())
        stix_objects.append({
            "type": "identity",
            "spec_version": "2.1",
            "id": f"identity--{identity_id}",
            "created": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "modified": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "name": "ThreatForge Intelligence",
            "identity_class": "organization",
        })

        if include_actors:
            for actor in self.actors.values():
                threat_actor = {
                    "type": "threat-actor",
                    "spec_version": "2.1",
                    "id": f"threat-actor--{actor.actor_id}",
                    "created": (actor.first_seen or datetime.utcnow()).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "modified": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "name": actor.name,
                    "aliases": actor.aliases,
                    "description": actor.description,
                    "sophistication": actor.sophistication,
                    "resource_level": "unknown",
                    "primary_motivation": actor.motivation,
                    "goals": actor.target_sectors,
                    "external_references": [{"source_name": "threatforge", "description": ref} for ref in actor.references],
                }
                stix_objects.append(threat_actor)

        if include_campaigns:
            for campaign in self.campaigns.values():
                stix_campaign = {
                    "type": "campaign",
                    "spec_version": "2.1",
                    "id": f"campaign--{campaign.campaign_id}",
                    "created": (campaign.first_seen or datetime.utcnow()).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "modified": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "name": campaign.name,
                    "description": campaign.description,
                    "first_seen": campaign.first_seen.strftime("%Y-%m-%dT%H:%M:%SZ") if campaign.first_seen else None,
                    "last_seen": campaign.last_seen.strftime("%Y-%m-%dT%H:%M:%SZ") if campaign.last_seen else None,
                }
                stix_objects.append(stix_campaign)

        if include_iocs:
            for ioc in self.ioc_manager.iocs.values():
                if ioc.status.value != "active":
                    continue
                pattern = self._ioc_to_stix_pattern(ioc)
                if pattern:
                    indicator = {
                        "type": "indicator",
                        "spec_version": "2.1",
                        "id": f"indicator--{ioc.ioc_id}",
                        "created": ioc.created_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "modified": ioc.updated_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "name": f"{ioc.type.value}: {ioc.value}",
                        "description": ioc.description,
                        "pattern": pattern,
                        "pattern_type": "stix",
                        "valid_from": ioc.first_seen.strftime("%Y-%m-%dT%H:%M:%SZ") if ioc.first_seen else ioc.created_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "confidence": int(ioc.confidence * 100),
                        "labels": ioc.tags,
                        "indicator_types": [ioc.type.value],
                    }
                    stix_objects.append(indicator)

        bundle = {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "spec_version": "2.1",
            "objects": stix_objects,
        }
        return json.dumps(bundle, indent=2)

    def _ioc_to_stix_pattern(self, ioc) -> str | None:
        value = ioc.value
        if ioc.type == IOCType.IP:
            return f"[ipv4-addr:value = '{value}']"
        elif ioc.type == IOCType.DOMAIN:
            return f"[domain-name:value = '{value}']"
        elif ioc.type == IOCType.URL:
            return f"[url:value = '{value}']"
        elif ioc.type == IOCType.EMAIL:
            return f"[email-addr:value = '{value}']"
        elif ioc.type == IOCType.HASH:
            if len(value) == 32:
                return f"[file:hashes.MD5 = '{value}']"
            elif len(value) == 40:
                return f"[file:hashes.'SHA-1' = '{value}']"
            elif len(value) == 64:
                return f"[file:hashes.'SHA-256' = '{value}']"
        return None

    def search_actors(self, query: str) -> list[ThreatActor]:
        query_lower = query.lower()
        return [
            actor for actor in self.actors.values()
            if query_lower in actor.name.lower()
            or any(query_lower in alias.lower() for alias in actor.aliases)
            or query_lower in actor.description.lower()
            or any(query_lower in sector.lower() for sector in actor.target_sectors)
        ]

    def search_campaigns(self, query: str) -> list[ThreatCampaign]:
        query_lower = query.lower()
        return [
            campaign for campaign in self.campaigns.values()
            if query_lower in campaign.name.lower()
            or query_lower in campaign.description.lower()
        ]

    def get_actor_by_id(self, actor_id: str) -> ThreatActor | None:
        return self.actors.get(actor_id)

    def get_campaign_by_id(self, campaign_id: str) -> ThreatCampaign | None:
        return self.campaigns.get(campaign_id)

    def get_feed_by_id(self, feed_id: str) -> ThreatFeed | None:
        return self.feeds.get(feed_id)

    def get_statistics(self) -> dict[str, Any]:
        return {
            "feeds": {
                "total": len(self.feeds),
                "active": sum(1 for f in self.feeds.values() if f.enabled),
                "inactive": sum(1 for f in self.feeds.values() if not f.enabled),
                "error": sum(1 for f in self.feeds.values() if f.status == FeedStatus.ERROR),
            },
            "iocs": self.ioc_manager.get_statistics(),
            "actors": len(self.actors),
            "campaigns": len(self.campaigns),
            "correlations": len(self.correlations),
            "threat_score": self.calculate_threat_score(),
        }

    def get_mitre_coverage(self) -> dict[str, list[str]]:
        coverage: dict[str, list[str]] = {}
        for actor in self.actors.values():
            for ttp in actor.ttps:
                if ttp not in coverage:
                    coverage[ttp] = []
                coverage[ttp].append(f"Actor: {actor.name}")
        for campaign in self.campaigns.values():
            for ttp in campaign.ttps:
                if ttp not in coverage:
                    coverage[ttp] = []
                coverage[ttp].append(f"Campaign: {campaign.name}")
        return coverage

    def export_iocs_as_json(self) -> str:
        return json.dumps(self.ioc_manager.get_iocs_as_dicts(), indent=2)

    def export_iocs_as_csv(self) -> str:
        import csv
        import io
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=[
            "ioc_id", "type", "value", "confidence", "severity",
            "source", "description", "tags", "status", "created_at",
        ])
        writer.writeheader()
        for ioc_dict in self.ioc_manager.get_iocs_as_dicts():
            writer.writerow({k: ioc_dict.get(k, "") for k in writer.fieldnames})
        return output.getvalue()
