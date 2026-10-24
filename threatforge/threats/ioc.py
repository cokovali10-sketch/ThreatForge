from __future__ import annotations

import csv
import io
import json
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any
# --- константы вынесены FORGE refactor ---
CONST_0_15 = 0.15
CONST_0_3 = 0.3
CONST_0_5 = 0.5
CONST_4 = 4



class IOCType(Enum):
    IP = "ip"
    DOMAIN = "domain"
    HASH = "hash"
    URL = "url"
    EMAIL = "email"


class IOCStatus(Enum):
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"


@dataclass
class IOC:
    ioc_id: str
    type: IOCType
    value: str
    confidence: float
    severity: float
    source: str
    description: str = ""
    tags: list[str] = field(default_factory=list)
    status: IOCStatus = IOCStatus.ACTIVE
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    expires_at: datetime | None = None
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    sightings: int = 0
    enrichment: dict[str, Any] = field(default_factory=dict)
    mitre_tactics: list[str] = field(default_factory=list)
    related_iocs: list[str] = field(default_factory=list)


@dataclass
class EnrichmentResult:
    ioc_id: str
    enrichment_type: str
    data: dict[str, Any]
    timestamp: datetime = field(default_factory=datetime.utcnow)
    source: str = ""


class IOCManager:
    def __init__(self) -> None:
        self.iocs: dict[str, IOC] = {}
        self.ioc_index: dict[str, dict[str, str]] = {
            "ip": {},
            "domain": {},
            "hash": {},
            "url": {},
            "email": {},
        }
        self.enrichment_cache: dict[str, list[EnrichmentResult]] = {}
        self._enrichment_providers: dict[str, Any] = {}
        self._load_default_enrichment_providers()

    def _load_default_enrichment_providers(self) -> None:
        self._enrichment_providers["whois"] = self._enrich_whois
        self._enrichment_providers["geoip"] = self._enrich_geoip
        self._enrichment_providers["reverse_dns"] = self._enrich_reverse_dns
        self._enrichment_providers["abuse_ch"] = self._enrich_abuse_ch
        self._enrichment_providers["virustotal"] = self._enrich_virustotal

    def add_ioc(
        self,
        ioc_type: IOCType,
        value: str,
        confidence: float = CONST_0_5,
        severity: float = CONST_0_5,
        source: str = "",
        description: str = "",
        tags: list[str] | None = None,
        expires_in_days: int | None = None,
        mitre_tactics: list[str] | None = None,
    ) -> IOC:
        normalized_value = self._normalize_value(ioc_type, value)
        existing = self._find_by_value(ioc_type, normalized_value)
        if existing:
            existing.sightings += 1
            existing.last_seen = datetime.utcnow()
            existing.confidence = max(existing.confidence, confidence)
            existing.severity = max(existing.severity, severity)
            existing.updated_at = datetime.utcnow()
            return existing

        ioc_id = str(uuid.uuid4())
        expires_at = None
        if expires_in_days:
            expires_at = datetime.utcnow() + timedelta(days=expires_in_days)

        ioc = IOC(
            ioc_id=ioc_id,
            type=ioc_type,
            value=normalized_value,
            confidence=confidence,
            severity=severity,
            source=source,
            description=description,
            tags=tags or [],
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
            expires_at=expires_at,
            mitre_tactics=mitre_tactics or [],
        )
        self.iocs[ioc_id] = ioc
        self.ioc_index[ioc_type.value][normalized_value] = ioc_id
        return ioc

    def remove_ioc(self, ioc_id: str) -> bool:
        ioc = self.iocs.get(ioc_id)
        if not ioc:
            return False
        ioc.status = IOCStatus.REVOKED
        ioc.updated_at = datetime.utcnow()
        index = self.ioc_index.get(ioc.type.value, {})
        index.pop(ioc.value, None)
        return True

    def expire_iocs(self) -> int:
        now = datetime.utcnow()
        expired_count = 0
        for ioc in self.iocs.values():
            if ioc.status == IOCStatus.ACTIVE and ioc.expires_at and ioc.expires_at <= now:
                ioc.status = IOCStatus.EXPIRED
                ioc.updated_at = now
                expired_count += 1
        return expired_count

    def import_from_csv(self, file_content: str, source: str = "csv_import") -> list[IOC]:
        iocs: list[IOC] = []
        reader = csv.DictReader(io.StringIO(file_content))
        for row in reader:
            ioc_type_str = row.get("type", "").lower().strip()
            value = row.get("value", "").strip()
            if not ioc_type_str or not value:
                continue
            try:
                ioc_type = IOCType(ioc_type_str)
            except ValueError:
                continue
            confidence = float(row.get("confidence", "0.5"))
            severity = float(row.get("severity", "0.5"))
            tags = [t.strip() for t in row.get("tags", "").split(",") if t.strip()]
            desc = row.get("description", "")
            mitre = [m.strip() for m in row.get("mitre_tactics", "").split(",") if m.strip()]
            ioc = self.add_ioc(
                ioc_type=ioc_type,
                value=value,
                confidence=confidence,
                severity=severity,
                source=source,
                description=desc,
                tags=tags,
                mitre_tactics=mitre,
            )
            iocs.append(ioc)
        return iocs

    def import_from_stix(self, stix_content: str) -> list[IOC]:
        iocs: list[IOC] = []
        try:
            data = json.loads(stix_content)
        except json.JSONDecodeError:
            return iocs

        objects = data if isinstance(data, list) else data.get("objects", [])
        for obj in objects:
            obj_type = obj.get("type", "")
            if obj_type == "indicator":
                pattern = obj.get("pattern", "")
                ioc_type, value = self._parse_stix_pattern(pattern)
                if ioc_type and value:
                    confidence = obj.get("confidence", 50) / 100.0
                    labels = obj.get("labels", [])
                    desc = obj.get("description", obj.get("name", ""))
                    ioc = self.add_ioc(
                        ioc_type=ioc_type,
                        value=value,
                        confidence=confidence,
                        severity=CONST_0_5,
                        source=obj.get("created_by_ref", "stix_import"),
                        description=desc,
                        tags=labels,
                    )
                    iocs.append(ioc)
        return iocs

    def import_from_text(self, text: str, default_type: IOCType | None = None, source: str = "text_import") -> list[IOC]:
        iocs: list[IOC] = []
        ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
        domain_pattern = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b")
        url_pattern = re.compile(r"https?://[^\s<>\"']+")
        email_pattern = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")
        hash_pattern = re.compile(r"\b[0-9a-fA-F]{32}\b|\b[0-9a-fA-F]{40}\b|\b[0-9a-fA-F]{64}\b")

        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            for match in ip_pattern.finditer(line):
                iocs.append(self.add_ioc(IOCType.IP, match.group(), source=source))
            for match in url_pattern.finditer(line):
                iocs.append(self.add_ioc(IOCType.URL, match.group(), source=source))
            for match in email_pattern.finditer(line):
                iocs.append(self.add_ioc(IOCType.EMAIL, match.group(), source=source))
            for match in hash_pattern.finditer(line):
                iocs.append(self.add_ioc(IOCType.HASH, match.group(), source=source))
            for match in domain_pattern.finditer(line):
                val = match.group()
                if not ip_pattern.match(val) and not val.endswith((".com", ".net", ".org")):
                    iocs.append(self.add_ioc(IOCType.DOMAIN, val, source=source))

        return iocs

    def import_from_json(self, json_content: str, source: str = "json_import") -> list[IOC]:
        iocs: list[IOC] = []
        try:
            data = json.loads(json_content)
        except json.JSONDecodeError:
            return iocs
        items = data if isinstance(data, list) else data.get("iocs", data.get("indicators", []))
        for item in items:
            ioc_type_str = item.get("type", "").lower()
            value = item.get("value", item.get("indicator", ""))
            if not ioc_type_str or not value:
                continue
            try:
                ioc_type = IOCType(ioc_type_str)
            except ValueError:
                continue
            ioc = self.add_ioc(
                ioc_type=ioc_type,
                value=value,
                confidence=float(item.get("confidence", CONST_0_5)),
                severity=float(item.get("severity", CONST_0_5)),
                source=source,
                description=item.get("description", ""),
                tags=item.get("tags", []),
                mitre_tactics=item.get("mitre_tactics", []),
            )
            iocs.append(ioc)
        return iocs

    def enrich_ioc(self, ioc_id: str, providers: list[str] | None = None) -> list[EnrichmentResult]:
        ioc = self.iocs.get(ioc_id)
        if not ioc:
            return []
        providers = providers or list(self._enrichment_providers.keys())
        results: list[EnrichmentResult] = []
        for provider_name in providers:
            provider = self._enrichment_providers.get(provider_name)
            if provider:
                result = provider(ioc)
                if result:
                    results.append(result)
                    if ioc_id not in self.enrichment_cache:
                        self.enrichment_cache[ioc_id] = []
                    self.enrichment_cache[ioc_id].append(result)
                    ioc.enrichment[provider_name] = result.data
                    ioc.updated_at = datetime.utcnow()
        return results

    def _enrich_whois(self, ioc: IOC) -> EnrichmentResult | None:
        data: dict[str, Any] = {}
        if ioc.type == IOCType.IP:
            data = {
                "registrar": "Unknown",
                "registrant_country": "Unknown",
                "creation_date": "Unknown",
                "whois_server": "whois.arin.net",
            }
        elif ioc.type == IOCType.DOMAIN:
            data = {
                "registrar": "Unknown",
                "registrant_org": "Unknown",
                "creation_date": "Unknown",
                "expiration_date": "Unknown",
                "name_servers": [],
                "status": [],
            }
        elif ioc.type == IOCType.EMAIL:
            parts = ioc.value.split("@")
            if len(parts) == 2:
                data = {
                    "domain": parts[1],
                    "mx_records": [],
                    "domain_age": "Unknown",
                }
        return EnrichmentResult(ioc_id=ioc.ioc_id, enrichment_type="whois", data=data, source="whois_provider") if data else None

    def _enrich_geoip(self, ioc: IOC) -> EnrichmentResult | None:
        if ioc.type != IOCType.IP:
            return None
        data = {
            "country": "Unknown",
            "country_code": "XX",
            "region": "Unknown",
            "city": "Unknown",
            "latitude": 0.0,
            "longitude": 0.0,
            "isp": "Unknown",
            "as_number": "Unknown",
            "is_tor": False,
            "is_vpn": False,
        }
        return EnrichmentResult(ioc_id=ioc.ioc_id, enrichment_type="geoip", data=data, source="geoip_provider")

    def _enrich_reverse_dns(self, ioc: IOC) -> EnrichmentResult | None:
        if ioc.type != IOCType.IP:
            return None
        data = {
            "hostname": f"{ioc.value}.unknown",
            "resolution_confidence": 0.0,
        }
        return EnrichmentResult(ioc_id=ioc.ioc_id, enrichment_type="reverse_dns", data=data, source="dns_provider")

    def _enrich_abuse_ch(self, ioc: IOC) -> EnrichmentResult | None:
        data: dict[str, Any] = {}
        if ioc.type in (IOCType.IP, IOCType.DOMAIN):
            data = {
                "malware_prints": [],
                "first_seen": None,
                "last_seen": None,
                "tags": [],
                "threat_type": "unknown",
                "confidence": 0,
            }
        elif ioc.type == IOCType.HASH:
            data = {
                "file_type": "unknown",
                "file_size": 0,
                "signature": "unknown",
                "tags": [],
            }
        return EnrichmentResult(ioc_id=ioc.ioc_id, enrichment_type="abuse_ch", data=data, source="abuse.ch") if data else None

    def _enrich_virustotal(self, ioc: IOC) -> EnrichmentResult | None:
        data: dict[str, Any] = {}
        if ioc.type == IOCType.IP:
            data = {
                "detection_ratio": "0/90",
                "reputation": 0,
                "asn": "Unknown",
                "as_owner": "Unknown",
                "country": "Unknown",
                "network": "Unknown",
            }
        elif ioc.type == IOCType.DOMAIN:
            data = {
                "detection_ratio": "0/90",
                "reputation": 0,
                "categories": {},
                "popularity_ranks": {},
            }
        elif ioc.type == IOCType.HASH:
            data = {
                "detection_ratio": "0/70",
                "file_type": "unknown",
                "file_size": 0,
                "names": [],
                "tags": [],
            }
        elif ioc.type == IOCType.URL:
            data = {
                "detection_ratio": "0/90",
                "categories": {},
                "title": "Unknown",
            }
        return EnrichmentResult(ioc_id=ioc.ioc_id, enrichment_type="virustotal", data=data, source="virustotal") if data else None

    def _normalize_value(self, ioc_type: IOCType, value: str) -> str:
        value = value.strip()
        if ioc_type == IOCType.IP:
            return self._normalize_ip(value)
        elif ioc_type == IOCType.DOMAIN:
            return value.lower().rstrip(".")
        elif ioc_type == IOCType.HASH:
            return value.lower()
        elif ioc_type == IOCType.URL:
            return value.rstrip("/").lower()
        elif ioc_type == IOCType.EMAIL:
            return value.lower()
        return value

    def _normalize_ip(self, ip: str) -> str:
        parts = ip.split(".")
        if len(parts) == CONST_4:
            try:
                return ".".join(str(min(255, max(0, int(p)))) for p in parts)
            except ValueError:
                pass
        return ip

    def _find_by_value(self, ioc_type: IOCType, value: str) -> IOC | None:
        index = self.ioc_index.get(ioc_type.value, {})
        ioc_id = index.get(value)
        if ioc_id:
            return self.iocs.get(ioc_id)
        return None

    def _parse_stix_pattern(self, pattern: str) -> tuple[IOCType | None, str | None]:
        ip_match = re.search(r"ipv4-addr:value\s*=\s*'([^']+)'", pattern)
        if ip_match:
            return IOCType.IP, ip_match.group(1)
        domain_match = re.search(r"domain-name:value\s*=\s*'([^']+)'", pattern)
        if domain_match:
            return IOCType.DOMAIN, domain_match.group(1)
        url_match = re.search(r"url:value\s*=\s*'([^']+)'", pattern)
        if url_match:
            return IOCType.URL, url_match.group(1)
        email_match = re.search(r"email-addr:value\s*=\s*'([^']+)'", pattern)
        if email_match:
            return IOCType.EMAIL, email_match.group(1)
        hash_match = re.search(r"file:hashes\.\w+\s*=\s*'([^']+)'", pattern)
        if hash_match:
            return IOCType.HASH, hash_match.group(1)
        return None, None

    def search(self, query: str, ioc_type: IOCType | None = None) -> list[IOC]:
        query_lower = query.lower()
        results: list[IOC] = []
        types_to_search = [ioc_type] if ioc_type else list(IOCType)
        for itype in types_to_search:
            for ioc in self.iocs.values():
                if ioc.type == itype and ioc.status == IOCStatus.ACTIVE:
                    if query_lower in ioc.value.lower() or query_lower in ioc.description.lower():
                        results.append(ioc)
                    elif any(query_lower in tag.lower() for tag in ioc.tags):
                        results.append(ioc)
        return results

    def get_by_type(self, ioc_type: IOCType, active_only: bool = True) -> list[IOC]:
        results = [ioc for ioc in self.iocs.values() if ioc.type == ioc_type]
        if active_only:
            results = [ioc for ioc in results if ioc.status == IOCStatus.ACTIVE]
        return results

    def get_by_severity(self, min_severity: float = 0.7, active_only: bool = True) -> list[IOC]:
        results = [ioc for ioc in self.iocs.values() if ioc.severity >= min_severity]
        if active_only:
            results = [ioc for ioc in results if ioc.status == IOCStatus.ACTIVE]
        return sorted(results, key=lambda x: x.severity, reverse=True)

    def get_by_source(self, source: str, active_only: bool = True) -> list[IOC]:
        results = [ioc for ioc in self.iocs.values() if ioc.source == source]
        if active_only:
            results = [ioc for ioc in results if ioc.status == IOCStatus.ACTIVE]
        return results

    def get_expired(self) -> list[IOC]:
        return [ioc for ioc in self.iocs.values() if ioc.status == IOCStatus.EXPIRED]

    def calculate_score(self, ioc: IOC) -> float:
        confidence_weight = CONST_0_3
        severity_weight = CONST_0_3
        age_weight = CONST_0_15
        sightings_weight = CONST_0_15
        enrichment_weight = 0.1

        age_days = 0
        if ioc.first_seen:
            age_days = (datetime.utcnow() - ioc.first_seen).days
        age_factor = max(0, 1 - (age_days / 365))

        sightings_factor = min(1.0, ioc.sightings / 10)

        enrichment_factor = min(1.0, len(ioc.enrichment) / 5)

        score = (
            ioc.confidence * confidence_weight
            + ioc.severity * severity_weight
            + age_factor * age_weight
            + sightings_factor * sightings_weight
            + enrichment_factor * enrichment_weight
        )
        return round(min(1.0, max(0.0, score)), CONST_4)

    def get_iocs_as_dicts(self, active_only: bool = True) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for ioc in self.iocs.values():
            if active_only and ioc.status != IOCStatus.ACTIVE:
                continue
            results.append({
                "ioc_id": ioc.ioc_id,
                "type": ioc.type.value,
                "value": ioc.value,
                "confidence": ioc.confidence,
                "severity": ioc.severity,
                "score": self.calculate_score(ioc),
                "source": ioc.source,
                "description": ioc.description,
                "tags": ioc.tags,
                "status": ioc.status.value,
                "created_at": ioc.created_at.isoformat(),
                "expires_at": ioc.expires_at.isoformat() if ioc.expires_at else None,
                "first_seen": ioc.first_seen.isoformat() if ioc.first_seen else None,
                "last_seen": ioc.last_seen.isoformat() if ioc.last_seen else None,
                "sightings": ioc.sightings,
                "mitre_tactics": ioc.mitre_tactics,
                "enrichment": ioc.enrichment,
            })
        return results

    def get_statistics(self) -> dict[str, Any]:
        total = len(self.iocs)
        active = sum(1 for ioc in self.iocs.values() if ioc.status == IOCStatus.ACTIVE)
        expired = sum(1 for ioc in self.iocs.values() if ioc.status == IOCStatus.EXPIRED)
        revoked = sum(1 for ioc in self.iocs.values() if ioc.status == IOCStatus.REVOKED)
        by_type: dict[str, int] = {}
        for ioc in self.iocs.values():
            by_type[ioc.type.value] = by_type.get(ioc.type.value, 0) + 1
        by_source: dict[str, int] = {}
        for ioc in self.iocs.values():
            by_source[ioc.source] = by_source.get(ioc.source, 0) + 1
        avg_score = 0.0
        if active > 0:
            scores = [self.calculate_score(ioc) for ioc in self.iocs.values() if ioc.status == IOCStatus.ACTIVE]
            avg_score = sum(scores) / len(scores) if scores else 0.0
        return {
            "total": total,
            "active": active,
            "expired": expired,
            "revoked": revoked,
            "by_type": by_type,
            "by_source": by_source,
            "average_score": round(avg_score, CONST_4),
        }
