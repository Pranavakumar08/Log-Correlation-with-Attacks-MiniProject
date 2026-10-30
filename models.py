# Core Data Models for Insider Threat Detection SIEM

from datetime import datetime
from enum import Enum
from typing import Dict, Any, List, Optional
import uuid

class LogSource(str, Enum):
    AUTH = "Authentication"
    FILE_ACCESS = "File / DLP"
    SYSTEM_CMD = "Endpoint / Auditd"
    BADGE_ACCESS = "Physical Badge"
    HR_CONTEXT = "HR Context"

class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class LogEvent:
    """Represents an individual access or system event ingested into the SIEM."""
    def __init__(
        self,
        source: LogSource,
        user_id: str,
        user_name: str,
        department: str,
        action: str,
        details: Dict[str, Any],
        timestamp: Optional[datetime] = None,
        event_id: Optional[str] = None,
        is_synthetic_threat: bool = False
    ):
        self.event_id = event_id or f"LOG-{uuid.uuid4().hex[:8].upper()}"
        self.timestamp = timestamp or datetime.now()
        self.source = source
        self.user_id = user_id
        self.user_name = user_name
        self.department = department
        self.action = action
        self.details = details
        self.is_synthetic_threat = is_synthetic_threat

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "source": self.source.value if isinstance(self.source, LogSource) else str(self.source),
            "user_id": self.user_id,
            "user_name": self.user_name,
            "department": self.department,
            "action": self.action,
            "details": self.details,
            "is_synthetic_threat": self.is_synthetic_threat
        }

class CorrelationRule:
    """Represents a SIEM correlation logic rule designed to detect insider threat patterns."""
    def __init__(
        self,
        rule_id: str,
        name: str,
        description: str,
        severity: Severity,
        mitre_technique: str,
        time_window_seconds: int,
        base_risk_score: int
    ):
        self.rule_id = rule_id
        self.name = name
        self.description = description
        self.severity = severity
        self.mitre_technique = mitre_technique
        self.time_window_seconds = time_window_seconds
        self.base_risk_score = base_risk_score

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "description": self.description,
            "severity": self.severity.value,
            "mitre_technique": self.mitre_technique,
            "time_window_seconds": self.time_window_seconds,
            "base_risk_score": self.base_risk_score
        }

class ThreatIncident:
    """Represents a detected insider threat pattern composed of correlated log events."""
    def __init__(
        self,
        title: str,
        user_id: str,
        user_name: str,
        department: str,
        severity: Severity,
        risk_score: int,
        rule_id: str,
        rule_name: str,
        mitre_technique: str,
        summary: str,
        correlated_events: List[LogEvent],
        recommendations: List[str],
        incident_id: Optional[str] = None,
        detected_at: Optional[datetime] = None,
        status: str = "OPEN"
    ):
        self.incident_id = incident_id or f"INC-{uuid.uuid4().hex[:6].upper()}"
        self.detected_at = detected_at or datetime.now()
        self.title = title
        self.user_id = user_id
        self.user_name = user_name
        self.department = department
        self.severity = severity
        self.risk_score = min(max(risk_score, 10), 100)
        self.rule_id = rule_id
        self.rule_name = rule_name
        self.mitre_technique = mitre_technique
        self.summary = summary
        self.correlated_events = correlated_events
        self.recommendations = recommendations
        self.status = status  # OPEN, INVESTIGATING, CONTAINED, FALSE_POSITIVE

    def to_dict(self) -> Dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "detected_at": self.detected_at.strftime("%Y-%m-%d %H:%M:%S"),
            "title": self.title,
            "user_id": self.user_id,
            "user_name": self.user_name,
            "department": self.department,
            "severity": self.severity.value if isinstance(self.severity, Severity) else str(self.severity),
            "risk_score": self.risk_score,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "mitre_technique": self.mitre_technique,
            "summary": self.summary,
            "event_count": len(self.correlated_events),
            "correlated_events": [e.to_dict() for e in self.correlated_events],
            "recommendations": self.recommendations,
            "status": self.status
        }
