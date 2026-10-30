# Correlation Engine for Insider Threat Detection
# Implements sliding time-window correlation across disparate access logs

from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
import math
from models import LogEvent, LogSource, Severity, ThreatIncident, CorrelationRule

class CorrelationEngine:
    """
    Core SIEM engine that correlates disparate log sources (Auth, File/DLP, System Cmd,
    Badge Access, HR context) using sliding time windows to detect insider threat patterns.
    """
    def __init__(self, time_window_minutes: int = 45):
        self.time_window = timedelta(minutes=time_window_minutes)
        self.raw_logs: List[LogEvent] = []
        self.incidents: List[ThreatIncident] = []
        
        # User event buffers: user_id -> List[LogEvent] sorted by timestamp
        self.user_buffers: Dict[str, List[LogEvent]] = {}
        
        # User profile risk tracking: user_id -> metadata & score
        self.user_risk_profiles: Dict[str, Dict[str, Any]] = {}
        
        # Registered rules
        self.rules = self._initialize_rules()
        
        # Correlation statistics
        self.stats = {
            "total_logs_processed": 0,
            "anomalies_detected": 0,
            "incidents_created": 0,
            "severity_counts": {
                "LOW": 0,
                "MEDIUM": 0,
                "HIGH": 0,
                "CRITICAL": 0
            },
            "source_counts": {
                LogSource.AUTH.value: 0,
                LogSource.FILE_ACCESS.value: 0,
                LogSource.SYSTEM_CMD.value: 0,
                LogSource.BADGE_ACCESS.value: 0,
                LogSource.HR_CONTEXT.value: 0
            }
        }

    def _initialize_rules(self) -> Dict[str, CorrelationRule]:
        return {
            "ITD-01": CorrelationRule(
                rule_id="ITD-01",
                name="Off-Hours Privilege Escalation & Data Exfiltration",
                description="User accesses systems during non-business hours, elevates privileges, and transfers sensitive data.",
                severity=Severity.CRITICAL,
                mitre_technique="T1078 (Valid Accounts), T1048 (Exfiltration Over Alternative Protocol)",
                time_window_seconds=1800,
                base_risk_score=90
            ),
            "ITD-02": CorrelationRule(
                rule_id="ITD-02",
                name="Privilege Abuse & Security Log Tampering",
                description="Administrative elevation immediately followed by disabling audit logs or clearing event records.",
                severity=Severity.CRITICAL,
                mitre_technique="T1070 (Indicator Removal on Host), T1548 (Abuse Elevation Control)",
                time_window_seconds=900,
                base_risk_score=95
            ),
            "ITD-03": CorrelationRule(
                rule_id="ITD-03",
                name="Disgruntled / Resigning Employee Asset Harvesting",
                description="Employee with pending resignation or disciplinary HR status downloading or deleting critical intellectual property.",
                severity=Severity.HIGH,
                mitre_technique="T1530 (Data from Cloud Storage Object), T1485 (Data Destruction)",
                time_window_seconds=2400,
                base_risk_score=85
            ),
            "ITD-04": CorrelationRule(
                rule_id="ITD-04",
                name="Impossible Travel & Lateral Movement",
                description="Logins from geolocations too distant to travel within the elapsed time window, followed by internal service queries.",
                severity=Severity.HIGH,
                mitre_technique="T1078.004 (Cloud Accounts), T1021 (Remote Services)",
                time_window_seconds=3600,
                base_risk_score=80
            ),
            "ITD-05": CorrelationRule(
                rule_id="ITD-05",
                name="Cross-Department Confidential Asset Snooping",
                description="Repeated access to sensitive/confidential repositories outside the employee's assigned business unit.",
                severity=Severity.MEDIUM,
                mitre_technique="T1083 (File and Directory Discovery)",
                time_window_seconds=1800,
                base_risk_score=60
            ),
            "ITD-06": CorrelationRule(
                rule_id="ITD-06",
                name="Repeated Authentication Failures followed by Privilege Spike",
                description="Multiple consecutive login/auth failures on internal systems followed by credential exploitation.",
                severity=Severity.MEDIUM,
                mitre_technique="T1110 (Brute Force)",
                time_window_seconds=1200,
                base_risk_score=65
            )
        }

    def process_event(self, event: LogEvent) -> List[ThreatIncident]:
        """
        Ingest and process a single log event.
        Returns any new incidents triggered by this event.
        """
        self.raw_logs.append(event)
        self.stats["total_logs_processed"] += 1
        
        # Update source counters
        source_val = event.source.value if isinstance(event.source, LogSource) else str(event.source)
        if source_val in self.stats["source_counts"]:
            self.stats["source_counts"][source_val] += 1
        else:
            self.stats["source_counts"][source_val] = 1

        # Maintain per-user event buffer
        user_id = event.user_id
        if user_id not in self.user_buffers:
            self.user_buffers[user_id] = []
            self.user_risk_profiles[user_id] = {
                "user_id": user_id,
                "user_name": event.user_name,
                "department": event.department,
                "risk_score": 10,
                "risk_level": "LOW",
                "incident_count": 0,
                "last_active": event.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                "status": "NORMAL"
            }
        
        self.user_buffers[user_id].append(event)
        self.user_risk_profiles[user_id]["last_active"] = event.timestamp.strftime("%Y-%m-%d %H:%M:%S")

        # Keep buffer within time window
        cutoff_time = event.timestamp - self.time_window
        self.user_buffers[user_id] = [e for e in self.user_buffers[user_id] if e.timestamp >= cutoff_time]

        # Execute correlation detection rules
        new_incidents: List[ThreatIncident] = []
        
        # Check rule 1: Off-Hours Elevation & Exfiltration
        inc_1 = self._check_off_hours_exfiltration(user_id, event)
        if inc_1: new_incidents.append(inc_1)

        # Check rule 2: Privilege Abuse & Log Clearing
        inc_2 = self._check_privilege_tampering(user_id, event)
        if inc_2: new_incidents.append(inc_2)

        # Check rule 3: Resigning Employee Harvesting
        inc_3 = self._check_resigning_employee(user_id, event)
        if inc_3: new_incidents.append(inc_3)

        # Check rule 4: Impossible Travel
        inc_4 = self._check_impossible_travel(user_id, event)
        if inc_4: new_incidents.append(inc_4)

        # Check rule 5: Cross-Department Snooping
        inc_5 = self._check_cross_department_snooping(user_id, event)
        if inc_5: new_incidents.append(inc_5)

        # Register and score newly detected incidents
        for inc in new_incidents:
            self._register_incident(inc)

        return new_incidents

    def _register_incident(self, incident: ThreatIncident):
        """Records the incident, updates risk scores and statistics."""
        self.incidents.insert(0, incident)  # newest first
        self.stats["incidents_created"] += 1
        self.stats["anomalies_detected"] += len(incident.correlated_events)
        
        sev = incident.severity.value
        if sev in self.stats["severity_counts"]:
            self.stats["severity_counts"][sev] += 1

        # Elevate user risk profile
        u_id = incident.user_id
        if u_id in self.user_risk_profiles:
            profile = self.user_risk_profiles[u_id]
            profile["incident_count"] += 1
            # Weighted cumulative risk score
            boost = incident.risk_score * 0.6
            profile["risk_score"] = min(100, int(profile["risk_score"] + boost))
            
            if profile["risk_score"] >= 80:
                profile["risk_level"] = "CRITICAL"
                profile["status"] = "FLAGGED_RESTRICTED"
            elif profile["risk_score"] >= 60:
                profile["risk_level"] = "HIGH"
                profile["status"] = "UNDER_REVIEW"
            elif profile["risk_score"] >= 35:
                profile["risk_level"] = "ELEVATED"
            else:
                profile["risk_level"] = "LOW"

    # --- Correlation Rule Evaluators ---

    def _check_off_hours_exfiltration(self, user_id: str, current_event: LogEvent) -> Optional[ThreatIncident]:
        """
        Rule ITD-01:
        1. Login during non-business hours (between 21:00 and 06:00 or weekend)
        2. Elevation / Privileged access (sudo, admin, privilege escalation)
        3. High volume file transfer, confidential download, or USB connection
        """
        events = self.user_buffers.get(user_id, [])
        if len(events) < 2:
            return None

        off_hour_logins = []
        elevations = []
        exfiltrations = []

        for e in events:
            # Check off-hours auth
            if e.source in [LogSource.AUTH, LogSource.BADGE_ACCESS]:
                hour = e.timestamp.hour
                is_off_hours = (hour >= 20 or hour < 6) or (e.timestamp.weekday() >= 5)
                if is_off_hours or e.details.get("off_hours", False):
                    off_hour_logins.append(e)
            
            # Check elevation
            if e.source == LogSource.SYSTEM_CMD:
                cmd = str(e.details.get("command", "")).lower()
                action = str(e.action).lower()
                if "sudo" in cmd or "runas" in cmd or "elevation" in action or e.details.get("elevated", False):
                    elevations.append(e)

            # Check exfiltration / large confidential transfer
            if e.source == LogSource.FILE_ACCESS:
                size = e.details.get("file_size_mb", 0)
                sensitivity = str(e.details.get("sensitivity", "")).upper()
                action = str(e.action).upper()
                is_exfil_action = any(kw in action for kw in ["DOWNLOAD", "EXPORT", "USB", "UPLOAD", "COPY", "PULL"])
                if (size > 80 or sensitivity in ["CONFIDENTIAL", "RESTRICTED", "SECRET"]) and is_exfil_action:
                    exfiltrations.append(e)

        # Correlate sequence: off hours + exfiltration, or off hours + elevation + exfiltration
        if off_hour_logins and exfiltrations:
            correlated = list({e.event_id: e for e in (off_hour_logins + elevations + exfiltrations)}.values())
            correlated.sort(key=lambda x: x.timestamp)
            
            # Check if this exact cluster was already reported or merge events
            if self._is_already_reported_or_update("ITD-01", user_id, correlated):
                return None

            rule = self.rules["ITD-01"]
            return ThreatIncident(
                title=f"Off-Hours Exfiltration Pattern: {current_event.user_name}",
                user_id=user_id,
                user_name=current_event.user_name,
                department=current_event.department,
                severity=rule.severity,
                risk_score=rule.base_risk_score,
                rule_id=rule.rule_id,
                rule_name=rule.name,
                mitre_technique=rule.mitre_technique,
                summary=(
                    f"Correlated {len(correlated)} events across Authentication, Endpoint Command, and File Transfer streams. "
                    f"User logged in outside standard business hours, exercised elevated privileges, and transferred sensitive data."
                ),
                correlated_events=correlated,
                recommendations=[
                    "Temporarily revoke active VPN tokens and remote session certificates.",
                    "Isolate the endpoint workstation from internal VLAN.",
                    "Initiate DLP forensic audit on the destination IP / connected USB serial number.",
                    "Notify Security Incident Response Team (SIRT) lead."
                ]
            )
        return None

    def _check_privilege_tampering(self, user_id: str, current_event: LogEvent) -> Optional[ThreatIncident]:
        """
        Rule ITD-02:
        Administrative privilege acquisition followed by tampering with audit logs or stopping SIEM agents.
        """
        events = self.user_buffers.get(user_id, [])
        tampering_keywords = [
            "auditctl -d", "wevtutil cl", "rm -rf /var/log", "systemctl stop syslog", 
            "stop auditd", "clear eventlog", "disable logging", "del /f *.log"
        ]
        
        tamper_events = []
        priv_events = []

        for e in events:
            if e.source == LogSource.SYSTEM_CMD:
                cmd = str(e.details.get("command", "")).lower()
                if any(kw in cmd for kw in tampering_keywords) or "log_tamper" in str(e.details.get("tag", "")):
                    tamper_events.append(e)
                elif "sudo" in cmd or e.details.get("elevated", False) or "privilege" in str(e.action).lower():
                    priv_events.append(e)

        if tamper_events:
            correlated = list({e.event_id: e for e in (priv_events + tamper_events)}.values())
            correlated.sort(key=lambda x: x.timestamp)

            if self._is_already_reported_or_update("ITD-02", user_id, correlated):
                return None

            rule = self.rules["ITD-02"]
            return ThreatIncident(
                title=f"Host Audit Evasion & Defense Impairment: {current_event.user_name}",
                user_id=user_id,
                user_name=current_event.user_name,
                department=current_event.department,
                severity=rule.severity,
                risk_score=rule.base_risk_score,
                rule_id=rule.rule_id,
                rule_name=rule.name,
                mitre_technique=rule.mitre_technique,
                summary=(
                    f"Critical SIEM defense evasion detected. Correlated administrative command sequence where "
                    f"user issued commands targeting system audit daemon and event logs."
                ),
                correlated_events=correlated,
                recommendations=[
                    "Immediately freeze administrative credentials in Active Directory / LDAP.",
                    "Preserve endpoint memory dump and capture immutable remote syslog records.",
                    "Deploy forensic investigator to examine file integrity checksums.",
                    "Report unauthorized audit alteration to compliance officer."
                ]
            )
        return None

    def _check_resigning_employee(self, user_id: str, current_event: LogEvent) -> Optional[ThreatIncident]:
        """
        Rule ITD-03:
        Employee flagged with HR status (Resignation / PIP / Disciplinary) exhibiting anomalous file activity.
        """
        events = self.user_buffers.get(user_id, [])
        hr_events = [e for e in events if e.source == LogSource.HR_CONTEXT or e.details.get("hr_flag")]
        
        # Check if there is an HR trigger or flag
        is_hr_flagged = len(hr_events) > 0 or current_event.details.get("hr_flag")
        
        if is_hr_flagged:
            # Check for abnormal file actions (mass downloads, confidential access, mass deletions)
            suspicious_file_ops = []
            for e in events:
                if e.source == LogSource.FILE_ACCESS:
                    action = str(e.action).upper()
                    sens = str(e.details.get("sensitivity", "")).upper()
                    is_suspicious_act = any(kw in action for kw in ["DOWNLOAD", "EXPORT", "DELETE", "USB", "COPY"])
                    if is_suspicious_act or sens in ["CONFIDENTIAL", "RESTRICTED", "IP_PROPRIETARY"]:
                        suspicious_file_ops.append(e)

            if suspicious_file_ops:
                correlated = list({e.event_id: e for e in (hr_events + suspicious_file_ops)}.values())
                correlated.sort(key=lambda x: x.timestamp)

                if self._is_already_reported_or_update("ITD-03", user_id, correlated):
                    return None

                rule = self.rules["ITD-03"]
                return ThreatIncident(
                    title=f"Flight Risk / Departing Insider Data Harvesting: {current_event.user_name}",
                    user_id=user_id,
                    user_name=current_event.user_name,
                    department=current_event.department,
                    severity=rule.severity,
                    risk_score=rule.base_risk_score,
                    rule_id=rule.rule_id,
                    rule_name=rule.name,
                    mitre_technique=rule.mitre_technique,
                    summary=(
                        f"Correlated HR notification of pending employee exit with abnormal file acquisition. "
                        f"User accessed or exported protected corporate proprietary data."
                    ),
                    correlated_events=correlated,
                    recommendations=[
                        "Enforce immediate read-only permission restrictions across all departmental file shares.",
                        "Verify non-disclosure agreement (NDA) obligations with Human Resources.",
                        "Audit outgoing email traffic and cloud storage syncing agents.",
                        "Coordinate with line manager for supervised handover."
                    ]
                )
        return None

    def _check_impossible_travel(self, user_id: str, current_event: LogEvent) -> Optional[ThreatIncident]:
        """
        Rule ITD-04:
        Two logins from geographically distant locations within an impossible physical transit window.
        """
        events = self.user_buffers.get(user_id, [])
        auth_events = [e for e in events if e.source == LogSource.AUTH and e.details.get("location")]
        
        if len(auth_events) < 2:
            return None

        # Compare last two distinct locations
        for i in range(len(auth_events) - 1):
            e1 = auth_events[i]
            e2 = auth_events[i + 1]
            loc1 = e1.details.get("location")
            loc2 = e2.details.get("location")
            
            if loc1 and loc2 and loc1 != loc2:
                time_diff_min = abs((e2.timestamp - e1.timestamp).total_seconds()) / 60.0
                # If locations are different and happened within 90 minutes
                if time_diff_min < 90:
                    correlated = [e1, e2]
                    # Also include any subsequent internal access
                    subsequent = [e for e in events if e.timestamp >= e2.timestamp and e.event_id not in [e1.event_id, e2.event_id]]
                    correlated.extend(subsequent[:2])

                    if self._is_already_reported_or_update("ITD-04", user_id, correlated):
                        return None

                    rule = self.rules["ITD-04"]
                    return ThreatIncident(
                        title=f"Impossible Travel / Credential Hijack: {current_event.user_name}",
                        user_id=user_id,
                        user_name=current_event.user_name,
                        department=current_event.department,
                        severity=rule.severity,
                        risk_score=rule.base_risk_score,
                        rule_id=rule.rule_id,
                        rule_name=rule.name,
                        mitre_technique=rule.mitre_technique,
                        summary=(
                            f"Concurrent or rapid logins detected from {loc1} and {loc2} "
                            f"within {int(time_diff_min)} minutes. Indicates credential compromise or unauthorized proxy usage."
                        ),
                        correlated_events=correlated,
                        recommendations=[
                            "Force immediate global password reset and invalidate current session cookies.",
                            "Enforce Hardware Token / FIDO2 Multi-Factor Authentication prompt.",
                            "Block malicious originating IP range at border firewall.",
                            "Audit all active cloud and SaaS tokens linked to user."
                        ]
                    )
        return None

    def _check_cross_department_snooping(self, user_id: str, current_event: LogEvent) -> Optional[ThreatIncident]:
        """
        Rule ITD-05:
        User accessing sensitive documents from departments unrelated to their role.
        """
        events = self.user_buffers.get(user_id, [])
        file_events = [e for e in events if e.source == LogSource.FILE_ACCESS]
        user_dept = current_event.department.lower()

        snooping_events = []
        for e in file_events:
            target_dept = str(e.details.get("target_department", "")).lower()
            sens = str(e.details.get("sensitivity", "")).upper()
            if target_dept and target_dept != user_dept and sens in ["CONFIDENTIAL", "RESTRICTED"]:
                snooping_events.append(e)

        if len(snooping_events) >= 2:
            if self._is_already_reported_or_update("ITD-05", user_id, snooping_events):
                return None

            rule = self.rules["ITD-05"]
            return ThreatIncident(
                title=f"Cross-Department Confidential Snooping: {current_event.user_name}",
                user_id=user_id,
                user_name=current_event.user_name,
                department=current_event.department,
                severity=rule.severity,
                risk_score=rule.base_risk_score,
                rule_id=rule.rule_id,
                rule_name=rule.name,
                mitre_technique=rule.mitre_technique,
                summary=(
                    f"User from {current_event.department} accessed confidential documents belonging to other "
                    f"departments without business justification."
                ),
                correlated_events=snooping_events,
                recommendations=[
                    "Validate legitimate need-to-know with department head.",
                    "Review access control lists (ACLs) on sensitive network shares.",
                    "Issue security awareness advisory on data classification policies."
                ]
            )
        return None

    def _is_already_reported_or_update(self, rule_id: str, user_id: str, correlated_events: List[LogEvent]) -> bool:
        """Helper to avoid flood of duplicate alerts; updates existing incident with new events if found."""
        for inc in self.incidents:
            if inc.rule_id == rule_id and inc.user_id == user_id:
                # Merge any new correlated events into existing incident
                existing_ids = {e.event_id for e in inc.correlated_events}
                new_added = False
                for e in correlated_events:
                    if e.event_id not in existing_ids:
                        inc.correlated_events.append(e)
                        existing_ids.add(e.event_id)
                        new_added = True
                if new_added:
                    inc.correlated_events.sort(key=lambda x: x.timestamp)
                return True
        return False

    def get_logs(self, limit: int = 100, source_filter: Optional[str] = None, user_filter: Optional[str] = None) -> List[Dict[str, Any]]:
        """Returns filtered raw logs in reverse chronological order."""
        logs = self.raw_logs[::-1]
        if source_filter:
            logs = [l for l in logs if (l.source.value if isinstance(l.source, LogSource) else str(l.source)) == source_filter]
        if user_filter:
            logs = [l for l in logs if user_filter.lower() in l.user_id.lower() or user_filter.lower() in l.user_name.lower()]
        return [l.to_dict() for l in logs[:limit]]

    def get_incidents(self, limit: int = 50, severity_filter: Optional[str] = None) -> List[Dict[str, Any]]:
        """Returns detected threat incidents."""
        incidents = self.incidents
        if severity_filter:
            incidents = [i for i in incidents if i.severity.value == severity_filter]
        return [i.to_dict() for i in incidents[:limit]]

    def get_incident_by_id(self, incident_id: str) -> Optional[Dict[str, Any]]:
        """Finds a specific incident for forensic drill-down."""
        for inc in self.incidents:
            if inc.incident_id == incident_id:
                return inc.to_dict()
        return None

    def update_incident_status(self, incident_id: str, new_status: str) -> bool:
        """Updates incident handling status (e.g. INVESTIGATING, CONTAINED, FALSE_POSITIVE)."""
        for inc in self.incidents:
            if inc.incident_id == incident_id:
                inc.status = new_status
                return True
        return False

    def get_risk_leaderboard(self) -> List[Dict[str, Any]]:
        """Returns list of users ordered by threat risk score."""
        profiles = list(self.user_risk_profiles.values())
        profiles.sort(key=lambda x: x["risk_score"], reverse=True)
        return profiles

    def get_analytics(self) -> Dict[str, Any]:
        """Provides dashboard statistics and overview metrics."""
        # Calculate threat level gauge
        critical_count = self.stats["severity_counts"]["CRITICAL"]
        high_count = self.stats["severity_counts"]["HIGH"]
        
        if critical_count > 0:
            threat_level = "CRITICAL"
        elif high_count > 0:
            threat_level = "ELEVATED"
        elif self.stats["incidents_created"] > 0:
            threat_level = "GUARDED"
        else:
            threat_level = "NORMAL"

        return {
            "threat_level": threat_level,
            "total_logs": self.stats["total_logs_processed"],
            "total_incidents": self.stats["incidents_created"],
            "anomalies_detected": self.stats["anomalies_detected"],
            "severity_breakdown": self.stats["severity_counts"],
            "source_breakdown": self.stats["source_counts"],
            "active_users_tracked": len(self.user_risk_profiles),
            "high_risk_users_count": len([p for p in self.user_risk_profiles.values() if p["risk_score"] >= 60])
        }

    def reset(self):
        """Clears all logs and incidents."""
        self.raw_logs.clear()
        self.incidents.clear()
        self.user_buffers.clear()
        self.user_risk_profiles.clear()
        self.stats = {
            "total_logs_processed": 0,
            "anomalies_detected": 0,
            "incidents_created": 0,
            "severity_counts": {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0},
            "source_counts": {s.value: 0 for s in LogSource}
        }
