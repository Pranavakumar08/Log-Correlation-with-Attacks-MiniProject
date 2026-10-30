# Synthetic Log Generator & Scenario Simulator for Insider Threat Detection
# Generates realistic enterprise access logs across diverse departments and personas

import random
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from models import LogEvent, LogSource

# Defined employee identities
USER_PERSONAS = [
    {
        "user_id": "sarah.chen",
        "user_name": "Sarah Chen",
        "department": "IT Operations",
        "role": "Lead DevOps Architect",
        "ip_home": "192.168.1.45",
        "location": "San Francisco, CA"
    },
    {
        "user_id": "marcus.vance",
        "user_name": "Marcus Vance",
        "department": "Finance",
        "role": "Senior Financial Analyst",
        "ip_home": "192.168.2.110",
        "location": "Chicago, IL"
    },
    {
        "user_id": "elena.rostova",
        "user_name": "Elena Rostova",
        "department": "Infrastructure",
        "role": "Database Administrator",
        "ip_home": "192.168.3.14",
        "location": "New York, NY"
    },
    {
        "user_id": "alex.morgan",
        "user_name": "Alex Morgan",
        "department": "Sales",
        "role": "Enterprise Account Executive",
        "ip_home": "192.168.4.88",
        "location": "Austin, TX"
    },
    {
        "user_id": "david.miller",
        "user_name": "David Miller",
        "department": "Engineering",
        "role": "Full Stack Software Engineer",
        "ip_home": "192.168.5.23",
        "location": "Seattle, WA"
    },
    {
        "user_id": "aisha.patel",
        "user_name": "Aisha Patel",
        "department": "Human Resources",
        "role": "People Operations Director",
        "ip_home": "192.168.6.99",
        "location": "Boston, MA"
    }
]

# Normal enterprise operations pool
NORMAL_ACTIONS = {
    LogSource.AUTH: [
        {"action": "SSO_LOGIN_SUCCESS", "details": {"method": "Okta MFA", "service": "Corporate Portal", "status": "200 OK"}},
        {"action": "VPN_CONNECT", "details": {"gateway": "vpn-us-west.internal", "protocol": "WireGuard", "status": "Connected"}},
        {"action": "SSH_SESSION_START", "details": {"target_host": "dev-node-04.corp", "port": 22, "auth_type": "Public Key"}},
        {"action": "KERBEROS_TICKET_RENEW", "details": {"domain": "CORP.LOCAL", "ticket_lifetime": "8h"}}
    ],
    LogSource.FILE_ACCESS: [
        {"action": "FILE_READ", "details": {"file_name": "Q3_Sprint_Roadmap.pdf", "file_size_mb": 4.2, "sensitivity": "INTERNAL"}},
        {"action": "FILE_WRITE", "details": {"file_name": "Project_Budget_Draft.xlsx", "file_size_mb": 1.5, "sensitivity": "INTERNAL"}},
        {"action": "REPO_PULL", "details": {"repo": "frontend-web-portal", "branch": "main", "commits_fetched": 3}},
        {"action": "WIKI_READ", "details": {"page": "Engineering_Onboarding_Guide", "sensitivity": "PUBLIC"}}
    ],
    LogSource.SYSTEM_CMD: [
        {"action": "CMD_EXEC", "details": {"command": "git commit -m 'update auth middleware'", "elevated": False}},
        {"action": "CMD_EXEC", "details": {"command": "npm run test:unit", "elevated": False}},
        {"action": "CMD_EXEC", "details": {"command": "docker-compose up -d local-db", "elevated": False}},
        {"action": "CMD_EXEC", "details": {"command": "cat /var/log/app/server.log | grep 500", "elevated": False}}
    ],
    LogSource.BADGE_ACCESS: [
        {"action": "BADGE_SWIPE_IN", "details": {"door": "Main Entrance Turnstile", "zone": "Floor 1 Reception", "status": "Granted"}},
        {"action": "BADGE_SWIPE_IN", "details": {"door": "Cafeteria East Wing", "zone": "Floor 2 Common Area", "status": "Granted"}},
        {"action": "BADGE_SWIPE_OUT", "details": {"door": "Parking Garage Level B1", "zone": "Exterior", "status": "Granted"}}
    ]
}

class LogGenerator:
    """Generates synthetic logs and structured insider threat scenario sequences."""
    
    def __init__(self):
        self.personas = {p["user_id"]: p for p in USER_PERSONAS}

    def generate_random_normal_log(self, current_time: Optional[datetime] = None) -> LogEvent:
        """Generates a benign background enterprise log."""
        ts = current_time or datetime.now()
        persona = random.choice(USER_PERSONAS)
        source = random.choice([LogSource.AUTH, LogSource.FILE_ACCESS, LogSource.SYSTEM_CMD, LogSource.BADGE_ACCESS])
        template = random.choice(NORMAL_ACTIONS[source])
        
        details = dict(template["details"])
        details["location"] = persona["location"]
        details["ip_address"] = persona["ip_home"]

        # Department specific enrichment
        if source == LogSource.FILE_ACCESS:
            details["target_department"] = persona["department"]

        return LogEvent(
            source=source,
            user_id=persona["user_id"],
            user_name=persona["user_name"],
            department=persona["department"],
            action=template["action"],
            details=details,
            timestamp=ts,
            is_synthetic_threat=False
        )

    def generate_scenario_departing_exfiltrator(self, base_time: Optional[datetime] = None) -> List[LogEvent]:
        """
        Scenario 1: Departing employee with resignation pending exfiltrates confidential financial records
        Triggering: ITD-01 (Off-hours Exfiltration) & ITD-03 (Resigning Employee)
        """
        t = base_time or datetime.now()
        marcus = self.personas["marcus.vance"]
        events = []

        # 1. HR Notification: Resignation tendered
        events.append(LogEvent(
            source=LogSource.HR_CONTEXT,
            user_id=marcus["user_id"],
            user_name=marcus["user_name"],
            department=marcus["department"],
            action="HR_STATUS_CHANGE",
            details={
                "status": "RESIGNATION_NOTICE_PENDING",
                "reason": "Competitive Employment Offer",
                "hr_flag": True,
                "notes": "2-week notice period initiated"
            },
            timestamp=t - timedelta(minutes=40),
            is_synthetic_threat=True
        ))

        # 2. Badge / VPN access at midnight (23:45)
        night_time = t.replace(hour=23, minute=45) if t.hour < 20 else t
        events.append(LogEvent(
            source=LogSource.AUTH,
            user_id=marcus["user_id"],
            user_name=marcus["user_name"],
            department=marcus["department"],
            action="VPN_LOGIN",
            details={
                "gateway": "vpn-ext-secure.internal",
                "off_hours": True,
                "hour": 23,
                "location": marcus["location"],
                "ip_address": marcus["ip_home"],
                "mfa_verified": True
            },
            timestamp=t - timedelta(minutes=25),
            is_synthetic_threat=True
        ))

        # 3. Access to restricted financial database & high sensitivity documents
        events.append(LogEvent(
            source=LogSource.FILE_ACCESS,
            user_id=marcus["user_id"],
            user_name=marcus["user_name"],
            department=marcus["department"],
            action="BULK_EXPORT",
            details={
                "file_name": "Executive_Compensation_Q1_Q4_All_Salaries.xlsx",
                "file_size_mb": 420.0,
                "sensitivity": "CONFIDENTIAL",
                "target_department": "Finance",
                "export_destination": "Local_Disk"
            },
            timestamp=t - timedelta(minutes=15),
            is_synthetic_threat=True
        ))

        # 4. USB transfer of confidential client ledger
        events.append(LogEvent(
            source=LogSource.FILE_ACCESS,
            user_id=marcus["user_id"],
            user_name=marcus["user_name"],
            department=marcus["department"],
            action="USB_COPY",
            details={
                "file_name": "Customer_Banking_Ledger_2026_Full.dump",
                "file_size_mb": 680.0,
                "sensitivity": "RESTRICTED",
                "usb_serial": "SANDISK_CRUZER_A98F71",
                "target_department": "Finance"
            },
            timestamp=t - timedelta(minutes=5),
            is_synthetic_threat=True
        ))

        return events

    def generate_scenario_rogue_admin_tamper(self, base_time: Optional[datetime] = None) -> List[LogEvent]:
        """
        Scenario 2: Privileged admin escalates and tampers with audit logs
        Triggering: ITD-02 (Defense Impairment & Audit Tampering)
        """
        t = base_time or datetime.now()
        sarah = self.personas["sarah.chen"]
        events = []

        # 1. SSH session to core database bastion
        events.append(LogEvent(
            source=LogSource.AUTH,
            user_id=sarah["user_id"],
            user_name=sarah["user_name"],
            department=sarah["department"],
            action="SSH_SESSION_START",
            details={
                "target_host": "prod-auth-bastion-01",
                "ip_address": sarah["ip_home"],
                "location": sarah["location"]
            },
            timestamp=t - timedelta(minutes=20),
            is_synthetic_threat=True
        ))

        # 2. Elevation of privilege to root
        events.append(LogEvent(
            source=LogSource.SYSTEM_CMD,
            user_id=sarah["user_id"],
            user_name=sarah["user_name"],
            department=sarah["department"],
            action="PRIVILEGE_ELEVATION",
            details={
                "command": "sudo su - root",
                "elevated": True,
                "target_user": "root"
            },
            timestamp=t - timedelta(minutes=14),
            is_synthetic_threat=True
        ))

        # 3. Disabling Linux auditd daemon
        events.append(LogEvent(
            source=LogSource.SYSTEM_CMD,
            user_id=sarah["user_id"],
            user_name=sarah["user_name"],
            department=sarah["department"],
            action="AUDIT_TAMPERING",
            details={
                "command": "auditctl -D && systemctl stop syslog",
                "elevated": True,
                "tag": "log_tamper",
                "impact": "Event stream disabled"
            },
            timestamp=t - timedelta(minutes=8),
            is_synthetic_threat=True
        ))

        # 4. Deleting local authentication log files
        events.append(LogEvent(
            source=LogSource.SYSTEM_CMD,
            user_id=sarah["user_id"],
            user_name=sarah["user_name"],
            department=sarah["department"],
            action="LOG_PURGE",
            details={
                "command": "rm -rf /var/log/auth.log /var/log/secure",
                "elevated": True,
                "tag": "log_tamper",
                "records_deleted": 14200
            },
            timestamp=t - timedelta(minutes=2),
            is_synthetic_threat=True
        ))

        return events

    def generate_scenario_impossible_travel(self, base_time: Optional[datetime] = None) -> List[LogEvent]:
        """
        Scenario 3: Impossible travel with compromised credentials and lateral DB access
        Triggering: ITD-04 (Impossible Travel)
        """
        t = base_time or datetime.now()
        elena = self.personas["elena.rostova"]
        events = []

        # 1. Normal login from New York office
        events.append(LogEvent(
            source=LogSource.AUTH,
            user_id=elena["user_id"],
            user_name=elena["user_name"],
            department=elena["department"],
            action="SSO_LOGIN_SUCCESS",
            details={
                "location": "New York, USA",
                "ip_address": "198.51.100.44",
                "service": "AWS IAM Management Console",
                "mfa_verified": True
            },
            timestamp=t - timedelta(minutes=35),
            is_synthetic_threat=True
        ))

        # 2. Suspicious login 15 minutes later from Frankfurt / Moscow
        events.append(LogEvent(
            source=LogSource.AUTH,
            user_id=elena["user_id"],
            user_name=elena["user_name"],
            department=elena["department"],
            action="VPN_LOGIN",
            details={
                "location": "Frankfurt, Germany",
                "ip_address": "185.220.101.5",
                "isp": "Tor Exit Node / HostEurope",
                "mfa_bypass": "Session Cookie Replay"
            },
            timestamp=t - timedelta(minutes=15),
            is_synthetic_threat=True
        ))

        # 3. Lateral movement - database dump query
        events.append(LogEvent(
            source=LogSource.FILE_ACCESS,
            user_id=elena["user_id"],
            user_name=elena["user_name"],
            department=elena["department"],
            action="MASS_DOWNLOAD",
            details={
                "file_name": "customer_credentials_hash_dump.sql",
                "file_size_mb": 350.0,
                "sensitivity": "RESTRICTED",
                "query": "SELECT * FROM production_users_credential_vault",
                "target_department": "Infrastructure"
            },
            timestamp=t - timedelta(minutes=5),
            is_synthetic_threat=True
        ))

        return events

    def generate_scenario_cross_snooping(self, base_time: Optional[datetime] = None) -> List[LogEvent]:
        """
        Scenario 4: Sales rep snooping on patent intellectual property and M&A deals
        Triggering: ITD-05 (Cross-Department Snooping)
        """
        t = base_time or datetime.now()
        alex = self.personas["alex.morgan"]
        events = []

        # 1. Accessing Engineering patents
        events.append(LogEvent(
            source=LogSource.FILE_ACCESS,
            user_id=alex["user_id"],
            user_name=alex["user_name"],
            department=alex["department"],
            action="FILE_READ",
            details={
                "file_name": "Quantum_Algorithm_Patent_Pending_v2.pdf",
                "file_size_mb": 18.5,
                "sensitivity": "CONFIDENTIAL",
                "target_department": "Engineering"
            },
            timestamp=t - timedelta(minutes=20),
            is_synthetic_threat=True
        ))

        # 2. Accessing Legal M&A confidential acquisition dossier
        events.append(LogEvent(
            source=LogSource.FILE_ACCESS,
            user_id=alex["user_id"],
            user_name=alex["user_name"],
            department=alex["department"],
            action="FILE_READ",
            details={
                "file_name": "Project_Titan_Competitor_Acquisition_TermSheet.docx",
                "file_size_mb": 5.2,
                "sensitivity": "CONFIDENTIAL",
                "target_department": "Legal & Corporate M&A"
            },
            timestamp=t - timedelta(minutes=10),
            is_synthetic_threat=True
        ))

        return events
