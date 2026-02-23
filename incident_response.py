"""
BlackRoad Incident Response - Security incident tracking, playbooks, and reporting.
Covers ransomware, phishing, breach, DDoS, insider threat, supply chain attacks.
"""

import json
import sqlite3
import uuid
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from typing import Optional
from enum import Enum


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class IncidentType(str, Enum):
    RANSOMWARE = "ransomware"
    PHISHING = "phishing"
    BREACH = "breach"
    DDOS = "ddos"
    INSIDER = "insider"
    SUPPLY_CHAIN = "supply_chain"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IncidentStatus(str, Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    ERADICATED = "eradicated"
    RECOVERED = "recovered"
    CLOSED = "closed"


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class TimelineEntry:
    timestamp: str
    action: str
    actor: str
    notes: str = ""


@dataclass
class Incident:
    id: str
    type: IncidentType
    severity: Severity
    status: IncidentStatus
    title: str
    description: str
    affected_systems: list
    iocs: list
    timeline: list          # list of TimelineEntry dicts
    playbook_id: Optional[str]
    assigned_to: str
    created_at: str
    contained_at: Optional[str]
    resolved_at: Optional[str]

    def to_dict(self) -> dict:
        d = asdict(self)
        d["type"] = self.type.value
        d["severity"] = self.severity.value
        d["status"] = self.status.value
        return d


@dataclass
class PlaybookStep:
    order: int
    title: str
    description: str
    responsible: str      # SOC analyst, CISO, Legal, IT, etc.
    tools: list
    done: bool = False


@dataclass
class Playbook:
    id: str
    incident_type: IncidentType
    name: str
    description: str
    steps: list           # list of PlaybookStep dicts
    contacts: list        # emergency contacts

    def to_dict(self) -> dict:
        d = asdict(self)
        d["incident_type"] = self.incident_type.value
        return d


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

SCHEMA = """
CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    severity TEXT NOT NULL,
    status TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    affected_systems TEXT NOT NULL,
    iocs TEXT NOT NULL,
    timeline TEXT NOT NULL,
    playbook_id TEXT,
    assigned_to TEXT NOT NULL,
    created_at TEXT NOT NULL,
    contained_at TEXT,
    resolved_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity);
CREATE INDEX IF NOT EXISTS idx_incidents_type ON incidents(type);

CREATE TABLE IF NOT EXISTS playbooks (
    id TEXT PRIMARY KEY,
    incident_type TEXT NOT NULL,
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    steps TEXT NOT NULL,
    contacts TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS incident_notes (
    id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL,
    author TEXT NOT NULL,
    content TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (incident_id) REFERENCES incidents(id)
);
"""

# ---------------------------------------------------------------------------
# Default Playbooks
# ---------------------------------------------------------------------------

RANSOMWARE_PLAYBOOK = {
    "incident_type": "ransomware",
    "name": "Ransomware Response Playbook",
    "description": "Steps to respond to a ransomware attack",
    "steps": [
        {"order": 1, "title": "Isolate infected systems",
         "description": "Immediately disconnect affected systems from network (unplug Ethernet, disable WiFi). Do NOT power off.",
         "responsible": "IT", "tools": ["network-switch", "firewall"]},
        {"order": 2, "title": "Identify scope",
         "description": "Determine which systems are encrypted, identify patient-zero, check for lateral spread.",
         "responsible": "SOC", "tools": ["edr", "siem", "network-scanner"]},
        {"order": 3, "title": "Notify stakeholders",
         "description": "Alert CISO, legal, executive team. Determine if breach notification is required.",
         "responsible": "CISO", "tools": ["email", "phone"]},
        {"order": 4, "title": "Preserve evidence",
         "description": "Take memory dumps, disk images of infected systems. Preserve logs.",
         "responsible": "IR-Team", "tools": ["volatility", "dd", "ftkimager"]},
        {"order": 5, "title": "Assess backup integrity",
         "description": "Verify backups are clean and accessible. Check backup timestamps.",
         "responsible": "IT", "tools": ["backup-tool"]},
        {"order": 6, "title": "Eradicate malware",
         "description": "Wipe and reinstall affected systems. Remove persistence mechanisms.",
         "responsible": "IT", "tools": ["antimalware", "edr"]},
        {"order": 7, "title": "Restore from backups",
         "description": "Restore clean systems from verified backups. Validate data integrity.",
         "responsible": "IT", "tools": ["backup-tool"]},
        {"order": 8, "title": "Post-incident review",
         "description": "Conduct lessons-learned meeting. Update security controls.",
         "responsible": "CISO", "tools": []},
    ],
    "contacts": ["CISO", "Legal", "PR", "Executive Team", "Law Enforcement (FBI Cyber)"],
}

PHISHING_PLAYBOOK = {
    "incident_type": "phishing",
    "name": "Phishing Response Playbook",
    "description": "Steps to respond to a phishing attack",
    "steps": [
        {"order": 1, "title": "Contain phishing email",
         "description": "Pull phishing email from all inboxes using email admin tools.",
         "responsible": "IT", "tools": ["o365-admin", "google-admin"]},
        {"order": 2, "title": "Identify victims",
         "description": "Determine who clicked links or opened attachments.",
         "responsible": "SOC", "tools": ["email-logs", "proxy-logs"]},
        {"order": 3, "title": "Reset credentials",
         "description": "Force password reset for all users who clicked. Enable MFA.",
         "responsible": "IT", "tools": ["active-directory", "okta"]},
        {"order": 4, "title": "Block malicious domains",
         "description": "Block sender domains, URLs in firewall and proxy.",
         "responsible": "SOC", "tools": ["firewall", "proxy", "dns-filter"]},
        {"order": 5, "title": "Scan for compromise",
         "description": "Run endpoint scans on victim machines for malware.",
         "responsible": "SOC", "tools": ["edr", "antivirus"]},
        {"order": 6, "title": "User notification",
         "description": "Notify affected users, provide security awareness training.",
         "responsible": "HR", "tools": ["email"]},
    ],
    "contacts": ["CISO", "HR", "Legal"],
}

BREACH_PLAYBOOK = {
    "incident_type": "breach",
    "name": "Data Breach Response Playbook",
    "description": "Steps to respond to a data breach",
    "steps": [
        {"order": 1, "title": "Confirm and scope the breach",
         "description": "Verify the breach occurred. Determine data types and volume affected.",
         "responsible": "IR-Team", "tools": ["dlp", "siem"]},
        {"order": 2, "title": "Contain the breach",
         "description": "Block attacker access. Revoke compromised credentials. Close vulnerabilities.",
         "responsible": "SOC", "tools": ["firewall", "iam"]},
        {"order": 3, "title": "Legal and regulatory notification",
         "description": "Determine breach notification obligations (GDPR 72h, HIPAA, PCI DSS).",
         "responsible": "Legal", "tools": ["legal-team"]},
        {"order": 4, "title": "Notify affected individuals",
         "description": "Draft and send breach notifications per regulatory requirements.",
         "responsible": "Legal", "tools": ["email", "postal-service"]},
        {"order": 5, "title": "Forensic investigation",
         "description": "Conduct full forensic analysis to understand attack vector and data exposed.",
         "responsible": "IR-Team", "tools": ["forensics-tools"]},
        {"order": 6, "title": "Remediate vulnerabilities",
         "description": "Patch exploited vulnerabilities. Implement additional controls.",
         "responsible": "IT", "tools": ["patch-management"]},
    ],
    "contacts": ["CISO", "Legal", "Privacy Officer", "PR", "Regulators"],
}

DDOS_PLAYBOOK = {
    "incident_type": "ddos",
    "name": "DDoS Response Playbook",
    "description": "Steps to respond to a Distributed Denial of Service attack",
    "steps": [
        {"order": 1, "title": "Detect and confirm DDoS",
         "description": "Confirm attack via traffic analysis. Identify attack type (volumetric, protocol, application).",
         "responsible": "NOC", "tools": ["netflow", "traffic-analyzer"]},
        {"order": 2, "title": "Enable DDoS protection",
         "description": "Activate CDN DDoS protection (Cloudflare, Akamai). Apply rate limiting.",
         "responsible": "IT", "tools": ["cloudflare", "cdn"]},
        {"order": 3, "title": "Traffic scrubbing",
         "description": "Route traffic through scrubbing center. Block attack source IPs.",
         "responsible": "NOC", "tools": ["scrubbing-center", "firewall"]},
        {"order": 4, "title": "Upstream filtering",
         "description": "Contact ISP for upstream null-routing of attack traffic.",
         "responsible": "IT", "tools": ["isp-noc"]},
        {"order": 5, "title": "Monitor recovery",
         "description": "Monitor service recovery. Gradually restore traffic.",
         "responsible": "NOC", "tools": ["monitoring"]},
    ],
    "contacts": ["NOC", "ISP NOC", "CDN Support", "Management"],
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _row_to_incident(row: tuple) -> Incident:
    (id_, type_, sev, status, title, desc, systems_j, iocs_j,
     timeline_j, pb_id, assigned, created, contained, resolved) = row
    return Incident(
        id=id_, type=IncidentType(type_), severity=Severity(sev),
        status=IncidentStatus(status), title=title, description=desc,
        affected_systems=json.loads(systems_j), iocs=json.loads(iocs_j),
        timeline=json.loads(timeline_j), playbook_id=pb_id,
        assigned_to=assigned, created_at=created,
        contained_at=contained, resolved_at=resolved,
    )


def _row_to_playbook(row: tuple) -> Playbook:
    id_, itype, name, desc, steps_j, contacts_j = row
    return Playbook(
        id=id_, incident_type=IncidentType(itype), name=name,
        description=desc, steps=json.loads(steps_j),
        contacts=json.loads(contacts_j),
    )


# ---------------------------------------------------------------------------
# IncidentResponseDB
# ---------------------------------------------------------------------------

class IncidentResponseDB:
    """Core incident response management system."""

    def __init__(self, db_path: str = "incident_response.db"):
        self.db_path = db_path
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_db(self):
        with self._connect() as conn:
            conn.executescript(SCHEMA)
            count = conn.execute("SELECT COUNT(*) FROM playbooks").fetchone()[0]
            if count == 0:
                self._load_default_playbooks()

    def _load_default_playbooks(self):
        for pb_data in [RANSOMWARE_PLAYBOOK, PHISHING_PLAYBOOK, BREACH_PLAYBOOK, DDOS_PLAYBOOK]:
            self._insert_playbook(pb_data)

    def _insert_playbook(self, pb_data: dict) -> Playbook:
        pb = Playbook(
            id=str(uuid.uuid5(uuid.NAMESPACE_DNS, pb_data["incident_type"])),
            incident_type=IncidentType(pb_data["incident_type"]),
            name=pb_data["name"],
            description=pb_data["description"],
            steps=pb_data["steps"],
            contacts=pb_data["contacts"],
        )
        with self._connect() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO playbooks (id, incident_type, name, description, steps, contacts) VALUES (?,?,?,?,?,?)",
                (pb.id, pb.incident_type.value, pb.name, pb.description,
                 json.dumps(pb.steps), json.dumps(pb.contacts)),
            )
        return pb

    # ------------------------------------------------------------------
    # Incident CRUD
    # ------------------------------------------------------------------

    def create_incident(
        self,
        type: str,
        severity: str,
        systems: list,
        title: str = "",
        description: str = "",
        assigned_to: str = "unassigned",
    ) -> Incident:
        """Create a new incident and auto-assign a playbook."""
        try:
            inc_type = IncidentType(type.lower())
        except ValueError:
            raise ValueError(f"Unknown incident type: {type}")
        try:
            inc_sev = Severity(severity.lower())
        except ValueError:
            raise ValueError(f"Unknown severity: {severity}")

        inc_id = str(uuid.uuid4())
        if not title:
            title = f"{inc_type.value.upper()} incident - {inc_id[:8]}"

        incident = Incident(
            id=inc_id,
            type=inc_type,
            severity=inc_sev,
            status=IncidentStatus.OPEN,
            title=title,
            description=description,
            affected_systems=systems,
            iocs=[],
            timeline=[{"timestamp": _now(), "action": "Incident created", "actor": "system", "notes": ""}],
            playbook_id=None,
            assigned_to=assigned_to,
            created_at=_now(),
            contained_at=None,
            resolved_at=None,
        )
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO incidents
                   (id, type, severity, status, title, description, affected_systems, iocs,
                    timeline, playbook_id, assigned_to, created_at, contained_at, resolved_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (incident.id, incident.type.value, incident.severity.value,
                 incident.status.value, incident.title, incident.description,
                 json.dumps(incident.affected_systems), json.dumps(incident.iocs),
                 json.dumps(incident.timeline), incident.playbook_id,
                 incident.assigned_to, incident.created_at, None, None),
            )
        # Auto-assign playbook
        self.assign_playbook(inc_id)
        return self.get_incident(inc_id)

    def get_incident(self, incident_id: str) -> Optional[Incident]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM incidents WHERE id=?", (incident_id,)
            ).fetchone()
        return _row_to_incident(row) if row else None

    def list_incidents(self, status: str = None) -> list:
        with self._connect() as conn:
            if status:
                rows = conn.execute(
                    "SELECT * FROM incidents WHERE status=? ORDER BY created_at DESC",
                    (status.lower(),),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM incidents ORDER BY created_at DESC"
                ).fetchall()
        return [_row_to_incident(r) for r in rows]

    def update_status(self, incident_id: str, status: str) -> Optional[Incident]:
        try:
            new_status = IncidentStatus(status.lower())
        except ValueError:
            raise ValueError(f"Unknown status: {status}")
        now = _now()
        with self._connect() as conn:
            conn.execute(
                "UPDATE incidents SET status=? WHERE id=?", (new_status.value, incident_id)
            )
        self.add_timeline_entry(incident_id, f"Status changed to {new_status.value}", "system")
        return self.get_incident(incident_id)

    # ------------------------------------------------------------------
    # Playbooks
    # ------------------------------------------------------------------

    def assign_playbook(self, incident_id: str) -> Optional[Playbook]:
        """Find and assign the best matching playbook for an incident."""
        incident = self.get_incident(incident_id)
        if not incident:
            return None
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM playbooks WHERE incident_type=?",
                (incident.type.value,),
            ).fetchone()
        if not row:
            return None
        playbook = _row_to_playbook(row)
        with self._connect() as conn:
            conn.execute(
                "UPDATE incidents SET playbook_id=? WHERE id=?",
                (playbook.id, incident_id),
            )
        self.add_timeline_entry(incident_id, f"Playbook assigned: {playbook.name}", "system")
        return playbook

    def get_playbook(self, playbook_id: str) -> Optional[Playbook]:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM playbooks WHERE id=?", (playbook_id,)).fetchone()
        return _row_to_playbook(row) if row else None

    def list_playbooks(self) -> list:
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM playbooks").fetchall()
        return [_row_to_playbook(r) for r in rows]

    # ------------------------------------------------------------------
    # Timeline
    # ------------------------------------------------------------------

    def add_timeline_entry(
        self, incident_id: str, action: str, actor: str, notes: str = ""
    ) -> Optional[Incident]:
        """Append an entry to the incident timeline."""
        incident = self.get_incident(incident_id)
        if not incident:
            return None
        entry = {"timestamp": _now(), "action": action, "actor": actor, "notes": notes}
        incident.timeline.append(entry)
        with self._connect() as conn:
            conn.execute(
                "UPDATE incidents SET timeline=? WHERE id=?",
                (json.dumps(incident.timeline), incident_id),
            )
        return self.get_incident(incident_id)

    def add_ioc(self, incident_id: str, ioc: str, ioc_type: str = "") -> Optional[Incident]:
        """Add an IOC to the incident."""
        incident = self.get_incident(incident_id)
        if not incident:
            return None
        ioc_entry = {"value": ioc, "type": ioc_type, "added_at": _now()}
        if ioc_entry not in incident.iocs:
            incident.iocs.append(ioc_entry)
        with self._connect() as conn:
            conn.execute(
                "UPDATE incidents SET iocs=? WHERE id=?",
                (json.dumps(incident.iocs), incident_id),
            )
        self.add_timeline_entry(incident_id, f"IOC added: {ioc}", "analyst")
        return self.get_incident(incident_id)

    def assign_to(self, incident_id: str, assignee: str) -> Optional[Incident]:
        with self._connect() as conn:
            conn.execute(
                "UPDATE incidents SET assigned_to=? WHERE id=?", (assignee, incident_id)
            )
        self.add_timeline_entry(incident_id, f"Assigned to {assignee}", "system")
        return self.get_incident(incident_id)

    # ------------------------------------------------------------------
    # Containment
    # ------------------------------------------------------------------

    def mark_contained(self, incident_id: str) -> Optional[Incident]:
        """Mark incident as contained and record containment time."""
        now = _now()
        with self._connect() as conn:
            conn.execute(
                "UPDATE incidents SET status=?, contained_at=? WHERE id=?",
                (IncidentStatus.CONTAINED.value, now, incident_id),
            )
        self.add_timeline_entry(incident_id, "Incident contained", "IR-Team")
        return self.get_incident(incident_id)

    def mark_resolved(self, incident_id: str) -> Optional[Incident]:
        """Mark incident as resolved."""
        now = _now()
        with self._connect() as conn:
            conn.execute(
                "UPDATE incidents SET status=?, resolved_at=? WHERE id=?",
                (IncidentStatus.CLOSED.value, now, incident_id),
            )
        self.add_timeline_entry(incident_id, "Incident resolved and closed", "IR-Team")
        return self.get_incident(incident_id)

    # ------------------------------------------------------------------
    # Metrics
    # ------------------------------------------------------------------

    def calculate_dwell_time(self, incident_id: str) -> Optional[dict]:
        """Calculate time-to-contain and time-to-resolve metrics."""
        incident = self.get_incident(incident_id)
        if not incident:
            return None
        created = datetime.fromisoformat(incident.created_at)

        result = {"incident_id": incident_id, "created_at": incident.created_at}

        if incident.contained_at:
            contained = datetime.fromisoformat(incident.contained_at)
            ttc = (contained - created).total_seconds()
            result["time_to_contain_seconds"] = ttc
            result["time_to_contain_human"] = _format_duration(ttc)
        else:
            result["time_to_contain_seconds"] = None
            result["time_to_contain_human"] = "Not yet contained"

        if incident.resolved_at:
            resolved = datetime.fromisoformat(incident.resolved_at)
            ttr = (resolved - created).total_seconds()
            result["time_to_resolve_seconds"] = ttr
            result["time_to_resolve_human"] = _format_duration(ttr)
        else:
            result["time_to_resolve_seconds"] = None
            result["time_to_resolve_human"] = "Not yet resolved"

        return result

    def stats(self) -> dict:
        """Return overall incident statistics."""
        with self._connect() as conn:
            total = conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
            by_status = conn.execute(
                "SELECT status, COUNT(*) FROM incidents GROUP BY status"
            ).fetchall()
            by_type = conn.execute(
                "SELECT type, COUNT(*) FROM incidents GROUP BY type"
            ).fetchall()
            by_severity = conn.execute(
                "SELECT severity, COUNT(*) FROM incidents GROUP BY severity"
            ).fetchall()
            open_critical = conn.execute(
                "SELECT COUNT(*) FROM incidents WHERE status != 'closed' AND severity = 'critical'"
            ).fetchone()[0]
        return {
            "total": total,
            "open_critical": open_critical,
            "by_status": dict(by_status),
            "by_type": dict(by_type),
            "by_severity": dict(by_severity),
        }

    # ------------------------------------------------------------------
    # Reporting
    # ------------------------------------------------------------------

    def generate_report(self, incident_id: str) -> str:
        """Generate a detailed incident report as a formatted string."""
        incident = self.get_incident(incident_id)
        if not incident:
            return f"Incident {incident_id} not found"

        playbook = self.get_playbook(incident.playbook_id) if incident.playbook_id else None
        dwell = self.calculate_dwell_time(incident_id)

        lines = [
            "=" * 70,
            f"INCIDENT REPORT",
            "=" * 70,
            f"ID:           {incident.id}",
            f"Title:        {incident.title}",
            f"Type:         {incident.type.value.upper()}",
            f"Severity:     {incident.severity.value.upper()}",
            f"Status:       {incident.status.value.upper()}",
            f"Assigned to:  {incident.assigned_to}",
            f"Created:      {incident.created_at}",
            "",
            "AFFECTED SYSTEMS",
            "-" * 40,
        ]
        for sys in incident.affected_systems:
            lines.append(f"  - {sys}")

        lines += ["", "INDICATORS OF COMPROMISE (IOCs)", "-" * 40]
        if incident.iocs:
            for ioc in incident.iocs:
                lines.append(f"  [{ioc.get('type', 'unknown')}] {ioc.get('value', '')}")
        else:
            lines.append("  None recorded")

        lines += ["", "TIMELINE", "-" * 40]
        for entry in incident.timeline:
            lines.append(f"  {entry['timestamp'][:19]}  [{entry['actor']}] {entry['action']}")
            if entry.get("notes"):
                lines.append(f"    Notes: {entry['notes']}")

        if dwell:
            lines += ["", "METRICS", "-" * 40]
            lines.append(f"  Time to contain: {dwell['time_to_contain_human']}")
            lines.append(f"  Time to resolve: {dwell['time_to_resolve_human']}")

        if playbook:
            lines += ["", "PLAYBOOK", "-" * 40]
            lines.append(f"  {playbook.name}")
            for step in playbook.steps:
                lines.append(f"  [{step['order']}] {step['title']} ({step['responsible']})")

        lines += ["", "=" * 70]
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _format_duration(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.0f}s"
    elif seconds < 3600:
        return f"{seconds/60:.1f}m"
    elif seconds < 86400:
        return f"{seconds/3600:.1f}h"
    else:
        return f"{seconds/86400:.1f}d"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    import sys
    db = IncidentResponseDB()
    args = sys.argv[1:]

    if not args:
        print("BlackRoad Incident Response")
        print("Usage: python incident_response.py <command> [args]")
        print()
        print("Commands:")
        print("  create <type> <severity> <system1,...>    - Create incident")
        print("  list [status]                             - List incidents")
        print("  get <id>                                  - Get incident details")
        print("  update-status <id> <status>               - Update incident status")
        print("  add-ioc <id> <ioc_value> [type]           - Add IOC to incident")
        print("  assign <id> <assignee>                    - Assign incident")
        print("  contain <id>                              - Mark incident contained")
        print("  resolve <id>                              - Mark incident resolved")
        print("  timeline <id> <action> <actor>            - Add timeline entry")
        print("  report <id>                               - Generate incident report")
        print("  dwell <id>                                - Show dwell time metrics")
        print("  playbooks                                 - List available playbooks")
        print("  stats                                     - Incident statistics")
        print("  demo                                      - Load demo incidents")
        return

    cmd = args[0]

    if cmd == "create":
        if len(args) < 4:
            print("Usage: create <type> <severity> <system1,...>"); return
        systems = args[3].split(",") if args[3] else []
        title = args[4] if len(args) > 4 else ""
        incident = db.create_incident(args[1], args[2], systems, title=title)
        print(f"✓ Incident created: {incident.id}")
        print(f"  Title:    {incident.title}")
        print(f"  Type:     {incident.type.value}")
        print(f"  Severity: {incident.severity.value}")
        print(f"  Playbook: {incident.playbook_id or 'none'}")

    elif cmd == "list":
        status = args[1] if len(args) > 1 else None
        incidents = db.list_incidents(status)
        label = f" (status={status})" if status else ""
        print(f"Incidents{label}: {len(incidents)}")
        for inc in incidents:
            print(f"  [{inc.severity.value.upper()}][{inc.status.value}] {inc.id[:8]} {inc.title}")
            print(f"    Type: {inc.type.value}  Assigned: {inc.assigned_to}  Systems: {len(inc.affected_systems)}")

    elif cmd == "get":
        if len(args) < 2:
            print("Usage: get <id>"); return
        inc = db.get_incident(args[1])
        if not inc:
            print(f"✗ Incident {args[1]} not found"); return
        print(f"Incident: {inc.id}")
        print(f"  Title:    {inc.title}")
        print(f"  Type:     {inc.type.value}")
        print(f"  Severity: {inc.severity.value}")
        print(f"  Status:   {inc.status.value}")
        print(f"  Assigned: {inc.assigned_to}")
        print(f"  Systems:  {', '.join(inc.affected_systems)}")
        print(f"  IOCs:     {len(inc.iocs)}")
        print(f"  Timeline: {len(inc.timeline)} entries")

    elif cmd == "update-status":
        if len(args) < 3:
            print("Usage: update-status <id> <status>"); return
        inc = db.update_status(args[1], args[2])
        print(f"✓ Status updated: {inc.status.value}" if inc else "✗ Incident not found")

    elif cmd == "add-ioc":
        if len(args) < 3:
            print("Usage: add-ioc <id> <ioc_value> [type]"); return
        ioc_type = args[3] if len(args) > 3 else "unknown"
        db.add_ioc(args[1], args[2], ioc_type)
        print(f"✓ IOC added to {args[1]}")

    elif cmd == "assign":
        if len(args) < 3:
            print("Usage: assign <id> <assignee>"); return
        db.assign_to(args[1], args[2])
        print(f"✓ Incident {args[1]} assigned to {args[2]}")

    elif cmd == "contain":
        if len(args) < 2:
            print("Usage: contain <id>"); return
        inc = db.mark_contained(args[1])
        print(f"✓ Incident marked contained: {inc.id}" if inc else "✗ Not found")

    elif cmd == "resolve":
        if len(args) < 2:
            print("Usage: resolve <id>"); return
        inc = db.mark_resolved(args[1])
        print(f"✓ Incident resolved: {inc.id}" if inc else "✗ Not found")

    elif cmd == "timeline":
        if len(args) < 4:
            print("Usage: timeline <id> <action> <actor>"); return
        notes = args[4] if len(args) > 4 else ""
        db.add_timeline_entry(args[1], args[2], args[3], notes)
        print(f"✓ Timeline entry added to {args[1]}")

    elif cmd == "report":
        if len(args) < 2:
            print("Usage: report <id>"); return
        print(db.generate_report(args[1]))

    elif cmd == "dwell":
        if len(args) < 2:
            print("Usage: dwell <id>"); return
        dwell = db.calculate_dwell_time(args[1])
        if not dwell:
            print("✗ Incident not found"); return
        print(f"Dwell time for {args[1]}:")
        print(f"  Time to contain: {dwell['time_to_contain_human']}")
        print(f"  Time to resolve: {dwell['time_to_resolve_human']}")

    elif cmd == "playbooks":
        playbooks = db.list_playbooks()
        print(f"Available playbooks: {len(playbooks)}")
        for pb in playbooks:
            print(f"  [{pb.incident_type.value}] {pb.name}")
            print(f"    {pb.description}")
            print(f"    Steps: {len(pb.steps)}  Contacts: {', '.join(pb.contacts[:3])}")

    elif cmd == "stats":
        s = db.stats()
        print("Incident Response Stats:")
        print(f"  Total incidents: {s['total']}")
        print(f"  Open critical:   {s['open_critical']}")
        print(f"  By status: {s['by_status']}")
        print(f"  By type: {s['by_type']}")
        print(f"  By severity: {s['by_severity']}")

    elif cmd == "demo":
        import time
        incidents_data = [
            ("ransomware", "critical",
             ["file-server-01", "file-server-02", "backup-server"],
             "Ryuk ransomware detected on file servers"),
            ("phishing", "high",
             ["workstation-MARKETING-01", "workstation-MARKETING-03"],
             "Phishing campaign targeting marketing team"),
            ("breach", "critical",
             ["customer-db-01", "api-gateway"],
             "Suspected customer data exfiltration"),
            ("ddos", "medium",
             ["web-frontend-01", "web-frontend-02", "load-balancer"],
             "DDoS attack on public website"),
            ("insider", "high",
             ["file-server-01", "dev-workstation-JOHN"],
             "Suspicious data access by departing employee"),
        ]
        created_ids = []
        for itype, sev, systems, title in incidents_data:
            inc = db.create_incident(itype, sev, systems, title=title)
            created_ids.append(inc.id)
            print(f"  Created: [{sev.upper()}] {title[:50]}")

        # Simulate some activity
        db.assign_to(created_ids[0], "IR-Team-Alpha")
        db.add_ioc(created_ids[0], "185.220.101.45", "ip")
        db.add_ioc(created_ids[0], "d41d8cd98f00b204e9800998ecf8427e", "md5")
        db.add_timeline_entry(created_ids[0], "Affected systems isolated from network", "IT-Admin")
        db.mark_contained(created_ids[0])
        db.add_timeline_entry(created_ids[1], "Phishing email pulled from 47 inboxes", "IT-Admin")
        db.update_status(created_ids[3], "contained")
        db.mark_resolved(created_ids[3])

        s = db.stats()
        print(f"\n✓ Demo: {s['total']} incidents created")
        print(f"  By severity: {s['by_severity']}")
        print(f"  Open critical: {s['open_critical']}")
    else:
        print(f"Unknown command: {cmd}")


if __name__ == "__main__":
    main()
