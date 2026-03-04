"""
End-to-end tests for BlackRoad Incident Response.

These tests exercise complete incident lifecycle workflows, CLI operations,
and cross-feature interactions to validate the system works as a whole.
"""
import json
import os
import subprocess
import sys
import pytest
from incident_response import (
    IncidentResponseDB, IncidentType, Severity, IncidentStatus
)


@pytest.fixture
def db(tmp_path):
    return IncidentResponseDB(db_path=str(tmp_path / "e2e_test.db"))


# ---------------------------------------------------------------------------
# E2E Lifecycle: Full incident from creation through resolution
# ---------------------------------------------------------------------------

class TestFullIncidentLifecycle:
    """Test a complete incident lifecycle from open to closed."""

    def test_ransomware_full_lifecycle(self, db):
        # 1. Create incident
        inc = db.create_incident(
            "ransomware", "critical",
            ["file-server-01", "file-server-02", "backup-server"],
            title="Ryuk ransomware on file servers",
            description="Encryption detected on multiple file servers at 03:00 UTC",
        )
        assert inc.status == IncidentStatus.OPEN
        assert inc.playbook_id is not None
        assert len(inc.timeline) >= 1

        # 2. Assign analyst
        inc = db.assign_to(inc.id, "IR-Team-Alpha")
        assert inc.assigned_to == "IR-Team-Alpha"

        # 3. Update status to investigating
        inc = db.update_status(inc.id, "investigating")
        assert inc.status == IncidentStatus.INVESTIGATING

        # 4. Add IOCs discovered during investigation
        db.add_ioc(inc.id, "185.220.101.45", "ip")
        db.add_ioc(inc.id, "d41d8cd98f00b204e9800998ecf8427e", "md5")
        db.add_ioc(inc.id, "ryuk-ransom@protonmail.com", "email")
        inc = db.get_incident(inc.id)
        assert len(inc.iocs) == 3

        # 5. Add timeline entries for investigation actions
        db.add_timeline_entry(inc.id, "Isolated file-server-01 from network", "IT-Admin")
        db.add_timeline_entry(inc.id, "Isolated file-server-02 from network", "IT-Admin")
        db.add_timeline_entry(inc.id, "Memory dump captured from file-server-01", "IR-Team-Alpha")
        db.add_timeline_entry(inc.id, "Identified patient zero: file-server-01", "IR-Team-Alpha",
                              notes="Initial infection via RDP brute force")

        # 6. Mark contained
        inc = db.mark_contained(inc.id)
        assert inc.status == IncidentStatus.CONTAINED
        assert inc.contained_at is not None

        # 7. Check dwell time after containment
        dwell = db.calculate_dwell_time(inc.id)
        assert dwell["time_to_contain_seconds"] is not None
        assert dwell["time_to_contain_seconds"] >= 0
        assert dwell["time_to_resolve_seconds"] is None

        # 8. More timeline for remediation
        db.add_timeline_entry(inc.id, "Wiped and reimaged file-server-01", "IT-Admin")
        db.add_timeline_entry(inc.id, "Restored data from clean backup", "IT-Admin")

        # 9. Resolve
        inc = db.mark_resolved(inc.id)
        assert inc.status == IncidentStatus.CLOSED
        assert inc.resolved_at is not None

        # 10. Check final dwell time
        dwell = db.calculate_dwell_time(inc.id)
        assert dwell["time_to_contain_seconds"] is not None
        assert dwell["time_to_resolve_seconds"] is not None
        assert dwell["time_to_resolve_seconds"] >= dwell["time_to_contain_seconds"]

        # 11. Generate report and verify it captures everything
        report = db.generate_report(inc.id)
        assert "INCIDENT REPORT" in report
        assert "Ryuk ransomware on file servers" in report
        assert "CRITICAL" in report
        assert "CLOSED" in report
        assert "IR-Team-Alpha" in report
        assert "185.220.101.45" in report
        assert "d41d8cd98f00b204e9800998ecf8427e" in report
        assert "file-server-01" in report
        assert "Isolated file-server-01" in report
        assert "PLAYBOOK" in report

        # 12. Final timeline should capture full story
        inc = db.get_incident(inc.id)
        actions = [e["action"] for e in inc.timeline]
        assert "Incident created" in actions
        assert "Playbook assigned: Ransomware Response Playbook" in actions
        assert "Isolated file-server-01 from network" in actions
        assert "Incident contained" in actions
        assert "Incident resolved and closed" in actions

    def test_phishing_full_lifecycle(self, db):
        inc = db.create_incident(
            "phishing", "high",
            ["workstation-MKT-01", "workstation-MKT-03"],
            title="Spear phishing targeting marketing",
        )
        assert inc.playbook_id is not None

        db.assign_to(inc.id, "SOC-Analyst-Bob")
        db.update_status(inc.id, "investigating")
        db.add_ioc(inc.id, "evil-login-page.com", "domain")
        db.add_ioc(inc.id, "phisher@fake-bank.com", "email")
        db.add_timeline_entry(inc.id, "Pulled phishing email from 47 inboxes", "IT-Admin")
        db.add_timeline_entry(inc.id, "3 users clicked link, credentials reset", "IT-Admin")
        db.mark_contained(inc.id)
        db.add_timeline_entry(inc.id, "Blocked evil-login-page.com at firewall", "SOC")
        inc = db.mark_resolved(inc.id)

        assert inc.status == IncidentStatus.CLOSED
        report = db.generate_report(inc.id)
        assert "evil-login-page.com" in report
        assert "Spear phishing" in report

    def test_breach_full_lifecycle(self, db):
        inc = db.create_incident(
            "breach", "critical",
            ["customer-db-01", "api-gateway"],
            title="Customer data exfiltration",
            description="Unauthorized access to customer PII via API vulnerability",
        )
        db.assign_to(inc.id, "IR-Lead-Sarah")
        db.update_status(inc.id, "investigating")
        db.add_ioc(inc.id, "203.0.113.50", "ip")
        db.add_ioc(inc.id, "/api/v1/customers/export?all=true", "url")
        db.add_timeline_entry(inc.id, "API vulnerability identified: broken auth on export endpoint", "IR-Lead-Sarah")
        db.add_timeline_entry(inc.id, "Legal notified for GDPR assessment", "CISO")
        db.mark_contained(inc.id)
        db.add_timeline_entry(inc.id, "API endpoint patched and redeployed", "DevOps")
        inc = db.mark_resolved(inc.id)

        assert inc.status == IncidentStatus.CLOSED
        dwell = db.calculate_dwell_time(inc.id)
        assert dwell["time_to_resolve_seconds"] >= 0

    def test_ddos_full_lifecycle(self, db):
        inc = db.create_incident(
            "ddos", "medium",
            ["web-frontend-01", "web-frontend-02", "load-balancer"],
            title="Volumetric DDoS on public site",
        )
        db.update_status(inc.id, "investigating")
        db.add_ioc(inc.id, "198.51.100.0/24", "ip-range")
        db.add_timeline_entry(inc.id, "Cloudflare Under Attack mode enabled", "NOC")
        db.add_timeline_entry(inc.id, "Traffic scrubbing activated", "NOC")
        db.mark_contained(inc.id)
        db.add_timeline_entry(inc.id, "Attack subsided, traffic normal", "NOC")
        inc = db.mark_resolved(inc.id)
        assert inc.status == IncidentStatus.CLOSED

    def test_insider_threat_lifecycle(self, db):
        inc = db.create_incident(
            "insider", "high",
            ["file-server-01", "dev-workstation-JOHN"],
            title="Suspicious data access by departing employee",
        )
        # Insider threats may not have a built-in playbook
        db.assign_to(inc.id, "HR-Security-Team")
        db.update_status(inc.id, "investigating")
        db.add_ioc(inc.id, "john.doe@company.com", "email")
        db.add_timeline_entry(inc.id, "USB device usage detected on workstation", "DLP-System")
        db.add_timeline_entry(inc.id, "Account disabled, badge deactivated", "HR")
        db.mark_contained(inc.id)
        inc = db.mark_resolved(inc.id)
        assert inc.status == IncidentStatus.CLOSED

    def test_supply_chain_lifecycle(self, db):
        inc = db.create_incident(
            "supply_chain", "critical",
            ["build-server-01", "artifact-repo", "prod-cluster"],
            title="Compromised dependency in CI/CD",
        )
        db.assign_to(inc.id, "DevSecOps-Team")
        db.update_status(inc.id, "investigating")
        db.add_ioc(inc.id, "malicious-lib@2.0.1", "package")
        db.add_ioc(inc.id, "abc123deadbeef", "sha256")
        db.add_timeline_entry(inc.id, "Identified compromised npm package in build", "DevSecOps")
        db.add_timeline_entry(inc.id, "Reverted to clean dependency version", "DevSecOps")
        db.mark_contained(inc.id)
        db.add_timeline_entry(inc.id, "All artifacts rebuilt from clean source", "DevSecOps")
        inc = db.mark_resolved(inc.id)
        assert inc.status == IncidentStatus.CLOSED


# ---------------------------------------------------------------------------
# E2E Multi-Incident: Concurrent incidents and stats
# ---------------------------------------------------------------------------

class TestMultiIncidentWorkflow:
    """Test managing multiple concurrent incidents."""

    def test_concurrent_incidents_stats(self, db):
        # Create a batch of incidents across types and severities
        ids = []
        for itype, sev, systems in [
            ("ransomware", "critical", ["srv-1"]),
            ("phishing", "high", ["ws-1"]),
            ("breach", "critical", ["db-1"]),
            ("ddos", "medium", ["lb-1"]),
            ("insider", "low", ["laptop-1"]),
        ]:
            inc = db.create_incident(itype, sev, systems)
            ids.append(inc.id)

        # All should be open
        stats = db.stats()
        assert stats["total"] == 5
        assert stats["open_critical"] == 2  # ransomware + breach

        # Contain the ransomware
        db.mark_contained(ids[0])
        # Resolve the DDoS
        db.mark_resolved(ids[3])

        # Verify filtered listing
        open_incs = db.list_incidents("open")
        assert len(open_incs) == 3  # phishing, breach, insider

        contained_incs = db.list_incidents("contained")
        assert len(contained_incs) == 1

        closed_incs = db.list_incidents("closed")
        assert len(closed_incs) == 1

        # Stats should reflect changes
        stats = db.stats()
        assert stats["total"] == 5
        assert stats["open_critical"] == 1  # only breach remains open+critical

    def test_multiple_iocs_across_incidents(self, db):
        inc1 = db.create_incident("ransomware", "critical", ["srv"])
        inc2 = db.create_incident("breach", "high", ["db"])

        # Add IOCs to both
        shared_ip = "10.0.0.99"
        db.add_ioc(inc1.id, shared_ip, "ip")
        db.add_ioc(inc1.id, "malware.exe", "filename")
        db.add_ioc(inc2.id, shared_ip, "ip")
        db.add_ioc(inc2.id, "stolen-data.zip", "filename")

        i1 = db.get_incident(inc1.id)
        i2 = db.get_incident(inc2.id)
        assert len(i1.iocs) == 2
        assert len(i2.iocs) == 2

        # Both reference the shared IP
        i1_ips = [ioc["value"] for ioc in i1.iocs]
        i2_ips = [ioc["value"] for ioc in i2.iocs]
        assert shared_ip in i1_ips
        assert shared_ip in i2_ips

    def test_reports_for_all_incidents(self, db):
        ids = []
        for itype in ["ransomware", "phishing", "breach", "ddos"]:
            inc = db.create_incident(itype, "high", ["system-1"])
            db.add_ioc(inc.id, f"ioc-for-{itype}", "indicator")
            db.add_timeline_entry(inc.id, f"Investigated {itype}", "analyst")
            ids.append(inc.id)

        for inc_id in ids:
            report = db.generate_report(inc_id)
            assert "INCIDENT REPORT" in report
            assert "TIMELINE" in report
            assert "INDICATORS OF COMPROMISE" in report
            assert "PLAYBOOK" in report


# ---------------------------------------------------------------------------
# E2E Playbook Integration
# ---------------------------------------------------------------------------

class TestPlaybookIntegration:
    """Test playbook auto-assignment and content."""

    def test_all_playbook_types_loaded(self, db):
        playbooks = db.list_playbooks()
        types = {pb.incident_type for pb in playbooks}
        assert IncidentType.RANSOMWARE in types
        assert IncidentType.PHISHING in types
        assert IncidentType.BREACH in types
        assert IncidentType.DDOS in types

    def test_playbook_auto_assigned_on_create(self, db):
        for itype in ["ransomware", "phishing", "breach", "ddos"]:
            inc = db.create_incident(itype, "high", ["host"])
            assert inc.playbook_id is not None
            pb = db.get_playbook(inc.playbook_id)
            assert pb is not None
            assert pb.incident_type.value == itype

    def test_playbook_in_report(self, db):
        inc = db.create_incident("ransomware", "critical", ["srv"])
        report = db.generate_report(inc.id)
        assert "Ransomware Response Playbook" in report
        assert "Isolate infected systems" in report

    def test_playbook_steps_have_required_fields(self, db):
        playbooks = db.list_playbooks()
        for pb in playbooks:
            assert len(pb.steps) > 0
            for step in pb.steps:
                assert "order" in step
                assert "title" in step
                assert "description" in step
                assert "responsible" in step
                assert "tools" in step

    def test_playbook_contacts_populated(self, db):
        playbooks = db.list_playbooks()
        for pb in playbooks:
            assert len(pb.contacts) > 0


# ---------------------------------------------------------------------------
# E2E Data Integrity
# ---------------------------------------------------------------------------

class TestDataIntegrity:
    """Test data persistence and consistency across operations."""

    def test_incident_persists_after_multiple_updates(self, db):
        inc = db.create_incident("ransomware", "critical", ["srv"],
                                 title="Persistence test")
        inc_id = inc.id

        db.assign_to(inc_id, "analyst-1")
        db.update_status(inc_id, "investigating")
        db.add_ioc(inc_id, "1.1.1.1", "ip")
        db.add_ioc(inc_id, "2.2.2.2", "ip")
        db.add_timeline_entry(inc_id, "Action 1", "actor-1")
        db.add_timeline_entry(inc_id, "Action 2", "actor-2")
        db.mark_contained(inc_id)

        # Re-fetch and verify everything stuck
        inc = db.get_incident(inc_id)
        assert inc.title == "Persistence test"
        assert inc.assigned_to == "analyst-1"
        assert inc.status == IncidentStatus.CONTAINED
        assert len(inc.iocs) == 2
        assert inc.contained_at is not None

        # Timeline should have: created + playbook assigned + status change + 2 IOC adds + 2 actions + contained
        assert len(inc.timeline) >= 8

    def test_to_dict_roundtrip(self, db):
        inc = db.create_incident("breach", "critical", ["db-1", "api-gw"],
                                 title="Serialization test")
        db.add_ioc(inc.id, "evil.com", "domain")
        inc = db.get_incident(inc.id)

        d = inc.to_dict()
        assert isinstance(d, dict)
        assert d["type"] == "breach"
        assert d["severity"] == "critical"
        assert d["status"] == "open"
        assert d["title"] == "Serialization test"
        assert len(d["affected_systems"]) == 2
        assert len(d["iocs"]) == 1
        assert isinstance(d["timeline"], list)

    def test_separate_db_instances_share_data(self, tmp_path):
        db_path = str(tmp_path / "shared.db")
        db1 = IncidentResponseDB(db_path=db_path)
        inc = db1.create_incident("phishing", "high", ["ws"])

        db2 = IncidentResponseDB(db_path=db_path)
        fetched = db2.get_incident(inc.id)
        assert fetched is not None
        assert fetched.id == inc.id
        assert fetched.type == IncidentType.PHISHING

    def test_duplicate_ioc_not_added(self, db):
        inc = db.create_incident("breach", "high", ["db"])
        db.add_ioc(inc.id, "1.2.3.4", "ip")
        db.add_ioc(inc.id, "1.2.3.4", "ip")  # duplicate
        inc = db.get_incident(inc.id)
        ip_values = [ioc["value"] for ioc in inc.iocs]
        assert ip_values.count("1.2.3.4") == 1


# ---------------------------------------------------------------------------
# E2E CLI
# ---------------------------------------------------------------------------

class TestCLI:
    """Test the CLI end-to-end via subprocess."""

    @pytest.fixture(autouse=True)
    def setup_env(self, tmp_path):
        self.db_path = str(tmp_path / "cli_test.db")
        self.script = os.path.join(os.path.dirname(__file__), "incident_response.py")
        # We'll patch DB path by running with a modified env approach
        # Since CLI uses default path, we'll cd to tmp_path
        self.cwd = str(tmp_path)

    def _run(self, *args):
        result = subprocess.run(
            [sys.executable, self.script] + list(args),
            capture_output=True, text=True, cwd=self.cwd, timeout=30,
        )
        return result

    def test_cli_no_args_shows_help(self):
        r = self._run()
        assert r.returncode == 0
        assert "BlackRoad Incident Response" in r.stdout
        assert "Commands:" in r.stdout

    def test_cli_create_and_list(self):
        r = self._run("create", "ransomware", "critical", "server-01,server-02")
        assert r.returncode == 0
        assert "Incident created" in r.stdout

        r = self._run("list")
        assert r.returncode == 0
        assert "CRITICAL" in r.stdout

    def test_cli_full_workflow(self):
        # Create
        r = self._run("create", "phishing", "high", "ws-01", "Phishing test")
        assert "Incident created" in r.stdout
        # Extract incident ID from output
        for line in r.stdout.splitlines():
            if "Incident created:" in line:
                inc_id = line.split(":")[-1].strip()
                break

        # Get
        r = self._run("get", inc_id)
        assert r.returncode == 0
        assert inc_id in r.stdout

        # Update status
        r = self._run("update-status", inc_id, "investigating")
        assert "Status updated" in r.stdout

        # Add IOC
        r = self._run("add-ioc", inc_id, "evil.com", "domain")
        assert "IOC added" in r.stdout

        # Assign
        r = self._run("assign", inc_id, "analyst-bob")
        assert "assigned to analyst-bob" in r.stdout

        # Timeline
        r = self._run("timeline", inc_id, "Investigated phishing", "analyst-bob")
        assert "Timeline entry added" in r.stdout

        # Contain
        r = self._run("contain", inc_id)
        assert "contained" in r.stdout

        # Dwell
        r = self._run("dwell", inc_id)
        assert "Time to contain" in r.stdout

        # Report
        r = self._run("report", inc_id)
        assert "INCIDENT REPORT" in r.stdout
        assert "evil.com" in r.stdout

        # Resolve
        r = self._run("resolve", inc_id)
        assert "resolved" in r.stdout

    def test_cli_playbooks(self):
        r = self._run("playbooks")
        assert r.returncode == 0
        assert "Ransomware Response Playbook" in r.stdout
        assert "Phishing Response Playbook" in r.stdout

    def test_cli_stats(self):
        self._run("create", "ransomware", "critical", "srv")
        self._run("create", "phishing", "high", "ws")
        r = self._run("stats")
        assert r.returncode == 0
        assert "Total incidents: 2" in r.stdout

    def test_cli_demo(self):
        r = self._run("demo")
        assert r.returncode == 0
        assert "Demo:" in r.stdout or "demo" in r.stdout.lower()

        r = self._run("stats")
        assert int(r.stdout.split("Total incidents:")[1].split()[0]) >= 5

    def test_cli_unknown_command(self):
        r = self._run("foobar")
        assert "Unknown command" in r.stdout

    def test_cli_list_by_status(self):
        self._run("create", "ddos", "medium", "lb")
        r = self._run("list", "open")
        assert r.returncode == 0


# ---------------------------------------------------------------------------
# E2E Edge Cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    """Test boundary conditions and error handling."""

    def test_create_with_empty_systems_list(self, db):
        inc = db.create_incident("ransomware", "low", [])
        assert inc.affected_systems == []

    def test_create_with_many_systems(self, db):
        systems = [f"server-{i:03d}" for i in range(100)]
        inc = db.create_incident("breach", "critical", systems)
        assert len(inc.affected_systems) == 100

    def test_long_title_and_description(self, db):
        title = "A" * 500
        desc = "B" * 5000
        inc = db.create_incident("phishing", "medium", ["ws"], title=title, description=desc)
        fetched = db.get_incident(inc.id)
        assert fetched.title == title
        assert fetched.description == desc

    def test_special_characters_in_ioc(self, db):
        inc = db.create_incident("breach", "high", ["db"])
        db.add_ioc(inc.id, "https://evil.com/path?q=1&x=<script>alert(1)</script>", "url")
        fetched = db.get_incident(inc.id)
        assert "<script>" in fetched.iocs[0]["value"]

    def test_unicode_in_timeline(self, db):
        inc = db.create_incident("phishing", "low", ["ws"])
        db.add_timeline_entry(inc.id, "Phishing von Angreifer erkannt", "analyst")
        fetched = db.get_incident(inc.id)
        assert any("Angreifer" in e["action"] for e in fetched.timeline)

    def test_operations_on_nonexistent_incident(self, db):
        fake_id = "00000000-0000-0000-0000-000000000000"
        assert db.get_incident(fake_id) is None
        assert db.add_timeline_entry(fake_id, "test", "test") is None
        assert db.add_ioc(fake_id, "1.2.3.4", "ip") is None
        assert db.mark_contained(fake_id) is None
        assert db.mark_resolved(fake_id) is None
        assert db.calculate_dwell_time(fake_id) is None
        assert "not found" in db.generate_report(fake_id)

    def test_case_insensitive_type_and_severity(self, db):
        inc = db.create_incident("RANSOMWARE", "CRITICAL", ["srv"])
        assert inc.type == IncidentType.RANSOMWARE
        assert inc.severity == Severity.CRITICAL

        inc2 = db.create_incident("Phishing", "High", ["ws"])
        assert inc2.type == IncidentType.PHISHING
        assert inc2.severity == Severity.HIGH

    def test_rapid_status_transitions(self, db):
        inc = db.create_incident("ddos", "medium", ["lb"])
        for status in ["investigating", "contained", "eradicated", "recovered", "closed"]:
            inc = db.update_status(inc.id, status)
            assert inc.status == IncidentStatus(status)
