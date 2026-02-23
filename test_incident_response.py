"""Tests for BlackRoad Incident Response."""
import pytest
from incident_response import (
    IncidentResponseDB, Incident, Playbook, IncidentType, Severity, IncidentStatus
)


@pytest.fixture
def db(tmp_path):
    return IncidentResponseDB(db_path=str(tmp_path / "ir_test.db"))


def test_create_incident(db):
    inc = db.create_incident("ransomware", "critical", ["server-01", "server-02"])
    assert inc.type == IncidentType.RANSOMWARE
    assert inc.severity == Severity.CRITICAL
    assert inc.status == IncidentStatus.OPEN
    assert "server-01" in inc.affected_systems


def test_create_incident_invalid_type(db):
    with pytest.raises(ValueError, match="Unknown incident type"):
        db.create_incident("alien-attack", "high", ["host"])


def test_create_incident_invalid_severity(db):
    with pytest.raises(ValueError, match="Unknown severity"):
        db.create_incident("phishing", "super-critical", ["host"])


def test_create_incident_assigns_playbook(db):
    inc = db.create_incident("ransomware", "critical", ["host"])
    assert inc.playbook_id is not None


def test_create_incident_phishing(db):
    inc = db.create_incident("phishing", "high", ["ws-01"])
    assert inc.type == IncidentType.PHISHING
    assert inc.playbook_id is not None


def test_get_incident(db):
    inc = db.create_incident("breach", "critical", ["db-01"])
    fetched = db.get_incident(inc.id)
    assert fetched is not None
    assert fetched.id == inc.id


def test_get_incident_not_found(db):
    assert db.get_incident("nonexistent-id") is None


def test_list_incidents_empty(db):
    assert db.list_incidents() == []


def test_list_incidents(db):
    db.create_incident("ddos", "medium", ["lb-01"])
    db.create_incident("phishing", "high", ["ws-01"])
    incs = db.list_incidents()
    assert len(incs) == 2


def test_list_incidents_by_status(db):
    db.create_incident("ddos", "medium", ["lb-01"])
    db.create_incident("phishing", "high", ["ws-01"])
    open_incs = db.list_incidents("open")
    assert len(open_incs) == 2


def test_update_status(db):
    inc = db.create_incident("insider", "high", ["laptop"])
    updated = db.update_status(inc.id, "investigating")
    assert updated.status == IncidentStatus.INVESTIGATING


def test_update_status_invalid(db):
    inc = db.create_incident("breach", "high", ["db"])
    with pytest.raises(ValueError):
        db.update_status(inc.id, "flying-saucers")


def test_add_timeline_entry(db):
    inc = db.create_incident("phishing", "medium", ["ws"])
    initial_count = len(inc.timeline)
    updated = db.add_timeline_entry(inc.id, "Phishing email isolated", "IT-Admin")
    assert len(updated.timeline) == initial_count + 1
    assert updated.timeline[-1]["action"] == "Phishing email isolated"


def test_add_timeline_to_nonexistent(db):
    result = db.add_timeline_entry("bad-id", "action", "actor")
    assert result is None


def test_add_ioc(db):
    inc = db.create_incident("breach", "critical", ["db-01"])
    updated = db.add_ioc(inc.id, "185.220.101.45", "ip")
    assert len(updated.iocs) == 1
    assert updated.iocs[0]["value"] == "185.220.101.45"


def test_add_multiple_iocs(db):
    inc = db.create_incident("ransomware", "critical", ["server"])
    db.add_ioc(inc.id, "1.2.3.4", "ip")
    db.add_ioc(inc.id, "evil.com", "domain")
    db.add_ioc(inc.id, "deadbeef", "md5")
    updated = db.get_incident(inc.id)
    assert len(updated.iocs) == 3


def test_assign_to(db):
    inc = db.create_incident("ddos", "medium", ["lb"])
    db.assign_to(inc.id, "alice@company.com")
    updated = db.get_incident(inc.id)
    assert updated.assigned_to == "alice@company.com"


def test_mark_contained(db):
    inc = db.create_incident("ransomware", "critical", ["server"])
    contained = db.mark_contained(inc.id)
    assert contained.status == IncidentStatus.CONTAINED
    assert contained.contained_at is not None


def test_mark_resolved(db):
    inc = db.create_incident("phishing", "high", ["ws"])
    resolved = db.mark_resolved(inc.id)
    assert resolved.status == IncidentStatus.CLOSED
    assert resolved.resolved_at is not None


def test_calculate_dwell_time_open(db):
    inc = db.create_incident("breach", "critical", ["db"])
    dwell = db.calculate_dwell_time(inc.id)
    assert dwell is not None
    assert dwell["time_to_contain_seconds"] is None
    assert "Not yet contained" in dwell["time_to_contain_human"]


def test_calculate_dwell_time_contained(db):
    inc = db.create_incident("ddos", "medium", ["lb"])
    db.mark_contained(inc.id)
    dwell = db.calculate_dwell_time(inc.id)
    assert dwell["time_to_contain_seconds"] is not None
    assert dwell["time_to_contain_seconds"] >= 0


def test_calculate_dwell_time_resolved(db):
    inc = db.create_incident("phishing", "low", ["ws"])
    db.mark_contained(inc.id)
    db.mark_resolved(inc.id)
    dwell = db.calculate_dwell_time(inc.id)
    assert dwell["time_to_resolve_seconds"] is not None
    assert dwell["time_to_resolve_seconds"] >= 0


def test_calculate_dwell_time_nonexistent(db):
    result = db.calculate_dwell_time("bad-id")
    assert result is None


def test_list_playbooks(db):
    playbooks = db.list_playbooks()
    assert len(playbooks) >= 4  # ransomware, phishing, breach, ddos


def test_ransomware_playbook_steps(db):
    playbooks = db.list_playbooks()
    ransomware_pbs = [p for p in playbooks if p.incident_type == IncidentType.RANSOMWARE]
    assert len(ransomware_pbs) >= 1
    pb = ransomware_pbs[0]
    assert len(pb.steps) >= 6
    assert len(pb.contacts) >= 3


def test_generate_report(db):
    inc = db.create_incident("ransomware", "critical", ["server-01"])
    db.add_ioc(inc.id, "1.2.3.4", "ip")
    db.add_timeline_entry(inc.id, "Systems isolated", "IT-Admin")
    report = db.generate_report(inc.id)
    assert "INCIDENT REPORT" in report
    assert inc.id in report
    assert "ransomware" in report.lower()
    assert "1.2.3.4" in report


def test_generate_report_nonexistent(db):
    result = db.generate_report("bad-id")
    assert "not found" in result


def test_stats_empty(db):
    s = db.stats()
    assert s["total"] == 0
    assert s["open_critical"] == 0


def test_stats(db):
    db.create_incident("ransomware", "critical", ["s1"])
    db.create_incident("phishing", "high", ["s2"])
    db.create_incident("ddos", "medium", ["s3"])
    s = db.stats()
    assert s["total"] == 3
    assert s["open_critical"] == 1
    assert "ransomware" in s["by_type"]


def test_incident_to_dict(db):
    inc = db.create_incident("breach", "high", ["db"])
    d = inc.to_dict()
    assert d["type"] == "breach"
    assert d["severity"] == "high"
    assert isinstance(d["affected_systems"], list)


def test_all_incident_types(db):
    for itype in ["ransomware", "phishing", "breach", "ddos", "insider", "supply_chain"]:
        inc = db.create_incident(itype, "high", ["host"])
        assert inc.type.value == itype
