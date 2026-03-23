# blackroad-incident-response

> Security incident response playbooks and tracking

Part of the [BlackRoad OS](https://blackroad.io) ecosystem — [BlackRoad-Security](https://github.com/BlackRoad-Security)

---

# blackroad-incident-response

> Security incident response playbooks and tracking — BlackRoad Security

[![CI](https://github.com/BlackRoad-Security/blackroad-incident-response/actions/workflows/ci.yml/badge.svg)](https://github.com/BlackRoad-Security/blackroad-incident-response/actions/workflows/ci.yml)

End-to-end incident lifecycle management: create incidents, auto-assign playbooks, track timelines, record IOCs, measure dwell time, and generate reports.

## Features

- 🚨 **Incident Types**: ransomware, phishing, breach, DDoS, insider, supply chain
- 📋 **Auto-Assigned Playbooks**: Best-practice response steps auto-matched to incident type
- ⏱ **Timeline Tracking**: Append-only chronological action log per incident
- 🔍 **IOC Management**: Associate IOCs with incidents
- 📊 **Dwell Time Metrics**: Time-to-contain, time-to-resolve
- 📄 **Report Generation**: Formatted incident reports with full timeline
- 💾 **SQLite**: Self-contained, zero-config

## Quick Start

```bash
# Load demo incidents
python incident_response.py demo

# Create a ransomware incident
python incident_response.py create ransomware critical "file-server-01,file-server-02"

# List all incidents
python incident_response.py list

# Assign incident to analyst
python incident_response.py assign <id> alice@company.com

# Add IOC
python incident_response.py add-ioc <id> "185.220.101.45" ip

# Add timeline entry
python incident_response.py timeline <id> "Systems isolated from network" "IT-Admin"

# Mark as contained
python incident_response.py contain <id>

# Generate report
python incident_response.py report <id>

# Measure dwell time
python incident_response.py dwell <id>

# List available playbooks
python incident_response.py playbooks

# View stats
python incident_response.py stats
```

## Incident Types

| Type | Playbook Steps | Key Contacts |
|------|---------------|--------------|
| `ransomware` | 8 steps: isolate → scope → notify → preserve → restore | CISO, Legal, IT, FBI |
| `phishing` | 6 steps: pull email → identify victims → reset creds | CISO, HR, Legal |
| `breach` | 6 steps: confirm → contain → notify regulators | Privacy Officer, Legal |
| `ddos` | 5 steps: detect → CDN protection → scrubbing | NOC, ISP, CDN |
| `insider` | Custom steps | HR, Legal, CISO |
| `supply_chain` | Custom steps | CISO, Procurement |

## API

```python
from incident_response import IncidentResponseDB

db = IncidentResponseDB("incidents.db")

# Create incident
inc = db.create_incident("ransomware", "critical",
                          ["server-01", "server-02"],
                          title="Ryuk ransomware detected")

# Add timeline
db.add_timeline_entry(inc.id, "Systems isolated", "IT-Admin")

# Add IOC
db.add_ioc(inc.id, "185.220.101.45", "ip")

# Mark contained
db.mark_contained(inc.id)

# Measure dwell time
dwell = db.calculate_dwell_time(inc.id)
print(f"Time to contain: {dwell['time_to_contain_human']}")

# Generate report
print(db.generate_report(inc.id))
```

## Running Tests

```bash
pip install pytest
pytest test_incident_response.py -v
```
