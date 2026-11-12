# SentinelOps

### Python-Based Security Monitoring and Threat Detection Lab

SentinelOps is a Python-based Security Operations Center (SOC) monitoring lab that analyzes SSH authentication logs, identifies suspicious login patterns, and generates structured, enriched security alerts.

The project demonstrates core SOC workflows, including log analysis, threat detection, alert enrichment, incident correlation, deduplication, investigation tracking, and persistent alert storage.

## Features

* SSH authentication log parsing.
* Detection of repeated failed SSH login attempts.
* Detection of successful SSH login following repeated failures.
* Configurable detection threshold and time window.
* HIGH and CRITICAL severity alerts.
* MITRE ATT&CK technique mapping.
* Evidence-rich JSON alert reports.
* Alert enrichment with investigation status and recommendations.
* Persistent alert history using JSON storage.
* Duplicate incident merging and evidence deduplication.
* Severity escalation when an incident becomes more serious.
* Alert lifecycle management.
* Timestamped investigation notes.
* Lifecycle transition history.
* Command-line alert management.
* Atomic JSON report updates.
* Automated unit testing.

## Architecture

```text
Synthetic SSH Authentication Logs
              |
              v
     Authentication Parser
              |
              v
       Detection Engine
          /       \
         v         v
  Brute-Force   Failed Attempts
   Detection    + Successful Login
          \       /
           v     v
        Alert Generation
              |
              v
        Alert Enrichment
              |
              v
      Incident Deduplication
              |
              v
      Persistent JSON Storage
              |
              v
       Alert Lifecycle Manager
              |
       +------+------+
       |      |      |
       v      v      v
      List   Show   Update
                     |
              +------+------+
              |             |
              v             v
          Change Status  Add Notes
              |
              v
       Investigation History
```

## Detection Rules

### 1. SSH Brute-Force Detection

* Detects at least 3 failed SSH password attempts from the same source IP.
* Uses a rolling 5-minute time window.
* Generates a HIGH severity alert.
* MITRE ATT&CK: T1110 – Brute Force.

### 2. Brute-Force Followed by Successful Login

* Detects at least 3 failed SSH password attempts followed by a successful login.
* Requires the events to originate from the same source IP.
* Requires the failures to fall within the 5-minute window before the successful login.
* Generates a CRITICAL severity alert.
* MITRE ATT&CK: T1110 – Brute Force.

**Note:** This is a suspicious indicator, not definitive proof of account compromise.

## Alert Management

SentinelOps enriches generated alerts with:

* Investigation status (`open` by default).
* Alert category.
* Recommended investigation actions.
* First-seen and last-seen timestamps.
* Last-updated timestamp.
* Evidence and occurrence counts.

### Incident Deduplication and Re-Correlation

- Correlates open alerts using detection name and source IP.
- Preserves the original alert ID when matching open incidents are merged.
- Prevents duplicate evidence from being added.
- Ignores previously processed evidence associated with resolved incidents.
- Creates a separate incident with a unique alert ID when genuinely new evidence appears after resolution.
- Preserves the original resolved incident and its investigation history.
- Preserves existing investigation status.
- Supports severity escalation, such as HIGH to CRITICAL.
- Stores alert history between program executions.

**Current correlation limitation:** Distinct incidents with the same detection name and source IP may be merged while an existing incident remains open. Evidence identity currently uses log line number and event text, so log rotation or reordering can affect deduplication accuracy.

### Alert Lifecycle Management

SentinelOps supports a structured incident investigation workflow:

```text
       OPEN
         |
         v
   INVESTIGATING
         |
         v
     RESOLVED
```

Supported transitions:

* `open` → `investigating`
* `investigating` → `resolved`

A resolved alert is terminal in the current implementation. Invalid transitions, repeated status changes, and unsupported statuses are rejected.

### Investigation Notes and History

Each alert can maintain:

* Timestamped status transition history.
* Analyst investigation notes.
* Current investigation status.
* Last-updated timestamp.

Lifecycle information is stored alongside the alert in persistent JSON storage.

## Command-Line Alert Management

SentinelOps includes a command-line interface for managing stored alerts.

### List all alerts

```bash
python3 scripts/manage_alerts.py list
```

### View a specific alert

```bash
python3 scripts/manage_alerts.py show ALERT_ID
```

### Start investigating an alert

```bash
python3 scripts/manage_alerts.py status ALERT_ID investigating
```

### Resolve an alert

```bash
python3 scripts/manage_alerts.py status ALERT_ID resolved
```

### Add an investigation note

```bash
python3 scripts/manage_alerts.py note ALERT_ID "Reviewed SSH authentication evidence."
```

Replace `ALERT_ID` with the actual ID displayed by the list command.

### View available commands

```bash
python3 scripts/manage_alerts.py --help
```

## Project Structure

```text
SentinelOps/
├── detection-rules/
│   └── SSH-BRUTE-FORCE.md
├── sample-logs/
│   ├── authentication.log
│   └── bruteforce-success.log
├── scripts/
│   ├── alert_manager.py
│   ├── alert_lifecycle.py
│   ├── detect_bruteforce.py
│   ├── manage_alerts.py
│   └── run_detection.py
├── tests/
│   ├── test_alert_lifecycle.py
│   ├── test_alert_manager.py
│   └── test_bruteforce.py
├── reports/
│   └── alerts.json
├── .gitignore
└── README.md
```

Generated reports and local backup files are excluded from version control.

## Technologies

* Python
* Regular Expressions
* IP Address Validation
* Linux / Ubuntu
* JSON
* Python unittest
* MITRE ATT&CK Framework
* Git and GitHub

## Setup and Execution

Clone the repository:

```bash
git clone https://github.com/SulthanBashaMulla/SentinelOps.git
cd SentinelOps
```

Run the detection engine:

```bash
python3 scripts/run_detection.py
```

The generated and enriched alerts are saved to:

```text
reports/alerts.json
```

Alert history is preserved across executions. Reprocessing identical sample logs does not duplicate matching evidence for an existing open incident.

## Run Automated Tests

Run the complete test suite:

```bash
python3 -m unittest discover -s tests -v
```

The current test suite contains **28 automated tests**.

**Detection tests**

* Rapid failed login detection.
* Failed attempts outside the time window.
* Successful login following repeated failures.
* Successful login after fewer than 3 failures.
* Successful login from a different IP.
* Successful login outside the five-minute window.

**Alert management tests**

* New alert enrichment.
* Preservation of investigation status.
* Duplicate evidence prevention.
* Separate incidents for different source IPs.
* Original alert ID preservation.
* Severity escalation.

**Alert lifecycle tests**

* Alert lookup by ID.
* Lifecycle field initialization.
* Valid status transitions.
* Rejection of invalid statuses.
* Rejection of invalid transitions.
* Prevention of reopening resolved alerts.
* Timestamped investigation notes.
* Rejection of empty notes.
* Collection-level status and note operations.
* Handling of unknown alert IDs.

## Current Limitations

* Events are correlated by source IP rather than username.
* Only matching SSH password authentication events are analyzed.
* Yearless syslog timestamps use a configured lab year.
* Incident correlation can merge separate incidents from the same source IP.
* Evidence deduplication relies on line number and event text.
* JSON storage is intended for this educational lab, not concurrent production SIEM workloads.
* The project currently uses synthetic logs rather than a live SIEM data source.

## Future Improvements

* Username-aware event correlation.
* Stronger event fingerprinting.
* IP reputation and threat intelligence integration.
* Detection of suspicious login locations.
* Dashboard for security alert visualization.
* Integration with live log collection.
* Database-backed incident storage.

## Disclaimer

SentinelOps is an educational security monitoring project. It uses synthetic lab logs and is intended for authorized security testing and learning.
