
# SentinelOps
### Python-Based Security Monitoring and Threat Detection Lab

SentinelOps is a Python-based Security Operations Center (SOC) monitoring lab that analyzes SSH authentication logs, identifies suspicious login patterns, and generates structured, enriched security alerts.

The project demonstrates core SOC workflows, including log analysis, threat detection, alert enrichment, incident correlation, deduplication, and persistent alert storage.

## Features

- SSH authentication log parsing.
- Detection of repeated failed SSH login attempts.
- Detection of successful SSH login following repeated failures.
- Configurable detection threshold and time window.
- HIGH and CRITICAL severity alerts.
- MITRE ATT&CK technique mapping.
- Evidence-rich JSON alert reports.
- Alert enrichment with investigation status and recommendations.
- Persistent alert history using JSON storage.
- Duplicate incident merging and evidence deduplication.
- Severity escalation when an incident becomes more serious.
- Atomic JSON report updates.
- Automated unit testing.

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
       Security Alert History
```

## Detection Rules

### 1. SSH Brute-Force Detection

- Detects at least 3 failed SSH password attempts from the same source IP.
- Uses a rolling 5-minute time window.
- Generates a HIGH severity alert.
- MITRE ATT&CK: T1110 – Brute Force.

### 2. Brute-Force Followed by Successful Login

- Detects at least 3 failed SSH password attempts followed by a successful login.
- Requires the events to originate from the same source IP.
- Requires the failures to fall within the 5-minute window before the successful login.
- Generates a CRITICAL severity alert.
- MITRE ATT&CK: T1110 – Brute Force.

**Note:** This is a suspicious indicator, not definitive proof of account compromise.

## Alert Management

SentinelOps enriches generated alerts with:

- Investigation status (`open` by default).
- Alert category.
- Recommended investigation actions.
- First-seen and last-seen timestamps.
- Last-updated timestamp.
- Evidence and occurrence counts.

### Incident Deduplication

- Correlates open alerts using detection name and source IP.
- Preserves the original alert ID when matching incidents are merged.
- Prevents duplicate evidence from being added during repeated processing of the same logs.
- Preserves an existing investigation status.
- Supports severity escalation, such as HIGH to CRITICAL.
- Stores alert history between program executions.

**Current correlation limitation:** Distinct incidents with the same detection name and source IP may be merged while the existing incident remains open. Evidence identity currently uses log line number and event text, so log rotation or reordering can affect deduplication accuracy.

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
│   ├── detect_bruteforce.py
│   └── run_detection.py
├── tests/
│   ├── test_alert_manager.py
│   └── test_bruteforce.py
├── reports/
│   └── alerts.json
├── .gitignore
└── README.md
```

Generated reports and local backup files are excluded from version control.

## Technologies

- Python
- Regular Expressions
- IP Address Validation
- Linux / Ubuntu
- JSON
- Python unittest
- MITRE ATT&CK Framework
- Git and GitHub

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

Alert history is preserved across executions. Reprocessing identical sample logs does not duplicate matching evidence.

## Run Automated Tests

Run the complete test suite:

```bash
python3 -m unittest discover -s tests -v
```

The test suite currently covers:

**Detection tests**
- Rapid failed login detection.
- Failed attempts outside the time window.
- Successful login following repeated failures.
- Successful login after fewer than 3 failures.
- Successful login from a different IP.
- Successful login outside the five-minute window.

**Alert management tests**
- New alert enrichment.
- Preservation of investigation status.
- Duplicate evidence prevention.
- Separate incidents for different source IPs.
- Original alert ID preservation.
- Severity escalation.

## Current Limitations

- Events are correlated by source IP rather than username.
- Only matching SSH password authentication events are analyzed.
- Yearless syslog timestamps use a configured lab year.
- Incident correlation can merge separate incidents from the same source IP.
- Evidence deduplication relies on line number and event text.
- JSON storage is intended for this educational lab, not concurrent production SIEM workloads.
- The project currently uses synthetic logs rather than a live SIEM data source.

## Future Improvements

- Username-aware event correlation.
- Stronger event fingerprinting.
- Incident closure and reopening workflows.
- IP reputation and threat intelligence integration.
- Detection of suspicious login locations.
- Dashboard for security alert visualization.
- Integration with live log collection.
- Database-backed incident storage.

## Disclaimer

SentinelOps is an educational security monitoring project. It uses synthetic lab logs and is intended for authorized security testing and learning.
