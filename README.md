# SentinelOps

### Python-Based Security Monitoring and Threat Detection Lab

SentinelOps is a Python-based Security Operations Center (SOC) monitoring lab that analyzes SSH authentication logs, identifies suspicious login patterns, and generates structured, enriched security alerts.

The project demonstrates core SOC workflows, including log analysis, threat detection, alert enrichment, incident correlation, evidence deduplication, risk-based prioritization, investigation tracking, and persistent alert storage.

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
* SHA-256 evidence fingerprinting.
* Time-based incident correlation using a 15-minute window.
* Severity escalation when an incident becomes more serious.
* Risk scoring using a deterministic 0–100 scoring model.
* Risk-level classification and alert prioritization.
* Risk-based CLI filtering and sorting.
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
     Evidence Fingerprinting
              |
              v
      Incident Correlation
              |
              v
      Incident Deduplication
              |
              v
        Risk Scoring
              |
              v
     Alert Prioritization
              |
              v
      Persistent JSON Storage
              |
              v
       Alert Management CLI
              |
       +------+------+
       |      |      |
       v      v      v
      List   Show   Update
       |
       v
 Risk-Based Filtering
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
* Risk score, risk level, and risk factors.

### Incident Deduplication and Re-Correlation

* Correlates open alerts using detection name and source IP.
* Preserves the original alert ID when matching open incidents are merged.
* Prevents duplicate evidence from being added.
* Ignores previously processed evidence associated with resolved incidents.
* Creates a separate incident with a unique alert ID when genuinely new evidence appears after resolution.
* Preserves the original resolved incident and its investigation history.
* Preserves existing investigation status.
* Supports severity escalation, such as HIGH to CRITICAL.
* Stores alert history between program executions.
* Uses SHA-256 fingerprints of normalized log event text to identify duplicate evidence independently of line numbers.

**Time-based correlation:** Open incidents are correlated using detection name, source IP, and a 15-minute correlation window. New activity within the window is merged into the existing incident. Activity outside the window creates a separate incident with a unique alert ID, preserving previous incident history.

### Evidence Fingerprinting

SentinelOps uses SHA-256 hashing to generate fingerprints from normalized log event text.

* Identical normalized events produce the same fingerprint.
* Duplicate evidence can be identified independently of log line numbers.
* Evidence fingerprints help prevent repeated events from being stored multiple times.

SHA-256 is used here for evidence identification and deduplication, not encryption.

## Risk Scoring and Alert Prioritization

SentinelOps assigns every alert a deterministic risk score between **0 and 100**.

The score is calculated using severity, failed authentication attempts, successful login indicators, and evidence count.

### Risk Scoring Model

| Risk Factor | Scoring |
|---|---:|
| LOW severity | 10 points |
| MEDIUM severity | 25 points |
| HIGH severity | 40 points |
| CRITICAL severity | 55 points |
| Each failed authentication attempt | +2 points |
| Failed-attempt contribution limit | +20 points |
| Successful login after repeated failures | +20 points |
| Each evidence record | +1 point |
| Evidence contribution limit | +5 points |
| Maximum total score | 100 points |

### Risk Classification

| Risk Score | Risk Level |
|---|---|
| 0–24 | LOW |
| 25–49 | MEDIUM |
| 50–74 | HIGH |
| 75–100 | CRITICAL |

The risk score is recalculated when alerts are enriched or merged. Alerts are prioritized in descending order of risk score.

**Example:** A HIGH severity alert with 3 failed attempts and 1 evidence record receives:

`40 + 6 + 1 = 47`

Its resulting risk level is MEDIUM.

**Note:** These scoring weights are transparent educational heuristics. They are not calibrated probabilities of compromise or a substitute for analyst judgment.

## Alert Lifecycle Management

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

SentinelOps includes a command-line interface for managing and prioritizing stored alerts.

### List all alerts

```bash
python3 scripts/manage_alerts.py list
```

Alerts are displayed in descending risk-score order.

### Filter alerts by risk level

```bash
python3 scripts/manage_alerts.py list --risk HIGH
```

Available risk levels:

* `LOW`
* `MEDIUM`
* `HIGH`
* `CRITICAL`

### Filter alerts by minimum risk score

```bash
python3 scripts/manage_alerts.py list --min-score 60
```

### Combine risk-level and score filters

```bash
python3 scripts/manage_alerts.py list --risk HIGH --min-score 60
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

### View available commands

```bash
python3 scripts/manage_alerts.py --help
```

Replace `ALERT_ID` with the actual ID displayed by the list command.

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
│   ├── test_bruteforce.py
│   └── test_manage_alerts.py
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
* SHA-256 Hashing
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

Alert history is preserved across executions. Reprocessing identical sample logs does not duplicate matching evidence for an existing incident.

## Run Automated Tests

Run the complete test suite:

```bash
python3 -m unittest discover -s tests -v
```

The current test suite contains **54 automated tests**, all passing in the latest verified run.

### Detection Tests

* Rapid failed login detection.
* Failed attempts outside the time window.
* Successful login following repeated failures.
* Successful login after fewer than 3 failures.
* Successful login from a different IP.
* Successful login outside the five-minute window.

### Alert Management Tests

* New alert enrichment.
* Preservation of investigation status.
* Duplicate evidence prevention.
* Separate incidents for different source IPs.
* Original alert ID preservation.
* Severity escalation.
* SHA-256 evidence fingerprinting.
* Time-based incident correlation.
* Risk-score calculation and classification.
* Risk-score recalculation after alert merging.
* Alert prioritization.

### Alert Lifecycle Tests

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

### CLI Tests

* Filtering alerts by risk level.
* Filtering alerts by minimum risk score.
* Sorting alerts by risk score.
* Accepting valid risk-score input.
* Rejecting negative risk scores.
* Rejecting non-numeric risk scores.
* Rejecting scores above 100.

## Current Limitations

* Events are correlated by source IP rather than username.
* Only matching SSH password authentication events are analyzed.
* Yearless syslog timestamps use a configured lab year.
* Incident correlation uses a fixed 15-minute window and detection name/source IP matching.
* Evidence fingerprinting detects identical normalized event text; changes to actual event content can produce different fingerprints.
* Risk scoring uses fixed heuristic weights and is not calibrated against real-world incident outcomes.
* JSON storage is intended for this educational lab, not concurrent production SIEM workloads.
* The project currently uses synthetic logs rather than a live SIEM data source.

## Future Improvements

* Username-aware event correlation.
* Configurable incident correlation windows.
* IP reputation and threat intelligence integration.
* Detection of suspicious login locations.
* Dashboard for security alert visualization.
* Integration with live log collection.
* Database-backed incident storage.
* Configurable risk-scoring weights.

## Disclaimer

SentinelOps is an educational security monitoring project. It uses synthetic lab logs and is intended for authorized security testing and learning.
