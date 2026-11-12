# SentinelOps
### Python-Based Security Monitoring and Threat Detection Lab

SentinelOps is a Python-based Security Operations Center (SOC) monitoring lab that analyzes SSH authentication logs, identifies suspicious login patterns, and generates structured security alerts.

## Features

- SSH authentication log parsing.
- Detection of repeated failed SSH login attempts.
- Detection of successful SSH login following repeated failures.
- Configurable detection threshold and time window.
- HIGH and CRITICAL severity alerts.
- MITRE ATT&CK technique mapping.
- Evidence-rich JSON alert reports.
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
        JSON Alert Report
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

## Project Structure

```text
SentinelOps/
├── detection-rules/
│   └── SSH-BRUTE-FORCE.md
├── sample-logs/
│   ├── authentication.log
│   └── bruteforce-success.log
├── scripts/
│   ├── detect_bruteforce.py
│   └── run_detection.py
├── tests/
│   └── test_bruteforce.py
├── .gitignore
└── README.md
```

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

The generated alerts are saved to:

```text
reports/alerts.json
```

## Run Automated Tests

```bash
python3 -m unittest discover -s tests -v
```

The test suite covers:

- Rapid failed login detection.
- Failed attempts outside the time window.
- Successful login following repeated failures.
- Successful login after fewer than 3 failures.
- Successful login from a different IP.
- Successful login outside the five-minute window.

## Current Limitations

- Events are correlated by source IP rather than username.
- Only matching SSH password authentication events are analyzed.
- Yearless syslog timestamps use a configured lab year.
- The project currently uses synthetic logs rather than a live SIEM data source.

## Future Improvements

- Username-aware event correlation.
- IP reputation and threat intelligence integration.
- Detection of suspicious login locations.
- Alert deduplication and enrichment.
- Dashboard for security alert visualization.
- Integration with live log collection.

## Disclaimer

SentinelOps is an educational security monitoring project. It uses synthetic lab logs and is intended for authorized security testing and learning.
