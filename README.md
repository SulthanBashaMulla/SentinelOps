
# SentinelOps 🛡️

### A Hands-On Security Operations and Threat Detection Lab

SentinelOps is a Python-based security monitoring project that analyses Linux SSH authentication logs, detects suspicious login activity, and generates structured security alerts with supporting evidence.

The project is being developed as a practical Security Operations Centre (SOC) and DevSecOps learning environment.

## Current Features

- Parses Linux SSH authentication log entries.
- Extracts and validates IPv4 source addresses.
- Detects repeated failed SSH login attempts.
- Uses a five-minute sliding-window detection algorithm.
- Generates HIGH-severity brute-force alerts.
- Maps the detection to MITRE ATT&CK T1110.
- Preserves original log evidence in JSON alerts.
- Includes automated unit tests for detection scenarios.

## Architecture

```text
Synthetic SSH Authentication Logs
              |
              v
       Log Parser (Python)
              |
              v
    Timestamp and IP Validation
              |
              v
      Failed Event Grouping
              |
              v
   Five-Minute Sliding Window
              |
              v
    Brute-Force Detection
              |
              v
     MITRE ATT&CK Mapping
              |
              v
       JSON Security Alerts
              |
              v
       Evidence for Analysis
```

## Technology Stack

| Technology | Purpose |
|---|---|
| Ubuntu Linux | Development environment |
| Python 3 | Log parsing and detection |
| Regular Expressions | Log pattern matching |
| JSON | Structured security alerts |
| Git | Version control |
| unittest | Automated testing |
| MITRE ATT&CK | Detection technique mapping |

## Project Structure

```text
SentinelOps/
├── detection-rules/
│   └── SSH-BRUTE-FORCE.md
├── docs/
├── reports/
├── sample-logs/
│   └── authentication.log
├── screenshots/
├── scripts/
│   ├── detect_bruteforce.py
│   └── run_detection.py
├── tests/
│   └── test_bruteforce.py
├── .gitignore
└── README.md
```

## Detection Rule: SSH Brute Force

**Rule ID:** SENTINELOPS-SSH-001

**Detection condition:**
Three or more failed SSH password attempts from the same source IP within five minutes.

**Severity:** HIGH

**MITRE ATT&CK:** T1110 — Brute Force

See [SSH Brute-Force Detection Rule](detection-rules/SSH-BRUTE-FORCE.md) for the detection logic, test scenarios, evidence fields, and limitations.

## Getting Started

### Requirements

- Python 3
- Git
- Linux, Ubuntu, or WSL2

### Clone the repository

```bash
git clone https://github.com/SulthanBashaMulla/SentinelOps.git
cd SentinelOps
```

### Run the detection engine

```bash
python3 scripts/run_detection.py
```

### View generated alerts

```bash
cat reports/alerts.json
```

### Run automated tests

```bash
python3 -m unittest discover -s tests -v
```

## Test Scenarios

| Scenario | Expected Result |
|---|---|
| Four failed attempts within five minutes | HIGH alert |
| Three failed attempts separated by ten minutes | No alert |

Both scenarios have passed the current automated tests.

## Sample Alert

The detection engine generates JSON alerts containing:

- Alert ID
- Detection name
- Severity
- Source IP address
- Failed attempt count
- Detection time window
- First and last event timestamps
- MITRE ATT&CK mapping
- Original log evidence

Generated alert files are excluded from Git because they are runtime output.

## Current Limitations

- Supports IPv4 source addresses only.
- Uses a fixed lab year for yearless timestamps.
- Detects failed-password events only.
- Uses a fixed threshold and time window.
- Does not yet correlate activity across multiple hosts.
- Alerts require analyst investigation and do not prove compromise.

## Roadmap

- [x] Linux development environment
- [x] Project architecture and Git setup
- [x] SSH authentication log parsing
- [x] Brute-force detection
- [x] Five-minute sliding-window analysis
- [x] Structured JSON alerts
- [x] MITRE ATT&CK mapping
- [x] Initial automated unit tests
- [x] Detection rule documentation
- [ ] Additional detection rules
- [ ] More comprehensive automated tests
- [ ] Wazuh SIEM integration
- [ ] Security monitoring dashboard
- [ ] Incident investigation workflow

## Disclaimer

SentinelOps is an educational security engineering project. Its detection logic is tested using synthetic authentication logs. Only use security monitoring and testing techniques on systems you own or are explicitly authorised to assess.

## Author

**Sulthan Basha Mulla**

- GitHub: [SulthanBashaMulla](https://github.com/SulthanBashaMulla)
- LinkedIn: [Sulthan Basha Mulla](https://www.linkedin.com/in/sulthanbashamulla/)
