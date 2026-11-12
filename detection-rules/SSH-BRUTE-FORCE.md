
# SSH Brute-Force Detection

## Rule 1: Repeated Failed SSH Authentication

**Rule ID:** SENTINELOPS-SSH-001
**Severity:** HIGH
**MITRE ATT&CK:** T1110 – Brute Force

### Description
Detects repeated failed SSH password authentication attempts originating from the same source IP address.

### Detection Logic
- Monitors failed SSH password authentication events.
- Groups events by source IP address.
- Triggers an alert when at least 3 failed attempts occur within 5 minutes.

### Alert Evidence
- Source IP address
- Number of failed attempts
- First and last event timestamps
- Original log entries and line numbers

---

## Rule 2: Brute-Force Attempts Followed by Successful Login

**Rule ID:** SENTINELOPS-SSH-002
**Severity:** CRITICAL
**MITRE ATT&CK:** T1110 – Brute Force

### Description
Detects a successful SSH password login following at least 3 failed authentication attempts from the same source IP address within a 5-minute window.

### Detection Logic
- Monitors failed and successful SSH password authentication events.
- Groups events by source IP address.
- Maintains a rolling 5-minute window of failed attempts.
- Removes expired failures before evaluating each event.
- Triggers an alert when a successful login follows at least 3 qualifying failures.

### Alert Evidence
- Source IP address
- Number of qualifying failed attempts
- Successful login line number
- First failure and successful login timestamps
- Original failed and successful log entries

### Important Interpretation
This pattern is a suspicious indicator that deserves investigation. It does not independently prove account compromise.

---

## Detection Limitations

- Events are correlated by source IP, not username.
- Different usernames from the same IP may be counted together.
- Only matching SSH password authentication events are processed.
- The current lab parser assigns the configured lab year to yearless syslog timestamps.
- The current implementation uses synthetic authentication logs for testing.

## Threshold Configuration

| Setting | Value |
|---|---|
| Failed attempt threshold | 3 |
| Detection time window | 5 minutes |
| Repeated failures severity | HIGH |
| Failures followed by success severity | CRITICAL |
