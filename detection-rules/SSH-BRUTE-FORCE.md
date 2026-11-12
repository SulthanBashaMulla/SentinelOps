
# SSH Brute-Force Detection Rule

## Rule Information

- **Rule ID:** SENTINELOPS-SSH-001
- **Rule Name:** SSH Brute-Force Detection
- **Severity:** High
- **Log Source:** Linux SSH authentication logs
- **Detection Type:** Threshold-based, time-window detection
- **MITRE ATT&CK Tactic:** Credential Access
- **MITRE ATT&CK Technique:** T1110 — Brute Force

## Objective

Identify a source IP address generating three or more failed SSH
authentication attempts within a five-minute time window.

## Detection Logic

1. Read SSH authentication log entries.
2. Identify entries containing `Failed password`.
3. Extract and validate the timestamp and source IP address.
4. Group failed authentication events by source IP.
5. Sort events chronologically.
6. Evaluate each IP using a five-minute sliding window.
7. Generate a HIGH severity alert when the threshold is reached.
8. Preserve the matching events as alert evidence.

## Detection Threshold

- **Threshold:** 3 failed attempts
- **Time Window:** 5 minutes (300 seconds)
- **Alert Condition:** 3 or more failures from one source IP within the window.

## Test Scenarios

### Scenario 1 — Rapid Failed Logins

Four failed attempts from `192.168.1.50` within five minutes.

Expected result: HIGH severity alert.

### Scenario 2 — Distributed Over Time

Three failed attempts from `192.168.1.80`, separated by ten minutes.

Expected result: No brute-force alert.

## Alert Evidence

The generated JSON alert contains:

- Alert ID
- Severity
- Source IP
- Failed attempt count
- Time window
- First and last event timestamps
- MITRE ATT&CK mapping
- Original log evidence and line numbers

## Limitations

- Currently supports IPv4 source addresses.
- Uses a fixed lab year of 2026 for timestamps without a year.
- Detects failed-password events only.
- Threshold-based detection can produce false positives.
- Does not yet correlate events across multiple hosts.
- An alert indicates suspicious activity, not confirmed compromise.

## Future Improvements

- Support IPv6.
- Support year-aware and timezone-aware log parsing.
- Add configurable thresholds.
- Add additional SSH detection rules.
- Integrate with Wazuh or another SIEM.
- Add alert enrichment and incident investigation workflows.
