
import re
import ipaddress
from datetime import datetime, timedelta, timezone
from collections import defaultdict, deque


# Detection configuration
THRESHOLD = 3
TIME_WINDOW = timedelta(minutes=5)
LAB_YEAR = 2026


# Match failed and successful SSH authentication events
LOG_PATTERN = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
    r".*sshd\[\d+\]: "
    r"(?P<status>Failed password|Accepted password)"
    r".*from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})\b"
)


def parse_auth_events(log_lines):
    """Parse successful and failed SSH authentication events."""

    auth_events = defaultdict(list)

    for line_number, line in enumerate(log_lines, start=1):

        match = LOG_PATTERN.search(line)

        if not match:
            continue

        try:
            timestamp_text = f"{LAB_YEAR} {match.group('timestamp')}"

            timestamp = datetime.strptime(
                timestamp_text,
                "%Y %b %d %H:%M:%S"
            ).replace(tzinfo=timezone.utc)

            source_ip = str(
                ipaddress.ip_address(match.group("ip"))
            )

        except ValueError:
            continue

        status = (
            "failed"
            if match.group("status") == "Failed password"
            else "success"
        )

        auth_events[source_ip].append(
            {
                "timestamp": timestamp,
                "status": status,
                "line_number": line_number,
                "raw_event": line.strip(),
            }
        )

    return auth_events


def parse_failed_events(log_lines):
    """Extract only failed authentication events."""

    auth_events = parse_auth_events(log_lines)

    failed_events = defaultdict(list)

    for source_ip, events in auth_events.items():

        failed_events[source_ip] = [
            event
            for event in events
            if event["status"] == "failed"
        ]

    return failed_events


def detect_bruteforce(failed_events):
    """Detect repeated failed SSH authentication attempts."""

    alerts = []

    for source_ip, events in failed_events.items():

        events.sort(key=lambda event: event["timestamp"])

        recent_events = deque()
        maximum_window = []

        for event in events:

            recent_events.append(event)

            while (
                recent_events
                and event["timestamp"]
                - recent_events[0]["timestamp"]
                > TIME_WINDOW
            ):
                recent_events.popleft()

            if len(recent_events) > len(maximum_window):
                maximum_window = list(recent_events)

        if len(maximum_window) >= THRESHOLD:

            alerts.append(
                {
                    "alert_id": (
                        f"SENTINELOPS-BRUTEFORCE-"
                        f"{source_ip.replace('.', '-')}"
                    ),
                    "severity": "HIGH",
                    "detection": (
                        "Possible SSH Brute-Force Activity"
                    ),
                    "source_ip": source_ip,
                    "failed_attempts": len(maximum_window),
                    "time_window_seconds": int(
                        TIME_WINDOW.total_seconds()
                    ),
                    "first_event": maximum_window[0][
                        "timestamp"
                    ].isoformat(),
                    "last_event": maximum_window[-1][
                        "timestamp"
                    ].isoformat(),
                    "mitre_attack": {
                        "tactic": "Credential Access",
                        "technique_id": "T1110",
                        "technique": "Brute Force",
                    },
                    "evidence": [
                        {
                            "line_number": event["line_number"],
                            "event": event["raw_event"],
                        }
                        for event in maximum_window
                    ],
                }
            )

    return alerts


def detect_bruteforce_success(auth_events):
    """Detect successful SSH login following repeated failures."""

    alerts = []

    for source_ip, events in auth_events.items():

        events.sort(key=lambda event: event["timestamp"])

        recent_failures = deque()

        for event in events:

            # Remove failures older than the five-minute window.
            while (
                recent_failures
                and event["timestamp"]
                - recent_failures[0]["timestamp"]
                > TIME_WINDOW
            ):
                recent_failures.popleft()

            if event["status"] == "failed":

                recent_failures.append(event)

            elif event["status"] == "success":

                if len(recent_failures) >= THRESHOLD:

                    alerts.append(
                        {
                            "alert_id": (
                                f"SENTINELOPS-BRUTEFORCE-SUCCESS-"
                                f"{source_ip.replace('.', '-')}-"
                                f"{event['line_number']}"
                            ),
                            "severity": "CRITICAL",
                            "detection": (
                                "Possible SSH Brute-Force "
                                "Followed by Successful Login"
                            ),
                            "source_ip": source_ip,
                            "failed_attempts": len(recent_failures),
                            "successful_login_line": (
                                event["line_number"]
                            ),
                            "first_failure": (
                                recent_failures[0]["timestamp"].isoformat()
                            ),
                            "successful_login": (
                                event["timestamp"].isoformat()
                            ),
                            "mitre_attack": {
                                "tactic": "Credential Access",
                                "technique_id": "T1110",
                                "technique": "Brute Force",
                            },
                            "evidence": [
                                {
                                    "line_number": item["line_number"],
                                    "status": item["status"],
                                    "event": item["raw_event"],
                                }
                                for item in list(recent_failures) + [event]
                            ],
                        }
                    )

                # Do not reuse previous failures for another success alert.
                recent_failures.clear()

    return alerts
