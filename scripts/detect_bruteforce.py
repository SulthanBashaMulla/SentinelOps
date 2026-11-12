import re
import ipaddress
from datetime import datetime, timedelta, timezone
from collections import defaultdict, deque


THRESHOLD = 3
TIME_WINDOW = timedelta(minutes=5)
LAB_YEAR = 2026


LOG_PATTERN = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
    r".*Failed password.*from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})\b"
)


def parse_failed_events(log_lines):
    """Parse failed SSH authentication events from log lines."""

    failed_events = defaultdict(list)

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

        failed_events[source_ip].append(
            {
                "timestamp": timestamp,
                "line_number": line_number,
                "raw_event": line.strip(),
            }
        )

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
                event["timestamp"]
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
