from datetime import datetime, timezone


def enrich_alert(alert):
    """Add investigation and triage information to an alert."""

    enriched = alert.copy()

    enriched.setdefault("status", "open")

    enriched["category"] = "Authentication"

    enriched["recommendation"] = (
        "Review authentication evidence, verify whether the source IP "
        "is authorized, and investigate affected accounts. Consider "
        "blocking the source IP only after validating the activity."
    )

    enriched["first_seen"] = (
        alert.get("first_event")
        or alert.get("first_failure")
    )

    enriched["last_seen"] = (
        alert.get("last_event")
        or alert.get("successful_login")
    )

    enriched["last_updated"] = datetime.now(
        timezone.utc
    ).isoformat()

    return enriched

import json
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
ALERT_FILE = PROJECT_ROOT / "reports" / "alerts.json"


def load_alerts():
    """Load previously stored alerts."""

    if not ALERT_FILE.exists():
        return []

    try:
        with ALERT_FILE.open("r", encoding="utf-8") as file:
            alerts = json.load(file)

        if isinstance(alerts, list):
            return alerts

        raise ValueError("Alert report must contain a JSON list.")

    except json.JSONDecodeError as error:
        raise ValueError(
            f"Alert report contains invalid JSON: {error}"
        ) from error
def merge_alerts(existing_alerts, new_alerts):
    """Merge new alerts without duplicating existing evidence."""

    merged = [enrich_alert(alert) for alert in existing_alerts]

    for new_alert in new_alerts:

        new_alert = enrich_alert(new_alert)

        matching_alert = next(
            (
                alert for alert in merged
                if alert.get("detection") == new_alert.get("detection")
                and alert.get("source_ip") == new_alert.get("source_ip")
                and alert.get("status", "open") == "open"
            ),
            None
        )

        if matching_alert is None:
            new_alert["occurrence_count"] = len(
                new_alert.get("evidence", [])
            )
            merged.append(new_alert)
            continue

        # Preserve the original investigation status and alert ID.
        matching_alert["last_seen"] = new_alert.get("last_seen")
        matching_alert["last_updated"] = datetime.now(
            timezone.utc
        ).isoformat()

        existing_evidence = matching_alert.setdefault("evidence", [])
        known_events = {
            (item.get("line_number"), item.get("event"))
            for item in existing_evidence
        }

        for item in new_alert.get("evidence", []):
            event_key = (item.get("line_number"), item.get("event"))

            if event_key not in known_events:
                existing_evidence.append(item)
                known_events.add(event_key)

        matching_alert["occurrence_count"] = len(existing_evidence)

        # Retain the highest severity if the incident escalates.
        severity_rank = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

        if severity_rank.get(new_alert.get("severity"), 0) > severity_rank.get(
            matching_alert.get("severity"), 0
        ):
            matching_alert["severity"] = new_alert["severity"]

    return merged
def save_alerts(alerts):
    """Save alerts to persistent JSON storage."""

    ALERT_FILE.parent.mkdir(parents=True, exist_ok=True)

    temporary_file = ALERT_FILE.with_suffix(".tmp")

    with temporary_file.open("w", encoding="utf-8") as file:
        json.dump(alerts, file, indent=4)

    temporary_file.replace(ALERT_FILE)
