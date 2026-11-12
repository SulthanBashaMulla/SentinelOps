import json
from datetime import datetime, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
ALERT_FILE = PROJECT_ROOT / "reports" / "alerts.json"

SEVERITY_RANK = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


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
        alert.get("first_event") or alert.get("first_failure")
    )
    enriched["last_seen"] = (
        alert.get("last_event") or alert.get("successful_login")
    )
    enriched["last_updated"] = datetime.now(timezone.utc).isoformat()

    return enriched


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


def get_evidence_key(item):
    """Create a key identifying one log evidence record."""

    return item.get("line_number"), item.get("event")


def generate_unique_alert_id(base_id, existing_alerts):
    """Generate an alert ID that does not already exist."""

    existing_ids = {
        alert.get("alert_id") for alert in existing_alerts
    }

    if base_id not in existing_ids:
        return base_id

    suffix = 2

    while f"{base_id}-{suffix}" in existing_ids:
        suffix += 1

    return f"{base_id}-{suffix}"


def merge_alerts(existing_alerts, new_alerts):
    """Merge alerts while preserving resolved incidents."""

    merged = [enrich_alert(alert) for alert in existing_alerts]

    for incoming in new_alerts:
        new_alert = enrich_alert(incoming)

        same_incidents = [
            alert for alert in merged
            if alert.get("detection") == new_alert.get("detection")
            and alert.get("source_ip") == new_alert.get("source_ip")
        ]

        # Prefer merging into an existing open incident.
        matching_open = next(
            (
                alert for alert in same_incidents
                if alert.get("status", "open") == "open"
            ),
            None,
        )

        incoming_evidence = new_alert.get("evidence", [])

        if matching_open is not None:
            existing_evidence = matching_open.setdefault("evidence", [])

            known_events = {
                get_evidence_key(item)
                for item in existing_evidence
            }

            for item in incoming_evidence:
                event_key = get_evidence_key(item)

                if event_key not in known_events:
                    existing_evidence.append(item)
                    known_events.add(event_key)

            matching_open["occurrence_count"] = len(existing_evidence)
            matching_open["last_seen"] = new_alert.get("last_seen")
            matching_open["last_updated"] = datetime.now(
                timezone.utc
            ).isoformat()

            if SEVERITY_RANK.get(
                new_alert.get("severity"), 0
            ) > SEVERITY_RANK.get(
                matching_open.get("severity"), 0
            ):
                matching_open["severity"] = new_alert["severity"]

            continue

        # Collect evidence already stored in previous incidents.
        historical_evidence = {
            get_evidence_key(item)
            for alert in same_incidents
            for item in alert.get("evidence", [])
        }

        # Keep only evidence that has never been processed.
        fresh_evidence = [
            item for item in incoming_evidence
            if get_evidence_key(item) not in historical_evidence
        ]

        # Identical evidence must not recreate a resolved incident.
        if not fresh_evidence:
            continue

        new_alert["evidence"] = fresh_evidence
        new_alert["occurrence_count"] = len(fresh_evidence)

        new_alert["alert_id"] = generate_unique_alert_id(
            new_alert.get("alert_id", "SENTINELOPS-ALERT"),
            merged,
        )

        merged.append(new_alert)

    return merged


def save_alerts(alerts):
    """Save alerts to persistent JSON storage."""

    ALERT_FILE.parent.mkdir(parents=True, exist_ok=True)

    temporary_file = ALERT_FILE.with_suffix(".tmp")

    with temporary_file.open("w", encoding="utf-8") as file:
        json.dump(alerts, file, indent=4)

    temporary_file.replace(ALERT_FILE)
