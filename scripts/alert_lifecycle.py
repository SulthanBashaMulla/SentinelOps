from datetime import datetime, timezone


VALID_STATUSES = {
    "open",
    "investigating",
    "resolved",
}


ALLOWED_TRANSITIONS = {
    "open": {
        "investigating",
    },
    "investigating": {
        "resolved",
    },
    "resolved": set(),
}


def get_alert_by_id(alerts, alert_id):
    """Return an alert matching the supplied alert ID."""

    for alert in alerts:
        if alert.get("alert_id") == alert_id:
            return alert

    return None


def initialize_lifecycle(alert):
    """Ensure an alert contains lifecycle tracking fields."""

    alert.setdefault("status", "open")
    alert.setdefault("lifecycle_history", [])
    alert.setdefault("notes", [])

    return alert


def change_alert_status(alert, new_status):
    """Change an alert status when the transition is allowed."""

    initialize_lifecycle(alert)

    if new_status not in VALID_STATUSES:
        raise ValueError(
            f"Invalid alert status: {new_status}"
        )

    current_status = alert["status"]

    if new_status == current_status:
        raise ValueError(
            f"Alert is already in '{current_status}' status."
        )

    if new_status not in ALLOWED_TRANSITIONS[current_status]:
        raise ValueError(
            f"Invalid status transition: "
            f"{current_status} -> {new_status}"
        )

    timestamp = datetime.now(timezone.utc).isoformat()

    alert["status"] = new_status

    alert["lifecycle_history"].append(
        {
            "from_status": current_status,
            "to_status": new_status,
            "changed_at": timestamp,
        }
    )

    alert["last_updated"] = timestamp

    return alert


def add_alert_note(alert, note):
    """Add an investigation note to an alert."""

    initialize_lifecycle(alert)

    if not isinstance(note, str) or not note.strip():
        raise ValueError(
            "Alert note must be a non-empty string."
        )

    timestamp = datetime.now(timezone.utc).isoformat()

    alert["notes"].append(
        {
            "note": note.strip(),
            "created_at": timestamp,
        }
    )

    alert["last_updated"] = timestamp

    return alert
def update_alert_status(alerts, alert_id, new_status):
    """Find an alert and update its lifecycle status."""

    alert = get_alert_by_id(alerts, alert_id)

    if alert is None:
        raise ValueError(
            f"Alert not found: {alert_id}"
        )

    change_alert_status(alert, new_status)

    return alert


def add_note_to_alert(alerts, alert_id, note):
    """Find an alert and add an investigation note."""

    alert = get_alert_by_id(alerts, alert_id)

    if alert is None:
        raise ValueError(
            f"Alert not found: {alert_id}"
        )

    add_alert_note(alert, note)

    return alert
