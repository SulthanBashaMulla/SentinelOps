
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
ALERT_FILE = PROJECT_ROOT / "reports" / "alerts.json"


SEVERITY_RANK = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}

SEVERITY_POINTS = {
    "LOW": 10,
    "MEDIUM": 25,
    "HIGH": 40,
    "CRITICAL": 55,
}

CORRELATION_WINDOW_MINUTES = 15
CORRELATION_WINDOW = timedelta(
    minutes=CORRELATION_WINDOW_MINUTES
)


def parse_alert_timestamp(value):
    """Parse an ISO 8601 timestamp into UTC."""

    if not value:
        return None

    try:
        timestamp = datetime.fromisoformat(value)

        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)

        return timestamp.astimezone(timezone.utc)

    except (ValueError, TypeError):
        return None


def is_within_correlation_window(existing_alert, new_alert):
    """Check whether two alerts belong to the same time window."""

    existing_time = parse_alert_timestamp(
        existing_alert.get("last_seen")
    )

    incoming_time = parse_alert_timestamp(
        new_alert.get("first_seen")
    )

    if existing_time is None or incoming_time is None:
        return False

    time_difference = incoming_time - existing_time

    return timedelta(0) <= time_difference <= CORRELATION_WINDOW


def get_risk_level(score):
    """Convert a numeric risk score into a risk category."""

    if score >= 75:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    return "LOW"


def calculate_risk_score(alert):
    """Calculate a transparent heuristic risk score from 0 to 100."""

    severity = str(alert.get("severity", "LOW")).upper()
    severity_points = SEVERITY_POINTS.get(severity, 0)

    try:
        failed_attempts = max(
            0,
            int(alert.get("failed_attempts", 0) or 0),
        )
    except (ValueError, TypeError):
        failed_attempts = 0

    failed_attempt_points = min(
        failed_attempts * 2,
        20,
    )

    successful_login_detected = bool(
        alert.get("successful_login")
        or alert.get("successful_login_line")
    )

    successful_login_points = (
        20 if successful_login_detected else 0
    )

    evidence_count = len(alert.get("evidence", []))

    evidence_points = min(evidence_count, 5)

    total = (
        severity_points
        + failed_attempt_points
        + successful_login_points
        + evidence_points
    )

    return min(total, 100), {
        "severity_points": severity_points,
        "failed_attempt_points": failed_attempt_points,
        "successful_login_points": successful_login_points,
        "evidence_points": evidence_points,
    }


def apply_risk_score(alert):
    """Attach the current risk score and explanation to an alert."""

    score, factors = calculate_risk_score(alert)

    alert["risk_score"] = score
    alert["risk_level"] = get_risk_level(score)
    alert["risk_factors"] = factors

    return alert


def prioritize_alerts(alerts):
    """Return alerts ranked from highest to lowest risk."""

    scored_alerts = [
        apply_risk_score(enrich_alert(alert))
        for alert in alerts
    ]

    return sorted(
        scored_alerts,
        key=lambda alert: alert["risk_score"],
        reverse=True,
    )


def enrich_alert(alert):
    """Add investigation, triage and risk information."""

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

    enriched["last_updated"] = datetime.now(
        timezone.utc
    ).isoformat()

    enriched.setdefault(
        "occurrence_count",
        len(enriched.get("evidence", [])),
    )

    return apply_risk_score(enriched)


def load_alerts():
    """Load previously stored alerts."""

    if not ALERT_FILE.exists():
        return []

    try:
        with ALERT_FILE.open(
            "r",
            encoding="utf-8",
        ) as file:
            alerts = json.load(file)

        if isinstance(alerts, list):
            return alerts

        raise ValueError(
            "Alert report must contain a JSON list."
        )

    except json.JSONDecodeError as error:
        raise ValueError(
            f"Alert report contains invalid JSON: {error}"
        ) from error


def get_evidence_key(item):
    """Create a stable SHA-256 fingerprint for a log event."""

    existing_fingerprint = item.get("fingerprint")

    if existing_fingerprint:
        return existing_fingerprint

    event = item.get("event", "")
    normalized_event = " ".join(event.split())

    return hashlib.sha256(
        normalized_event.encode("utf-8")
    ).hexdigest()


def add_evidence_fingerprints(evidence):
    """Add SHA-256 fingerprints to evidence records."""

    for item in evidence:
        item["fingerprint"] = get_evidence_key(item)

    return evidence


def generate_unique_alert_id(base_id, existing_alerts):
    """Generate an alert ID that does not already exist."""

    existing_ids = {
        alert.get("alert_id")
        for alert in existing_alerts
    }

    if base_id not in existing_ids:
        return base_id

    suffix = 2

    while f"{base_id}-{suffix}" in existing_ids:
        suffix += 1

    return f"{base_id}-{suffix}"


def merge_alerts(existing_alerts, new_alerts):
    """Merge alerts while preserving incident history."""

    merged = [
        enrich_alert(alert)
        for alert in existing_alerts
    ]

    for alert in merged:
        add_evidence_fingerprints(
            alert.get("evidence", [])
        )

    for incoming in new_alerts:
        new_alert = enrich_alert(incoming)

        same_incidents = [
            alert
            for alert in merged
            if (
                alert.get("detection")
                == new_alert.get("detection")
                and alert.get("source_ip")
                == new_alert.get("source_ip")
            )
        ]

        eligible_open = [
            alert
            for alert in same_incidents
            if (
                alert.get("status", "open") == "open"
                and is_within_correlation_window(
                    alert,
                    new_alert,
                )
            )
        ]

        matching_open = max(
            eligible_open,
            key=lambda alert: parse_alert_timestamp(
                alert.get("last_seen")
            ),
            default=None,
        )

        incoming_evidence = new_alert.get(
            "evidence",
            [],
        )

        add_evidence_fingerprints(
            incoming_evidence
        )

        if matching_open is not None:
            existing_evidence = matching_open.setdefault(
                "evidence",
                [],
            )

            add_evidence_fingerprints(
                existing_evidence
            )

            known_events = {
                get_evidence_key(item)
                for item in existing_evidence
            }

            for item in incoming_evidence:
                event_key = get_evidence_key(item)

                if event_key not in known_events:
                    existing_evidence.append(item)
                    known_events.add(event_key)

            matching_open["occurrence_count"] = (
                len(existing_evidence)
            )

            old_last_seen = parse_alert_timestamp(
                matching_open.get("last_seen")
            )

            new_last_seen = parse_alert_timestamp(
                new_alert.get("last_seen")
            )

            if (
                new_last_seen is not None
                and (
                    old_last_seen is None
                    or new_last_seen > old_last_seen
                )
            ):
                matching_open["last_seen"] = (
                    new_alert.get("last_seen")
                )

            matching_open["last_updated"] = datetime.now(
                timezone.utc
            ).isoformat()

            if SEVERITY_RANK.get(
                new_alert.get("severity"),
                0,
            ) > SEVERITY_RANK.get(
                matching_open.get("severity"),
                0,
            ):
                matching_open["severity"] = (
                    new_alert["severity"]
                )

            # Recalculate after evidence and severity changes.
            apply_risk_score(matching_open)

            continue

        historical_evidence = {
            get_evidence_key(item)
            for alert in same_incidents
            for item in alert.get("evidence", [])
        }

        fresh_evidence = [
            item
            for item in incoming_evidence
            if get_evidence_key(item)
            not in historical_evidence
        ]

        if not fresh_evidence:
            continue

        new_alert["evidence"] = fresh_evidence

        new_alert["occurrence_count"] = (
            len(fresh_evidence)
        )

        new_alert["alert_id"] = generate_unique_alert_id(
            new_alert.get(
                "alert_id",
                "SENTINELOPS-ALERT",
            ),
            merged,
        )

        # Score the new incident using only its fresh evidence.
        apply_risk_score(new_alert)

        merged.append(new_alert)

    return prioritize_alerts(merged)


def save_alerts(alerts):
    """Save alerts to persistent JSON storage atomically."""

    ALERT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    temporary_file = ALERT_FILE.with_suffix(".tmp")

    with temporary_file.open(
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            alerts,
            file,
            indent=4,
        )

    temporary_file.replace(ALERT_FILE)
