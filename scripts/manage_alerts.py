import argparse
import json

from alert_manager import load_alerts, save_alerts
from alert_lifecycle import (
    get_alert_by_id,
    update_alert_status,
    add_note_to_alert,
)


def list_alerts(alerts):
    """Display all stored alerts."""

    if not alerts:
        print("No alerts found.")
        return

    for alert in alerts:
        print("-" * 55)
        print("Alert ID:", alert.get("alert_id"))
        print("Severity:", alert.get("severity"))
        print("Detection:", alert.get("detection"))
        print("Source IP:", alert.get("source_ip"))
        print("Status:", alert.get("status", "open"))
        print("Evidence:", len(alert.get("evidence", [])))

    print("-" * 55)
    print("Total alerts:", len(alerts))


def show_alert(alert):
    """Display detailed information about an alert."""

    print(json.dumps(alert, indent=4))


def main():
    parser = argparse.ArgumentParser(
        description="SentinelOps Alert Lifecycle Manager"
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    subparsers.add_parser("list", help="List all stored alerts")

    show_parser = subparsers.add_parser(
        "show",
        help="Show details of an alert",
    )
    show_parser.add_argument("alert_id")

    status_parser = subparsers.add_parser(
        "status",
        help="Change alert status",
    )
    status_parser.add_argument("alert_id")
    status_parser.add_argument(
        "new_status",
        choices=["investigating", "resolved"],
    )

    note_parser = subparsers.add_parser(
        "note",
        help="Add an investigation note",
    )
    note_parser.add_argument("alert_id")
    note_parser.add_argument("note")

    args = parser.parse_args()

    alerts = load_alerts()

    try:
        if args.command == "list":
            list_alerts(alerts)
            return

        if args.command == "show":
            alert = get_alert_by_id(alerts, args.alert_id)

            if alert is None:
                raise ValueError(
                    f"Alert not found: {args.alert_id}"
                )

            show_alert(alert)
            return

        if args.command == "status":
            alert = update_alert_status(
                alerts,
                args.alert_id,
                args.new_status,
            )

            save_alerts(alerts)

            print("Alert status updated successfully.")
            print("Alert ID:", alert["alert_id"])
            print("New status:", alert["status"])
            return

        if args.command == "note":
            alert = add_note_to_alert(
                alerts,
                args.alert_id,
                args.note,
            )

            save_alerts(alerts)

            print("Investigation note added successfully.")
            print("Alert ID:", alert["alert_id"])
            print("Total notes:", len(alert["notes"]))

    except ValueError as error:
        parser.exit(1, f"Error: {error}\n")


if __name__ == "__main__":
    main()
