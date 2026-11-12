from pathlib import Path

from detect_bruteforce import (
    parse_failed_events,
    parse_auth_events,
    detect_bruteforce,
    detect_bruteforce_success,
)

from alert_manager import (
    load_alerts,
    merge_alerts,
    save_alerts,
)


PROJECT_ROOT = Path(__file__).resolve().parent.parent
LOG_FILE = PROJECT_ROOT / "sample-logs" / "authentication.log"


def main():

    with LOG_FILE.open("r", encoding="utf-8") as file:
        log_lines = file.readlines()

    # Detection 1: Repeated failed SSH logins
    failed_events = parse_failed_events(log_lines)
    brute_force_alerts = detect_bruteforce(failed_events)

    # Detection 2: Successful login following repeated failures
    auth_events = parse_auth_events(log_lines)
    success_alerts = detect_bruteforce_success(auth_events)

    # Combine newly detected alerts
    new_alerts = brute_force_alerts + success_alerts

    # Load, enrich, merge and persist alert history
    existing_alerts = load_alerts()
    all_alerts = merge_alerts(existing_alerts, new_alerts)
    save_alerts(all_alerts)

    print("\n========== SENTINELOPS DETECTION REPORT ==========\n")

    if new_alerts:
        print(f"New detections: {len(new_alerts)}")
    else:
        print("[INFO] No new detections")

    for alert in all_alerts:
        print(f"[{alert['severity']}] {alert['detection']}")
        print(f"Alert ID: {alert['alert_id']}")
        print(f"Source IP: {alert['source_ip']}")
        print(f"Status: {alert['status']}")
        print(f"Evidence Count: {len(alert.get('evidence', []))}")
        print(f"Occurrence Count: {alert.get('occurrence_count', 0)}")
        print("-" * 50)

    print(f"\nTotal Stored Alerts: {len(all_alerts)}")
    print(f"Alerts saved to: {PROJECT_ROOT / 'reports' / 'alerts.json'}")
    print("\n========== SCAN COMPLETED ==========\n")


if __name__ == "__main__":
    main()
