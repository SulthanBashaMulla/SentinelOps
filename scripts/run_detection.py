
import json
from pathlib import Path
from datetime import datetime, timezone

from detect_bruteforce import (
    parse_failed_events,
    parse_auth_events,
    detect_bruteforce,
    detect_bruteforce_success,
)


PROJECT_ROOT = Path(__file__).resolve().parent.parent
LOG_FILE = PROJECT_ROOT / "sample-logs" / "authentication.log"
ALERT_FILE = PROJECT_ROOT / "reports" / "alerts.json"


def main():

    with LOG_FILE.open("r", encoding="utf-8") as file:
        log_lines = file.readlines()

    # Detection 1: Repeated failed SSH logins
    failed_events = parse_failed_events(log_lines)
    brute_force_alerts = detect_bruteforce(failed_events)

    # Detection 2: Successful login following repeated failures
    auth_events = parse_auth_events(log_lines)
    success_alerts = detect_bruteforce_success(auth_events)

    # Combine all alerts
    alerts = brute_force_alerts + success_alerts

    generated_at = datetime.now(timezone.utc).isoformat()

    for alert in alerts:
        alert["generated_at"] = generated_at

    ALERT_FILE.parent.mkdir(parents=True, exist_ok=True)

    with ALERT_FILE.open("w", encoding="utf-8") as file:
        json.dump(alerts, file, indent=4)

    print("\n========== SENTINELOPS DETECTION REPORT ==========\n")

    if alerts:
        for alert in alerts:
            print(f"[{alert['severity']}] {alert['detection']}")
            print(f"Alert ID: {alert['alert_id']}")
            print(f"Source IP: {alert['source_ip']}")

            if "failed_attempts" in alert:
                print(
                    f"Failed Attempts: "
                    f"{alert['failed_attempts']}"
                )

            print(
                f"MITRE ATT&CK: "
                f"{alert['mitre_attack']['technique_id']} - "
                f"{alert['mitre_attack']['technique']}"
            )
            print("-" * 50)
    else:
        print("[INFO] No alerts generated")

    print(f"\nTotal Alerts: {len(alerts)}")
    print(f"Alerts saved to: {ALERT_FILE}")
    print("\n========== SCAN COMPLETED ==========\n")


if __name__ == "__main__":
    main()
