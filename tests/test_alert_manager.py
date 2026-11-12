
import unittest

from scripts.alert_manager import enrich_alert, merge_alerts


def make_alert(
    source_ip="10.0.0.50",
    severity="HIGH",
    status=None,
    line_number=1,
):
    alert = {
        "alert_id": f"SENTINELOPS-{source_ip.replace('.', '-')}",
        "severity": severity,
        "detection": "Possible SSH Brute-Force Activity",
        "source_ip": source_ip,
        "failed_attempts": 3,
        "first_event": "2026-11-11T12:00:01+00:00",
        "last_event": "2026-11-11T12:02:00+00:00",
        "evidence": [
            {
                "line_number": line_number,
                "event": f"Failed password from {source_ip}",
            }
        ],
    }

    if status is not None:
        alert["status"] = status

    return alert


class TestAlertEnrichment(unittest.TestCase):

    def test_enriches_new_alert(self):
        alert = enrich_alert(make_alert())

        self.assertEqual(alert["status"], "open")
        self.assertEqual(alert["category"], "Authentication")
        self.assertTrue(alert["recommendation"])
        self.assertEqual(
            alert["first_seen"],
            alert["first_event"],
        )
        self.assertEqual(
            alert["last_seen"],
            alert["last_event"],
        )
        self.assertIn("last_updated", alert)

    def test_preserves_existing_status(self):
        alert = enrich_alert(make_alert(status="investigating"))

        self.assertEqual(alert["status"], "investigating")


class TestAlertMerging(unittest.TestCase):

    def test_does_not_duplicate_existing_evidence(self):
        existing = make_alert()
        incoming = make_alert()

        merged = merge_alerts([existing], [incoming])

        self.assertEqual(len(merged), 1)
        self.assertEqual(len(merged[0]["evidence"]), 1)
        self.assertEqual(merged[0]["occurrence_count"], 1)

    def test_different_ip_creates_separate_incident(self):
        existing = make_alert(source_ip="10.0.0.50")
        incoming = make_alert(source_ip="10.0.0.60")

        merged = merge_alerts([existing], [incoming])

        self.assertEqual(len(merged), 2)

    def test_severity_escalation(self):
        existing = make_alert(severity="HIGH")
        incoming = make_alert(severity="CRITICAL", line_number=2)

        merged = merge_alerts([existing], [incoming])

        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0]["severity"], "CRITICAL")
        self.assertEqual(len(merged[0]["evidence"]), 2)

    def test_preserves_original_alert_id(self):
        existing = make_alert()
        incoming = make_alert(line_number=2)

        original_id = existing["alert_id"]

        merged = merge_alerts([existing], [incoming])

        self.assertEqual(merged[0]["alert_id"], original_id)


if __name__ == "__main__":
    unittest.main()
