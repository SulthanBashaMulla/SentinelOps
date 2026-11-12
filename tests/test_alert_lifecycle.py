import unittest

from scripts.alert_lifecycle import (
    get_alert_by_id,
    initialize_lifecycle,
    change_alert_status,
    add_alert_note,
)


class TestAlertLookup(unittest.TestCase):

    def test_finds_alert_by_id(self):

        alerts = [
            {"alert_id": "ALERT-001"},
            {"alert_id": "ALERT-002"},
        ]

        alert = get_alert_by_id(alerts, "ALERT-002")

        self.assertIsNotNone(alert)
        self.assertEqual(
            alert["alert_id"],
            "ALERT-002"
        )

    def test_returns_none_when_alert_not_found(self):

        alerts = [
            {"alert_id": "ALERT-001"},
        ]

        alert = get_alert_by_id(alerts, "ALERT-999")

        self.assertIsNone(alert)


class TestAlertLifecycle(unittest.TestCase):

    def test_rejects_reopening_resolved_alert(self):

        alert = {
            "alert_id": "ALERT-001",
            "status": "resolved",
        }

        with self.assertRaises(ValueError):
            change_alert_status(
                alert,
                "investigating",
            )

        self.assertEqual(alert["status"], "resolved")
        self.assertEqual(alert["lifecycle_history"], [])

    def test_initializes_lifecycle_fields(self):

        alert = {
            "alert_id": "ALERT-001",
        }

        initialize_lifecycle(alert)

        self.assertEqual(
            alert["status"],
            "open"
        )

        self.assertEqual(
            alert["lifecycle_history"],
            []
        )

        self.assertEqual(
            alert["notes"],
            []
        )

    def test_changes_open_to_investigating(self):

        alert = {
            "alert_id": "ALERT-001",
            "status": "open",
        }

        change_alert_status(
            alert,
            "investigating"
        )

        self.assertEqual(
            alert["status"],
            "investigating"
        )

        self.assertEqual(
            len(alert["lifecycle_history"]),
            1
        )

        history = alert["lifecycle_history"][0]

        self.assertEqual(
            history["from_status"],
            "open"
        )

        self.assertEqual(
            history["to_status"],
            "investigating"
        )

    def test_changes_investigating_to_resolved(self):

        alert = {
            "alert_id": "ALERT-001",
            "status": "investigating",
        }

        change_alert_status(
            alert,
            "resolved"
        )

        self.assertEqual(
            alert["status"],
            "resolved"
        )

    def test_rejects_invalid_transition(self):

        alert = {
            "alert_id": "ALERT-001",
            "status": "open",
        }

        with self.assertRaises(ValueError):
            change_alert_status(
                alert,
                "resolved"
            )

    def test_rejects_invalid_status(self):

        alert = {
            "alert_id": "ALERT-001",
        }

        with self.assertRaises(ValueError):
            change_alert_status(
                alert,
                "closed"
            )


class TestAlertNotes(unittest.TestCase):

    def test_adds_investigation_note(self):

        alert = {
            "alert_id": "ALERT-001",
        }

        add_alert_note(
            alert,
            "Reviewed authentication activity."
        )

        self.assertEqual(
            len(alert["notes"]),
            1
        )

        self.assertEqual(
            alert["notes"][0]["note"],
            "Reviewed authentication activity."
        )

    def test_rejects_empty_note(self):

        alert = {
            "alert_id": "ALERT-001",
        }

        with self.assertRaises(ValueError):
            add_alert_note(alert, "   ")
class TestAlertCollectionOperations(unittest.TestCase):

    def setUp(self):
        self.alerts = [
            {
                "alert_id": "ALERT-001",
                "status": "open",
            },
            {
                "alert_id": "ALERT-002",
                "status": "open",
            },
        ]

    def test_updates_status_by_alert_id(self):
        from scripts.alert_lifecycle import update_alert_status

        alert = update_alert_status(
            self.alerts,
            "ALERT-001",
            "investigating",
        )

        self.assertEqual(alert["status"], "investigating")
        self.assertEqual(
            self.alerts[0]["status"],
            "investigating",
        )

    def test_rejects_unknown_alert_id(self):
        from scripts.alert_lifecycle import update_alert_status

        with self.assertRaises(ValueError):
            update_alert_status(
                self.alerts,
                "ALERT-999",
                "investigating",
            )

    def test_adds_note_by_alert_id(self):
        from scripts.alert_lifecycle import add_note_to_alert

        alert = add_note_to_alert(
            self.alerts,
            "ALERT-001",
            "Investigated source IP activity.",
        )

        self.assertEqual(
            alert["notes"][0]["note"],
            "Investigated source IP activity.",
        )

    def test_rejects_note_for_unknown_alert(self):
        from scripts.alert_lifecycle import add_note_to_alert

        with self.assertRaises(ValueError):
            add_note_to_alert(
                self.alerts,
                "ALERT-999",
                "Investigation note.",
            )


if __name__ == "__main__":
    unittest.main()

if __name__ == "__main__":
    unittest.main()
