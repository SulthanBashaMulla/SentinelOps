
import unittest
import sys
from pathlib import Path
from contextlib import redirect_stdout
from io import StringIO
import argparse

sys.path.insert(
    0,
    str(Path(__file__).resolve().parents[1] / "scripts"),
)

from manage_alerts import valid_score, list_alerts


class TestRiskScoreValidation(unittest.TestCase):

    def test_accepts_valid_score(self):
        self.assertEqual(valid_score("50"), 50)

    def test_rejects_score_above_100(self):
        with self.assertRaises(argparse.ArgumentTypeError):
            valid_score("150")

    def test_rejects_negative_score(self):
        with self.assertRaises(argparse.ArgumentTypeError):
            valid_score("-1")

    def test_rejects_non_numeric_score(self):
        with self.assertRaises(argparse.ArgumentTypeError):
            valid_score("abc")


class TestAlertFiltering(unittest.TestCase):

    def setUp(self):
        self.alerts = [
            {
                "alert_id": "ALERT-LOW",
                "severity": "LOW",
                "risk_score": 20,
                "risk_level": "LOW",
                "evidence": [],
            },
            {
                "alert_id": "ALERT-HIGH",
                "severity": "HIGH",
                "risk_score": 65,
                "risk_level": "HIGH",
                "evidence": [],
            },
            {
                "alert_id": "ALERT-CRITICAL",
                "severity": "CRITICAL",
                "risk_score": 90,
                "risk_level": "CRITICAL",
                "evidence": [],
            },
        ]

    def test_filters_by_risk_level(self):
        output = StringIO()

        with redirect_stdout(output):
            list_alerts(
                self.alerts,
                risk_level="HIGH",
            )

        result = output.getvalue()

        self.assertIn("ALERT-HIGH", result)
        self.assertNotIn("ALERT-LOW", result)
        self.assertNotIn("ALERT-CRITICAL", result)

    def test_filters_by_minimum_score(self):
        output = StringIO()

        with redirect_stdout(output):
            list_alerts(
                self.alerts,
                min_score=60,
            )

        result = output.getvalue()

        self.assertIn("ALERT-HIGH", result)
        self.assertIn("ALERT-CRITICAL", result)
        self.assertNotIn("ALERT-LOW", result)

    def test_sorts_alerts_by_descending_score(self):
        output = StringIO()

        with redirect_stdout(output):
            list_alerts(self.alerts)

        result = output.getvalue()

        critical_position = result.index("ALERT-CRITICAL")
        high_position = result.index("ALERT-HIGH")
        low_position = result.index("ALERT-LOW")

        self.assertLess(critical_position, high_position)
        self.assertLess(high_position, low_position)


if __name__ == "__main__":
    unittest.main()
