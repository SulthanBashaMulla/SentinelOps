import unittest

from scripts.detect_bruteforce import (
    parse_failed_events,
    detect_bruteforce,
)


class TestBruteForceDetection(unittest.TestCase):

    def test_detects_rapid_failed_logins(self):

        log_lines = [
            (
                "Nov 11 12:00:01 server sshd[1001]: "
                "Failed password for admin from 10.0.0.50 "
                "port 5001 ssh2"
            ),
            (
                "Nov 11 12:01:00 server sshd[1002]: "
                "Failed password for admin from 10.0.0.50 "
                "port 5002 ssh2"
            ),
            (
                "Nov 11 12:02:00 server sshd[1003]: "
                "Failed password for admin from 10.0.0.50 "
                "port 5003 ssh2"
            ),
            (
                "Nov 11 12:03:00 server sshd[1004]: "
                "Failed password for root from 10.0.0.50 "
                "port 5004 ssh2"
            ),
        ]

        events = parse_failed_events(log_lines)
        alerts = detect_bruteforce(events)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(
            alerts[0]["source_ip"],
            "10.0.0.50"
        )
        self.assertEqual(
            alerts[0]["failed_attempts"],
            4
        )

    def test_ignores_failures_outside_time_window(self):

        log_lines = [
            (
                "Nov 11 12:00:01 server sshd[2001]: "
                "Failed password for admin from 10.0.0.80 "
                "port 6001 ssh2"
            ),
            (
                "Nov 11 12:10:01 server sshd[2002]: "
                "Failed password for admin from 10.0.0.80 "
                "port 6002 ssh2"
            ),
            (
                "Nov 11 12:20:01 server sshd[2003]: "
                "Failed password for admin from 10.0.0.80 "
                "port 6003 ssh2"
            ),
        ]

        events = parse_failed_events(log_lines)
        alerts = detect_bruteforce(events)

        self.assertEqual(len(alerts), 0)


if __name__ == "__main__":
    unittest.main()
