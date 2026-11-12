
import unittest

from scripts.detect_bruteforce import (
    parse_failed_events,
    parse_auth_events,
    detect_bruteforce,
    detect_bruteforce_success,
)


class TestBruteForceDetection(unittest.TestCase):

    def test_detects_rapid_failed_logins(self):

        log_lines = [
            "Nov 11 12:00:01 server sshd[1001]: Failed password for admin from 10.0.0.50 port 5001 ssh2",
            "Nov 11 12:01:00 server sshd[1002]: Failed password for admin from 10.0.0.50 port 5002 ssh2",
            "Nov 11 12:02:00 server sshd[1003]: Failed password for admin from 10.0.0.50 port 5003 ssh2",
            "Nov 11 12:03:00 server sshd[1004]: Failed password for root from 10.0.0.50 port 5004 ssh2",
        ]

        events = parse_failed_events(log_lines)
        alerts = detect_bruteforce(events)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["source_ip"], "10.0.0.50")
        self.assertEqual(alerts[0]["failed_attempts"], 4)

    def test_ignores_failures_outside_time_window(self):

        log_lines = [
            "Nov 11 12:00:01 server sshd[2001]: Failed password for admin from 10.0.0.80 port 6001 ssh2",
            "Nov 11 12:10:01 server sshd[2002]: Failed password for admin from 10.0.0.80 port 6002 ssh2",
            "Nov 11 12:20:01 server sshd[2003]: Failed password for admin from 10.0.0.80 port 6003 ssh2",
        ]

        events = parse_failed_events(log_lines)
        alerts = detect_bruteforce(events)

        self.assertEqual(len(alerts), 0)


class TestBruteForceSuccessDetection(unittest.TestCase):

    def test_detects_success_after_repeated_failures(self):

        log_lines = [
            "Nov 11 12:00:01 server sshd[3001]: Failed password for admin from 10.0.0.50 port 7001 ssh2",
            "Nov 11 12:01:00 server sshd[3002]: Failed password for admin from 10.0.0.50 port 7002 ssh2",
            "Nov 11 12:02:00 server sshd[3003]: Failed password for admin from 10.0.0.50 port 7003 ssh2",
            "Nov 11 12:03:00 server sshd[3004]: Accepted password for admin from 10.0.0.50 port 7004 ssh2",
        ]

        events = parse_auth_events(log_lines)
        alerts = detect_bruteforce_success(events)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["severity"], "CRITICAL")
        self.assertEqual(alerts[0]["source_ip"], "10.0.0.50")
        self.assertEqual(alerts[0]["failed_attempts"], 3)

    def test_ignores_success_after_only_two_failures(self):

        log_lines = [
            "Nov 11 12:00:01 server sshd[4001]: Failed password for admin from 10.0.0.60 port 8001 ssh2",
            "Nov 11 12:01:00 server sshd[4002]: Failed password for admin from 10.0.0.60 port 8002 ssh2",
            "Nov 11 12:02:00 server sshd[4003]: Accepted password for admin from 10.0.0.60 port 8003 ssh2",
        ]

        events = parse_auth_events(log_lines)
        alerts = detect_bruteforce_success(events)

        self.assertEqual(len(alerts), 0)

    def test_ignores_success_from_different_ip(self):

        log_lines = [
            "Nov 11 12:00:01 server sshd[5001]: Failed password for admin from 10.0.0.70 port 9001 ssh2",
            "Nov 11 12:01:00 server sshd[5002]: Failed password for admin from 10.0.0.70 port 9002 ssh2",
            "Nov 11 12:02:00 server sshd[5003]: Failed password for admin from 10.0.0.70 port 9003 ssh2",
            "Nov 11 12:03:00 server sshd[5004]: Accepted password for admin from 10.0.0.90 port 9004 ssh2",
        ]

        events = parse_auth_events(log_lines)
        alerts = detect_bruteforce_success(events)

        self.assertEqual(len(alerts), 0)



    def test_ignores_success_outside_time_window(self):

        log_lines = [
            "Nov 11 12:00:01 server sshd[7001]: Failed password for admin from 10.0.0.50 port 7001 ssh2",
            "Nov 11 12:01:00 server sshd[7002]: Failed password for admin from 10.0.0.50 port 7002 ssh2",
            "Nov 11 12:02:00 server sshd[7003]: Failed password for admin from 10.0.0.50 port 7003 ssh2",
            "Nov 11 12:08:00 server sshd[7004]: Accepted password for admin from 10.0.0.50 port 7004 ssh2",
        ]

        auth_events = parse_auth_events(log_lines)
        alerts = detect_bruteforce_success(auth_events)

        self.assertEqual(len(alerts), 0)

if __name__ == "__main__":
    unittest.main()
