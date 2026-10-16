import sys
import unittest
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from analyzer import analyze, load_events

class AnalyzerTests(unittest.TestCase):
    def event(self, minute, kind, user="test_user", resource="-"):
        return {"timestamp": datetime.fromisoformat(f"2022-09-15T10:{minute:02d}:00"),
                "user": user, "event": kind, "source_ip": "192.0.2.10",
                "resource": resource, "row_num": minute + 2}

    def test_mfa_prompt_burst_detected(self):
        events = [self.event(m, "MFA_PROMPT") for m in range(0, 5)]
        alerts, _ = analyze(events)
        self.assertIn("MFA_PROMPT_BURST", [a["rule"] for a in alerts])

    def test_approval_after_burst_detected(self):
        events = [self.event(m, "MFA_PROMPT") for m in range(0, 5)]
        events.append(self.event(6, "MFA_APPROVED"))
        alerts, _ = analyze(events)
        self.assertIn("MFA_APPROVED_AFTER_BURST", [a["rule"] for a in alerts])

    def test_failures_then_success_detected(self):
        events = [self.event(m, "LOGIN_FAILURE") for m in range(0, 3)]
        events.append(self.event(4, "LOGIN_SUCCESS"))
        alerts, _ = analyze(events)
        self.assertIn("FAILURES_THEN_SUCCESS", [a["rule"] for a in alerts])

    def test_resource_access_after_suspicious_auth_detected(self):
        events = [self.event(m, "MFA_PROMPT") for m in range(0, 5)]
        events += [self.event(6, "MFA_APPROVED"), self.event(7, "LOGIN_SUCCESS"),
                   self.event(8, "RESOURCE_ACCESS", resource="synthetic_admin_portal")]
        alerts, _ = analyze(events)
        self.assertIn("RESOURCE_ACCESS_AFTER_ALERT", [a["rule"] for a in alerts])

    def test_normal_login_does_not_trigger_authentication_alert(self):
        events = [self.event(0, "LOGIN_SUCCESS"), self.event(1, "RESOURCE_ACCESS", resource="portal")]
        alerts, _ = analyze(events)
        self.assertEqual([], alerts)

    def test_sample_csv_has_expected_fields_and_events(self):
        events = load_events(ROOT / "data" / "sample_auth_logs.csv")
        self.assertGreater(len(events), 0)
        self.assertEqual(sorted(events, key=lambda x: x["timestamp"]), events)

if __name__ == "__main__":
    unittest.main(verbosity=2)
