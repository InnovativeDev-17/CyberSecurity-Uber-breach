#!/usr/bin/env python3
"""Educational rule-based authentication log analyzer.

Uses synthetic or authorized CSV logs only. This tool does not connect to systems.
"""
from __future__ import annotations
import argparse
import csv
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

VALID_EVENTS = {
    "LOGIN_FAILURE", "MFA_PROMPT", "MFA_APPROVED",
    "LOGIN_SUCCESS", "RESOURCE_ACCESS"
}
MFA_WINDOW_MINUTES = 10
MFA_PROMPT_THRESHOLD = 5
FAILURE_THRESHOLD = 3


def parse_timestamp(value: str) -> datetime:
    """Parse a timestamp in ISO format."""
    return datetime.fromisoformat(value.strip().replace("Z", "+00:00"))


def load_events(path: Path) -> list[dict]:
    required = {"timestamp", "user", "event", "source_ip", "resource"}
    with path.open("r", newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames or not required.issubset(set(reader.fieldnames)):
            raise ValueError(
                "CSV must contain columns: " + ", ".join(sorted(required))
            )
        events = []
        for row_num, row in enumerate(reader, start=2):
            event_type = row["event"].strip().upper()
            if event_type not in VALID_EVENTS:
                raise ValueError(
                    f"Row {row_num}: unsupported event '{row['event']}'. "
                    f"Allowed: {', '.join(sorted(VALID_EVENTS))}"
                )
            events.append({
                "timestamp": parse_timestamp(row["timestamp"]),
                "user": row["user"].strip(),
                "event": event_type,
                "source_ip": row["source_ip"].strip(),
                "resource": row["resource"].strip(),
                "row_num": row_num,
            })
    return sorted(events, key=lambda item: item["timestamp"])


def fmt_time(value: datetime) -> str:
    return value.isoformat(sep=" ", timespec="seconds")


def analyze(events: list[dict]) -> tuple[list[dict], list[str]]:
    """Return alerts and a readable chronological timeline."""
    by_user = defaultdict(list)
    for event in events:
        by_user[event["user"]].append(event)

    alerts = []
    timeline = []

    for user, user_events in by_user.items():
        prompts = [e for e in user_events if e["event"] == "MFA_PROMPT"]
        failures = [e for e in user_events if e["event"] == "LOGIN_FAILURE"]
        approvals = [e for e in user_events if e["event"] == "MFA_APPROVED"]
        successes = [e for e in user_events if e["event"] == "LOGIN_SUCCESS"]
        resource_access = [e for e in user_events if e["event"] == "RESOURCE_ACCESS"]

        burst_ends = []
        # Sliding-window detection: any 10-minute interval with >= threshold prompts.
        for i, first in enumerate(prompts):
            window_end = first["timestamp"] + timedelta(minutes=MFA_WINDOW_MINUTES)
            window = [p for p in prompts[i:] if p["timestamp"] <= window_end]
            if len(window) >= MFA_PROMPT_THRESHOLD:
                last = window[-1]
                burst_ends.append(last["timestamp"])
                alerts.append({
                    "severity": "HIGH",
                    "user": user,
                    "time": fmt_time(first["timestamp"]),
                    "rule": "MFA_PROMPT_BURST",
                    "details": (
                        f"{len(window)} MFA prompts within "
                        f"{MFA_WINDOW_MINUTES} minutes; review for MFA fatigue."
                    ),
                })
                break

        for approval in approvals:
            if any(end <= approval["timestamp"] <= end + timedelta(minutes=15)
                   for end in burst_ends):
                alerts.append({
                    "severity": "CRITICAL",
                    "user": user,
                    "time": fmt_time(approval["timestamp"]),
                    "rule": "MFA_APPROVED_AFTER_BURST",
                    "details": "MFA approval followed a detected prompt burst.",
                })

        for success in successes:
            recent_failures = [
                f for f in failures
                if timedelta(0) <= success["timestamp"] - f["timestamp"]
                <= timedelta(minutes=MFA_WINDOW_MINUTES)
            ]
            if len(recent_failures) >= FAILURE_THRESHOLD:
                alerts.append({
                    "severity": "HIGH",
                    "user": user,
                    "time": fmt_time(success["timestamp"]),
                    "rule": "FAILURES_THEN_SUCCESS",
                    "details": (
                        f"{len(recent_failures)} failed logins in the preceding "
                        f"{MFA_WINDOW_MINUTES} minutes followed by success."
                    ),
                })

        suspicious_times = [
            parse_timestamp(a["time"]) for a in alerts if a["user"] == user
        ]
        for access in resource_access:
            if any(t <= access["timestamp"] <= t + timedelta(minutes=30)
                   for t in suspicious_times):
                alerts.append({
                    "severity": "MEDIUM",
                    "user": user,
                    "time": fmt_time(access["timestamp"]),
                    "rule": "RESOURCE_ACCESS_AFTER_ALERT",
                    "details": (
                        f"Access to '{access['resource']}' occurred within "
                        "30 minutes of a suspicious authentication alert."
                    ),
                })

    for event in events:
        timeline.append(
            f"{fmt_time(event['timestamp'])} | user={event['user']} | "
            f"event={event['event']} | source={event['source_ip']} | "
            f"resource={event['resource']}"
        )

    # De-duplicate repeated identical burst alerts generated by overlapping windows.
    unique = {}
    for alert in alerts:
        key = (alert["user"], alert["time"], alert["rule"], alert["details"])
        unique[key] = alert
    alerts = sorted(unique.values(), key=lambda a: (a["time"], a["user"], a["rule"]))
    return alerts, timeline


def write_outputs(alerts: list[dict], timeline: list[str],
                  report_path: Path, alerts_path: Path, event_count: int) -> None:
    report_path.parent.mkdir(parents=True, exist_ok=True)
    alerts_path.parent.mkdir(parents=True, exist_ok=True)

    with report_path.open("w", encoding="utf-8") as handle:
        handle.write("UBER BREACH CASE STUDY — EDUCATIONAL LOG ANALYSIS\n")
        handle.write("=" * 58 + "\n\n")
        handle.write("NOTICE: This is a simulation using synthetic data, not Uber logs.\n")
        handle.write("Events analysed: " + str(event_count) + "\n")
        handle.write("Alerts generated: " + str(len(alerts)) + "\n\n")
        handle.write("DETECTION ALERTS\n" + "-" * 58 + "\n")
        if not alerts:
            handle.write("No alerts generated by the configured rules.\n")
        for index, alert in enumerate(alerts, start=1):
            handle.write(
                f"{index}. [{alert['severity']}] {alert['rule']} | "
                f"user={alert['user']} | time={alert['time']}\n"
                f"   {alert['details']}\n"
            )
        handle.write("\nCHRONOLOGICAL EVENT TIMELINE\n" + "-" * 58 + "\n")
        for line in timeline:
            handle.write(line + "\n")
        handle.write("\nINTERPRETATION\n" + "-" * 58 + "\n")
        handle.write(
            "Alerts are indicators for human review, not proof of compromise. "
            "Recommended controls include phishing-resistant MFA, rate limits, "
            "least privilege, secrets management, and identity monitoring.\n"
        )

    with alerts_path.open("w", newline="", encoding="utf-8") as handle:
        fields = ["severity", "user", "time", "rule", "details"]
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(alerts)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Analyse synthetic/authorized authentication logs."
    )
    parser.add_argument("--input", default="data/sample_auth_logs.csv",
                        help="Input CSV path (default: data/sample_auth_logs.csv)")
    parser.add_argument("--report", default="reports/analysis_report.txt",
                        help="Text report output path")
    parser.add_argument("--alerts", default="reports/alerts.csv",
                        help="CSV alerts output path")
    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        parser.error(f"Input file not found: {input_path}")
    try:
        events = load_events(input_path)
        alerts, timeline = analyze(events)
        write_outputs(alerts, timeline, Path(args.report), Path(args.alerts), len(events))
    except (ValueError, OSError) as exc:
        parser.error(str(exc))

    print(f"Events analysed: {len(events)}")
    print(f"Alerts generated: {len(alerts)}")
    print(f"Report: {args.report}")
    print(f"Alerts CSV: {args.alerts}")
    print("Educational simulation only; alerts require human investigation.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
