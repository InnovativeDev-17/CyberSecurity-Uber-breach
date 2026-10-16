# Uber Breach Case Study — Educational Detection Simulator

## Project overview
This Python project demonstrates a safe, rule-based analysis of synthetic authentication logs inspired by publicly documented themes from the September 2022 Uber incident: suspicious login attempts, repeated MFA prompts, approval of an MFA request, and subsequent access.

**Important:** This is an educational simulation. It does not contain Uber's actual logs, internal systems, credentials, or forensic evidence. It does not connect to Uber or any external system.

## Features
- Loads authentication events from a CSV file.
- Detects repeated MFA prompts for the same user in a short time window.
- Flags a successful login following repeated MFA prompts.
- Flags login failures followed by a success.
- Builds a chronological incident timeline.
- Exports findings to `reports/analysis_report.txt` and `reports/alerts.csv`.

## Requirements
- Python 3.10 or later
- No third-party Python packages are required.

## Run the project on Windows
1. Extract the ZIP file.
2. Install Python 3.10+ from https://www.python.org/downloads/ if Python is not installed. During setup, enable **Add Python to PATH**.
3. Open the extracted project folder.
4. Open Command Prompt or PowerShell in that folder.
5. Run:

```bash
python src/analyzer.py --input data/sample_auth_logs.csv
```

6. Open the generated files:
   - `reports/analysis_report.txt`
   - `reports/alerts.csv`

To analyse another CSV file:

```bash
python src/analyzer.py --input data/your_auth_logs.csv --report reports/my_report.txt --alerts reports/my_alerts.csv
```

## Input CSV format
The CSV must contain these columns:

- `timestamp`: ISO-like date and time, e.g. `2022-09-15T10:00:00`
- `user`: synthetic account identifier
- `event`: one of `LOGIN_FAILURE`, `MFA_PROMPT`, `MFA_APPROVED`, `LOGIN_SUCCESS`, `RESOURCE_ACCESS`
- `source_ip`: documentation-only IP address
- `resource`: synthetic resource or `-`

Example:

```csv
timestamp,user,event,source_ip,resource
2022-09-15T10:00:00,contractor_01,LOGIN_FAILURE,192.0.2.10,identity_provider
```

Use synthetic or properly authorized logs only. Do not upload real credentials, secrets, or personal data.

## Detection logic
1. **MFA prompt burst:** at least 5 MFA prompts for the same user within a 10-minute window.
2. **MFA fatigue indicator:** an MFA approval occurs after an MFA prompt burst.
3. **Failure-then-success indicator:** at least 3 failed logins for a user within 10 minutes followed by a successful login.
4. **Resource access after alert:** a resource access event occurs after a suspicious authentication sequence.

These are illustrative thresholds for a classroom demonstration, not production-ready detection rules and not claims about Uber's actual event counts.

## Suggested demonstration
1. Run the analyzer on the sample data.
2. Show the alerts generated for repeated MFA prompts and later access.
3. Open `reports/analysis_report.txt` to discuss the timeline.
4. Explain how phishing-resistant MFA, rate limiting, identity monitoring, and least-privilege access could reduce risk.

## Limitations
- The tool uses simple rule-based detection, not machine learning.
- Events are synthetic and designed for demonstration.
- It cannot prove an attack occurred; alerts require investigation.
- It does not perform network scanning, credential collection, malware execution, or access to real systems.

## Suggested future enhancements
- Add a Streamlit dashboard.
- Add configurable thresholds and severity levels.
- Map detections to MITRE ATT&CK T1621.
- Add unit tests and JSON output.
- Package as a Windows executable using PyInstaller.

## Automated tests and report material
A report-ready implementation description and explicit test plan are available in `docs/`. Run the unit tests from the project root:

```bash
python -m unittest discover -s tests -v
```

See `docs/implementation_and_test_plan.md` for test IDs, expected results, the mapping between incident themes and synthetic events, and limitations. See `docs/report_implementation_section.md` for a draft you can adapt to the Implementation Details section of your report. Capture your own terminal screenshots and actual test output for submission.
