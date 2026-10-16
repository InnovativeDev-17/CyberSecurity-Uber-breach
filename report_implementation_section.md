# Implementation Details (report-ready draft)

## 4.1 System Design
A lightweight Python-based authentication-log analyser was developed to demonstrate how security teams can identify indicators associated with MFA fatigue and suspicious account activity. The program accepts a CSV file, validates the required columns and event types, sorts events by timestamp, applies rule-based checks, and produces a chronological timeline with a separate alert file. The implementation uses Python's standard library and does not require access to an external service.

## 4.2 Detection Logic
The analyser flags five or more MFA prompts for one account within ten minutes, an MFA approval shortly after that burst, three or more failed logins followed by a success within the defined window, and resource access occurring shortly after a suspicious authentication alert. Thresholds are configurable constants in the source code and are used solely for demonstration. These rules are indicators for investigation rather than proof that an account has been compromised.

## 4.3 Test Environment
The prototype requires Python 3.10 or later. Input records in `data/sample_auth_logs.csv` are synthetic. The program generates `reports/analysis_report.txt` for the event timeline and interpretation, and `reports/alerts.csv` for machine-readable alerts. Automated tests in `tests/test_analyzer.py` cover the four detection rules, a normal-login negative case, and loading/sorting of the sample data.

## 4.4 Relationship to the Uber Incident
Uber publicly reported that an attacker obtained access through a contractor account and that repeated MFA requests were eventually approved. The prototype models those general event patterns using fictional records. It does not reproduce Uber's internal telemetry, exact event counts, source addresses, tools or forensic findings. Its purpose is to demonstrate a defensive detection workflow that could be adapted to authorised identity-provider logs.

## 4.5 Reproducibility
Run `python src/analyzer.py --input data/sample_auth_logs.csv` from the project directory. Run `python -m unittest discover -s tests -v` to execute the test suite. In the final report, include the actual console output and generated alert count from your run, along with screenshots of the terminal and report files. Do not claim results that have not been observed during execution.
