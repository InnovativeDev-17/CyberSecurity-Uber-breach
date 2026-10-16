# Implementation and Test Plan

## 1. Objective
Build a reproducible classroom demonstration that analyses authentication-event records for patterns relevant to social engineering and MFA fatigue. The program is inspired by publicly reported aspects of the 2022 Uber incident; it is not a reconstruction from Uber's private telemetry.

## 2. Design
**Input:** CSV records with timestamp, user, event, source IP and resource. **Processing:** validate columns and event types, sort records chronologically, group by account, apply transparent time-window rules, and create an event timeline. **Output:** a readable text report and a CSV alert list.

## 3. Detection rules
| Rule | Trigger | Meaning / limitation |
|---|---|---|
| MFA_PROMPT_BURST | At least 5 prompts for one user in 10 minutes | Possible MFA fatigue; threshold is illustrative |
| MFA_APPROVED_AFTER_BURST | Approval within 15 minutes after detected prompt burst | Escalates the suspicious sequence; approval alone does not prove coercion |
| FAILURES_THEN_SUCCESS | At least 3 failures in 10 minutes before success | Possible guessing or credential misuse; may also be legitimate error |
| RESOURCE_ACCESS_AFTER_ALERT | Resource access within 30 minutes after an alert | Provides context for triage; temporal proximity is not proof of causation |

## 4. Mapping to the case study
| Publicly reported theme | Safe simulation representation | Defensive purpose |
|---|---|---|
| Repeated MFA prompts | `MFA_PROMPT` events | Identify possible push fatigue |
| MFA request approved | `MFA_APPROVED` event | Prioritise review of the sequence |
| Suspicious authentication | Failed logins followed by success | Highlight account activity for investigation |
| Access to internal resource | `RESOURCE_ACCESS` event | Build context after suspicious authentication |

These are illustrative event labels, not raw Uber log fields. The sample data is synthetic and must not be presented as evidence from Uber.

## 5. Test cases and expected behaviour
| ID | Test | Expected result |
|---|---|---|
| TC-01 | Five MFA prompts within 10 minutes | `MFA_PROMPT_BURST` alert |
| TC-02 | MFA approval after prompt burst | `MFA_APPROVED_AFTER_BURST` alert |
| TC-03 | Three login failures followed by success within the window | `FAILURES_THEN_SUCCESS` alert |
| TC-04 | Resource access after a suspicious authentication sequence | `RESOURCE_ACCESS_AFTER_ALERT` alert |
| TC-05 | Ordinary successful login and resource access | No authentication alert |
| TC-06 | Load bundled sample CSV | Records load and are chronologically sorted |

The automated unit tests are executable. Record the actual output from the test run in the report; do not label a test as passed until it has been run.

## 6. Run instructions
From the project root:

```bash
python src/analyzer.py --input data/sample_auth_logs.csv
python -m unittest discover -s tests -v
```

The analyser uses only the Python standard library. Use Python 3.10 or later.

## 7. Ethical and technical limitations
The project uses synthetic events, has no connection to Uber or any production identity provider, and does not ingest real incident logs. Rules are simple heuristics and can produce false positives or miss sophisticated activity. Alerts should lead to human review, corroboration with identity-provider and endpoint logs, and documented incident-response procedures. No claim is made that Uber used this code or these exact thresholds.

## 8. Recommended controls to discuss
Prefer phishing-resistant MFA such as FIDO2/WebAuthn; rate-limit or suppress repeated prompts; use number matching where appropriate; enforce least privilege and time-bound privileged access; store secrets in a managed vault; alert on prompt bursts, new device/location patterns, unusual privilege changes and access to sensitive resources; and revoke sessions/credentials promptly when compromise is suspected. These are recommendations, not claims about controls Uber actually deployed after the incident.
