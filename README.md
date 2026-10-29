# PowerShell Investigation and Static Detection

A defensive cybersecurity portfolio project demonstrating PowerShell
investigation, encoded-command analysis, Windows telemetry review,
indicator detection, and automated testing.

**Case ID:** PS-001
**Project status:** Training investigation; static detection prototype

## Overview

This project simulates a Tier 1 Security Operations Center (SOC)
investigation into suspicious PowerShell execution.

The investigation examines synthetic Sysmon process-creation data,
PowerShell Script Block Logging (Event ID 4104), an encoded-command
sample, and a separate suspicious-script training artifact.

The objective is to identify investigation leads, correlate available
evidence, document limitations, and demonstrate how a small Python
detector can flag patterns requiring analyst review.

## Investigation Scenario

The synthetic telemetry describes a PowerShell process launched with
the `-EncodedCommand` argument. A corresponding PowerShell script-block
event contains `Start-Sleep -Seconds 2`.

The encoded sample is decoded as Base64 text using UTF-16LE encoding.
The script is inspected as text and is not executed.

A separate training artifact contains simulated download-related
keywords and an `example.invalid` URL. This artifact is used to test
static indicator matching; it is not proof that the actions occurred
on the synthetic endpoint.

## Investigation Findings

- Encoded PowerShell execution is represented in the synthetic
  process telemetry.
- The corresponding script-block sample contains a sleep command.
- The separate script sample contains strings that trigger configured
  static indicators.
- The detector returns findings that require analyst review.
- The evidence does not establish successful payload download,
  malicious execution, persistence, or endpoint compromise.

**Assessment:** Suspicious execution patterns warrant investigation,
but malicious activity is not confirmed by the supplied evidence.

## Detection Logic

The Python detector is located at
`analysis/detection/detect_powershell.py`.

It checks for configured patterns including:

- Encoded PowerShell command arguments.
- Hidden-window arguments.
- Download-related method names and keywords.
- Paths containing selected directories such as `Temp`, `Public`,
  or `AppData`.
- URLs, with `example.invalid` handled separately as a placeholder.

The detector uses static keyword and regular-expression matching.
It does not execute PowerShell, decode every encoded command
automatically, inspect runtime behaviour, or establish malicious intent.

A match is an investigation lead, not a verdict that a system is
compromised. Benign scripts can contain some of the same patterns.

## Repository Structure

```text
decoding-malicious-powershell/
├── analysis/
│   ├── decoded-sample-analysis.md
│   ├── timeline.md
│   └── detection/
│       └── detect_powershell.py
├── evidence/
│   ├── encoded-command-sample.txt
│   ├── powershell-4104.json
│   ├── suspicious-script-sample.txt
│   └── sysmon-events.json
├── tests/
│   └── test_detect_powershell.py
└── README.md
```

## Run the Detector

Run these commands from the repository root:

```bash
python analysis/detection/detect_powershell.py
```

The script reads `evidence/suspicious-script-sample.txt` and prints
a JSON report containing the case ID, indicator count, findings,
verdict, and limitations.

## Run the Automated Tests

```bash
python -m unittest discover -s tests -v
```

The tests cover benign input, download-related methods, encoded-command
arguments, hidden-window arguments, suspicious destinations, exclusion
of the placeholder domain from external-URL findings, and the supplied
synthetic script sample.

Record the actual test output when validating the project. Passing
tests demonstrate the tested behaviour; they do not prove detection
accuracy against real-world threats.

## Analyst Workflow Demonstrated

1. Review process-creation and script-block evidence.
2. Decode the provided command as text without executing it.
3. Build a timeline from the supplied synthetic events.
4. Run static indicator checks against the training artifact.
5. Validate selected detector behaviour with automated tests.
6. Document findings, uncertainty, and recommended follow-up.

## Limitations and Next Steps

- All supplied telemetry and samples are training evidence.
- No live endpoint or Microsoft Sentinel workspace is queried by the
  detector.
- No suspicious sample is executed.
- Static matching can produce false positives and miss threats that
  do not match the configured patterns.
- The supplied evidence does not prove a successful download,
  payload execution, or system compromise.
- Further validation should correlate genuine process, script-block,
  file, and network telemetry where available.

Potential improvements include safer encoded-command parsing,
structured event-field extraction, broader benign and suspicious test
cases, false-positive evaluation, and documented KQL detections.

## Disclaimer

This is a defensive learning and portfolio project. Samples and
findings must be interpreted within their stated evidence context.
Do not execute suspicious scripts on a personal or production system.
