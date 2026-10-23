
# PS-001 — Investigation Timeline

## Dataset classification
Synthetic training evidence. No live endpoint was investigated.

## Observed events

### 2026-10-22 08:41:16.420 UTC
- Source: Sysmon Event ID 1
- Process: powershell.exe
- Parent process: explorer.exe
- Working directory: C:\Users\J.Smith\Downloads
- Command-line indicator: -EncodedCommand
- Assessment: Suspicious execution pattern requiring investigation.

### 2026-10-22 08:41:16.510 UTC
- Source: PowerShell Event ID 4104
- Script block: Start-Sleep -Seconds 2
- Assessment: Matches the decoded command; no malicious behaviour established by this script block alone.

## Separate training artifact
The file evidence/suspicious-script-sample.txt demonstrates simulated download and payload-destination indicators.
It is not evidence that those actions occurred on WS-014.

## Current conclusion
Encoded execution was observed in the synthetic dataset.
Malicious activity has not been confirmed.
Further correlated evidence is required.
