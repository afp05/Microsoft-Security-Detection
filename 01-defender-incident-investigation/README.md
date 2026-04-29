# Defender Incident Investigation

## Objective

Investigate a suspicious endpoint security alert using Microsoft Defender XDR telemetry.

## Scenario

Suspicious PowerShell execution initiated from an Office process.

Example process chain:

```text
winword.exe → powershell.exe

Investigation Workflow
Review alert context
Identify affected device and user
Analyze process tree
Review command line
Pivot to network connections
Check file and registry activity
Determine verdict
Recommend response actions
Data Sources
Microsoft Defender XDR
Defender for Endpoint
Advanced Hunting
DeviceProcessEvents
DeviceNetworkEvents
DeviceFileEvents
DeviceRegistryEvents


MITRE ATT&CK Mapping
| Technique                         | ID        |
| --------------------------------- | --------- |
| User Execution                    | T1204     |
| PowerShell                        | T1059.001 |
| Command and Scripting Interpreter | T1059     |
| Ingress Tool Transfer             | T1105     |



Status

Lab setup in progress.
