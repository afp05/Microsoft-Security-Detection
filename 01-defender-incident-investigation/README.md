# Defender Incident Investigation

## Objective

Investigate a suspicious endpoint security alert using Microsoft Defender XDR telemetry.

## Scenario

Suspicious PowerShell execution initiated by Microsoft Word.

Example process chain:

```text

winword.exe → powershell.exe
```
## Investigation Workflow

1. Review alert context
2. Identify affected device and user
3. Analyze process tree
4. Review command line
5. Pivot to network connections
6. Check file and registry activity
7. Determine verdict
8. Recommend response actions
9. Data Sources
10. Microsoft Defender XDR
11. Defender for Endpoint
12. Advanced Hunting
13. DeviceProcessEvents
14. DeviceNetworkEvents
15. DeviceFileEvents
16. DeviceRegistryEvents





MITRE ATT&CK Mapping
| Technique                         | ID        |
| --------------------------------- | --------- |
| User Execution                    | T1204     |
| PowerShell                        | T1059.001 |
| Command and Scripting Interpreter | T1059     |
| Ingress Tool Transfer             | T1105     |



Status

Lab setup in progress.
