# Sentinel Analytics Rule

## Detection Use Case

Detect suspicious Office child process execution.

## Scenario

Office applications spawning script interpreters or LOLBins may indicate phishing-based malware execution.

Example:

```text
winword.exe → powershell.exe
excel.exe → cmd.exe
outlook.exe → mshta.exe
```
Detection Goal

Identify suspicious process chains where Microsoft Office applications launch:

 - PowerShell
 - CMD
 - WScript
 - CScript
 - MSHTA
 - Rundll32
 - Regsvr32

MITRE ATT&CK Mapping

| Technique                     | ID        |
| ----------------------------- | --------- |
| Phishing                      | T1566     |
| User Execution                | T1204     |
| PowerShell                    | T1059.001 |
| Windows Command Shell         | T1059.003 |
| Signed Binary Proxy Execution | T1218     |


Status

Rule draft in progress.
