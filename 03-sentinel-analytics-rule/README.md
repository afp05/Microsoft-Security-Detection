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

1. PowerShell
2. CMD
3. WScript
4. CScript
5. MSHTA
6. Rundll32
7. Regsvr32
8. MITRE ATT&CK Mapping
9. Technique	ID
10. Phishing	T1566
11. User Execution	T1204
12. PowerShell	T1059.001
13. Windows Command Shell	T1059.003
14. Signed Binary Proxy Execution	T1218

Status

Rule draft in progress.
