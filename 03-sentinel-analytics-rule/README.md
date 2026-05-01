# Sentinel Analytics Rule

## Detection Use Case

Detect suspicious user-initiated shell execution originating from desktop paths.

## Scenario

A user initiated command shell execution from the desktop context, launching a batch file that led to follow-on PowerShell activity.

This behavior is relevant because user-executed scripts from desktop locations are frequently associated with:

- staged payload execution
- user-assisted malware launch
- initial access execution chains
- script-based post-click activity

## Detection Goal

Identify suspicious command shell execution where:

- `explorer.exe` launches `cmd.exe`
- `cmd.exe` executes a script from user desktop paths
- execution may lead to follow-on scripting activity

## Detection Logic

This detection identifies command shell execution initiated by Windows Explorer where the executed command references batch or script content from user desktop locations.

## Detection Query

```kql
DeviceProcessEvents
| where Timestamp > ago(1h)
| where InitiatingProcessFileName =~ "explorer.exe"
| where FileName =~ "cmd.exe"
| where ProcessCommandLine has "\\Desktop\\"
| where ProcessCommandLine has_any (".bat", ".cmd", ".ps1")
| project
    Timestamp,
    DeviceName,
    AccountName,
    InitiatingProcessFileName,
    FileName,
    ProcessCommandLine,
    FolderPath,
    SHA256
| order by Timestamp desc
```

## Data Sources

- Microsoft Defender XDR
- Microsoft Defender for Endpoint
- DeviceProcessEvents

## MITRE ATT&CK Mapping

| Technique | ID |
|---|---|
| User Execution | T1204 |
| Windows Command Shell | T1059.003 |
| Command and Scripting Interpreter | T1059 |

## False Positives

Potential benign activity may include:

- user-executed local admin scripts
- local troubleshooting scripts
- manually launched desktop batch files
- developer / IT automation scripts

Analyst review should validate script origin, user intent and follow-on execution.

## Response Actions

- Review executed script contents
- Validate file origin and download source
- Review follow-on PowerShell activity
- Review related network connections
- Review child process activity
- Validate user intent
- Escalate if suspicious follow-on execution is observed

## Status

Validated in Microsoft Defender XDR telemetry and ready for Sentinel scheduled analytics rule conversion.
