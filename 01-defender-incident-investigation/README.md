# Defender Incident Investigation

## Objective

Investigate suspicious script execution observed during an active office-user workflow using Microsoft Defender XDR telemetry.

## Scenario

Suspicious command-line activity was observed shortly after a user launched LibreOffice Writer on a Windows endpoint onboarded to Microsoft Defender for Endpoint.

The objective was to determine whether the observed shell and PowerShell activity was consistent with benign user behavior or required escalation as suspicious execution.

## Alert Context

| Field | Value |
|---|---|
| Device | desktop-blre1q2 |
| User | Agnieszka |
| Initial Activity | LibreOffice launch |
| Suspicious Activity | Shell execution from desktop context |
| Follow-on Activity | PowerShell execution |
| Data Source | Microsoft Defender XDR Advanced Hunting |

## Investigation Workflow

1. Review process execution timeline
2. Identify baseline user activity
3. Analyze suspicious shell execution
4. Review command-line behavior
5. Correlate follow-on PowerShell activity
6. Review Defender follow-up telemetry
7. Determine verdict
8. Recommend response actions

## Baseline Activity

Normal user activity showed expected office application execution:

```text
explorer.exe → soffice.exe → soffice.bin
