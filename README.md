# Windows Persistence Detection — Microsoft Sentinel & KQL

A practical Detection Engineering project focused on identifying suspicious Windows scheduled-task activity using Microsoft Sentinel and Kusto Query Language (KQL).

The project demonstrates detection development, telemetry analysis, validation, false-positive investigation, and production rule design.

## Project Overview

**Detection technique:** Scheduled Task Persistence

**MITRE ATT&CK:** [T1053.005 — Scheduled Task](https://attack.mitre.org/techniques/T1053/005/)

**SIEM:** Microsoft Sentinel

**Query language:** KQL

**Data source:** Windows Security Events

**Primary Event IDs:**
- 4698 — Scheduled task created
- 4702 — Scheduled task updated

## Detection Objective

Identify potentially suspicious scheduled-task creation and modification activity that may indicate an attempt to establish or maintain persistence on Windows endpoints.

The detection focuses on:

- Executables launched from potentially risky directories.
- Suspicious PowerShell execution arguments.
- Unusual scheduled-task configurations.
- Contextual investigation of task creators and executable behavior.

## Detection Indicators

### Suspicious executable locations

Examples:

```text
C:\Users\Public\
C:\Users\<user>\AppData\Roaming\
C:\Users\<user>\AppData\Local\Temp\
C:\Windows\Temp\
```

These locations are not inherently malicious. They are investigated because attackers may abuse user-writable directories to store and execute payloads.

### Suspicious execution arguments

Examples:

```text
-EncodedCommand
-EC
-WindowStyle Hidden
-ExecutionPolicy Bypass
```

These indicators may reveal concealed or unusual execution behavior.

## Detection Logic

The detection evaluates two primary categories:

1. Risky executable paths.
2. Suspicious execution arguments.

A combined condition increases investigation priority:

```kql
RiskyPath
and (
    EncodedPowerShell
    or HiddenExecution
    or ExecutionPolicyBypass
)
```

The detection also preserves visibility into individual indicators rather than alerting exclusively on combined conditions.

## Detection Architecture

```text
Windows Endpoints
       |
       v
Windows Security Events
       |
       v
Microsoft Sentinel
       |
       v
Scheduled Task Events
  4698 / 4702
       |
       v
KQL Detection Logic
       |
       +----------------------+
       |                      |
       v                      v
Risky Executable Path    Suspicious Arguments
       |                      |
       +----------+-----------+
                  |
                  v
       Detection Classification
                  |
                  v
       Alert and Investigation
                  |
                  v
       SOC Analyst Runbook
```

## Validation

### Synthetic test results

| Test case | Expected behavior | Result |
|---|---|---|
| Risky path + normal arguments | Match | Passed |
| Normal path + encoded PowerShell | Match | Passed |
| Legitimate path + normal arguments | No match | Passed |
| Risky path + hidden execution | Match | Passed |
| Legitimate monitoring path | No match | Passed |
| AppData Roaming path | Match | Passed |

**Synthetic validation: 6/6 passed.**

### Actual telemetry validation

The detection query was confirmed working against actual Microsoft Sentinel telemetry.

Further documented production evidence should include representative positive and negative event examples, false-positive disposition, and alert-volume measurements.

## False-Positive Analysis

Potential legitimate activity includes:

- Backup software.
- Monitoring agents.
- Enterprise software updates.
- Approved administrative automation.
- Legitimate applications using AppData or temporary directories.

Tuning principles:

- Validate digital signatures and file hashes.
- Investigate task creator accounts.
- Review executable prevalence.
- Examine parent and child process activity where available.
- Avoid broad exclusions based on administrator accounts or signed software.
- Maintain narrow, documented exceptions.

## Investigation Context

For every suspicious match, investigate:

| Evidence | Purpose |
|---|---|
| Task name | Identify scheduled task |
| Executable path | Understand execution location |
| Command and arguments | Identify execution behavior |
| Creator account | Investigate task origin |
| Digital signature | Validate publisher |
| File hash | Support reputation checks |
| Host prevalence | Identify unusual distribution |
| Process activity | Understand execution relationships |

## MITRE ATT&CK Mapping

| Property | Mapping |
|---|---|
| Tactic | Persistence |
| Technique | T1053.005 |
| Technique name | Scheduled Task/Job: Scheduled Task |

## Repository Structure

```text
Windows-Persistence-Detection/
│
├── README.md
│
├── detections/
│   └── scheduled-task-detection.kql
│
├── tests/
│   └── scheduled-task-test-cases.kql
│
├── documentation/
│   ├── detection-specification.md
│   ├── false-positive-analysis.md
│   ├── analyst-runbook.md
│   └── deployment-checklist.md
│
└── evidence/
    ├── test-results/
    └── sentinel-alert-screenshots/
```

## Skills Demonstrated

- Microsoft Sentinel
- KQL detection development
- Windows Security Event analysis
- Scheduled-task persistence detection
- MITRE ATT&CK mapping
- Detection hypothesis development
- Positive and negative test-case design
- False-positive analysis
- Detection tuning
- Alert enrichment and entity mapping
- SOC investigation workflows
- Production detection engineering concepts

## Future Improvements

- Correlate scheduled-task events with process creation telemetry.
- Enrich detections with file hash and signer information.
- Add task configuration anomaly detection.
- Develop Sigma equivalents.
- Implement automated detection testing.
- Integrate detection-as-code workflows.

## Project Status

**Current status:** Detection development and validation.

- [x] Detection hypothesis developed.
- [x] Windows event telemetry identified.
- [x] KQL detection logic developed.
- [x] Six synthetic test cases passed.
- [x] Actual Sentinel telemetry query confirmed working.
- [x] Investigation runbook drafted.
- [x] False-positive analysis drafted.
- [x] Deployment checklist drafted.
- [x] Detection specification drafted.
- [ ] Final production KQL committed.
- [ ] Representative Sentinel evidence added.
- [ ] Analytics rule deployment verified.
- [ ] Entity mapping and alert grouping validated.

---

**Disclaimer:** This project is intended for defensive security research, detection engineering practice, and SOC investigation training. Risk indicators are not proof of malicious activity.
