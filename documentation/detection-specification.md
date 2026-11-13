# Scheduled Task Persistence — Detection Specification

## 1. Overview

| Property | Description |
|---|---|
| Detection name | Suspicious Scheduled Task Execution |
| Platform | Microsoft Sentinel |
| Data source | Windows Security Events |
| Table | SecurityEvent |
| Primary Event IDs | 4698, 4702 |
| MITRE tactic | Persistence |
| MITRE technique | T1053.005 — Scheduled Task/Job: Scheduled Task |
| Detection type | Behavioral detection |
| Status | Development and validation |

## 2. Detection Objective

Identify potentially malicious scheduled-task creation and modification activity that may indicate an attempt to establish or maintain persistence on Windows endpoints.

The detection focuses on suspicious executable locations and command-line execution behavior.

The objective is to identify suspicious task configurations while preserving visibility into legitimate administrative and software-related activity.

## 3. Attacker Behavior

Attackers may abuse Windows Task Scheduler to execute malicious programs or scripts automatically.

Common attacker behaviors include:

1. Creating a new scheduled task.
2. Modifying an existing scheduled task.
3. Configuring execution from a user-writable directory.
4. Using PowerShell or other scripting engines.
5. Hiding execution through command-line arguments.
6. Establishing recurring execution for persistence.

Scheduled tasks are legitimate Windows functionality, making behavioral context essential.

## 4. Telemetry Requirements

### Primary telemetry

Windows Security Events collected in Microsoft Sentinel.

| Event ID | Description | Detection purpose |
|---|---|---|
| 4698 | Scheduled task created | Identify new task creation |
| 4702 | Scheduled task updated | Identify changes to existing tasks |

### Additional context events

| Event ID | Description | Potential value |
|---|---|---|
| 4699 | Scheduled task deleted | Understand task lifecycle |
| 4700 | Scheduled task enabled | Identify task activation |
| 4701 | Scheduled task disabled | Understand task changes |
| 4688 | Process creation | Correlate execution behavior |

Event 4688 and additional process telemetry are enrichment sources, not assumed requirements for the primary detection.

### Required fields

- TimeGenerated
- Computer
- EventID
- Account
- EventData

The scheduled-task payload must provide sufficient information to extract:

- Task name
- Executable path
- Command
- Arguments
- Creator account, where available

Actual extraction paths and workspace field names must be validated against collected telemetry.

## 5. Detection Hypothesis

A scheduled task that launches an executable from a potentially risky location or uses suspicious execution arguments may represent an attempt to establish persistence.

Confidence increases when multiple independent indicators are present.

**Primary detection hypothesis:**

Detect scheduled-task creation or modification events involving potentially risky executable paths or suspicious command-line execution behavior.

## 6. Suspicious Indicators

### 6.1 Executable path indicators

Examples:

- `C:\Users\Public\`
- `C:\Users\<user>\AppData\Roaming\`
- `C:\Users\<user>\AppData\Local\Temp\`
- `C:\Windows\Temp\`

These paths are potential risk indicators, not inherently malicious locations.

### 6.2 Execution argument indicators

Examples:

- `-EncodedCommand`
- `-EC`
- `-WindowStyle Hidden`
- `-ExecutionPolicy Bypass`

These may indicate concealed or unusual execution behavior.

### 6.3 Contextual indicators

Additional investigation context includes:

- Unusual creator account
- Unexpected task name
- Unknown executable publisher
- Rare executable hash
- Unexpected parent process
- Suspicious child process
- Unusual task configuration
- Unexpected host or account activity

## 7. Detection Logic

The detection evaluates two primary categories.

**Category 1 — Risky executable path**

The scheduled task references an executable in a potentially risky directory.

**Category 2 — Suspicious execution arguments**

The task command contains suspicious execution indicators.

### Combined confidence logic

```kql
HighConfidenceDetection =
    RiskyPath
    and (
        EncodedPowerShell
        or HiddenExecution
        or ExecutionPolicyBypass
    )
```

### Proposed classification

| Condition | Classification |
|---|---|
| Risky path + suspicious arguments | High-confidence candidate |
| Risky path only | Suspicious activity |
| Suspicious arguments only | Suspicious activity |
| No indicators | No match |

These classifications require environmental tuning and do not independently establish maliciousness.

## 8. MITRE ATT&CK Mapping

**Tactic:** Persistence

**Technique:** T1053.005 — Scheduled Task/Job: Scheduled Task

The technique is relevant because attackers may use Windows Task Scheduler to execute programs automatically and maintain access to compromised systems.

## 9. False-Positive Considerations

Potential legitimate activity includes:

- Backup applications
- Monitoring agents
- Software update mechanisms
- Enterprise automation
- Approved administrative scripts

Mitigation:

- Validate digital signatures.
- Inspect file hashes.
- Review task configuration.
- Check creator-account activity.
- Analyze host prevalence.
- Inspect process relationships.
- Introduce narrow, documented exclusions only after validation.

## 10. Detection Limitations

The detection has several limitations:

1. Legitimate software can use suspicious-looking directories.
2. Attackers may use legitimate installation paths.
3. Signed binaries can be abused.
4. Command-line indicators can occur in legitimate administrative scripts.
5. Missing or incomplete event payloads may reduce detection coverage.
6. Event collection gaps can prevent task creation or modification from being observed.
7. Path-based indicators alone cannot establish malicious intent.

Additional telemetry and correlation improve investigation confidence.

## 11. Validation Strategy

### Synthetic validation

Six positive and negative test cases were executed.

**Result:** 6/6 passed.

### Actual telemetry validation

The user confirmed that the detection query works against actual Microsoft Sentinel telemetry.

Further validation should document:

- Real positive examples.
- Real negative examples.
- Field extraction accuracy.
- False-positive analysis.
- Detection volume.
- Analyst investigation outcomes.

## 12. Production Requirements

Before production deployment:

- [ ] Validate actual field extraction.
- [ ] Validate all detection conditions.
- [ ] Review false positives.
- [ ] Tune severity.
- [ ] Configure entity mapping.
- [ ] Configure alert grouping.
- [ ] Configure scheduled analytics rule.
- [ ] Prepare investigation runbook.
- [ ] Document deployment and rollback.
- [ ] Monitor detection performance.

## 13. Success Criteria

The detection should:

- Identify suspicious scheduled-task creation and modification.
- Detect potentially risky executable paths.
- Identify suspicious execution arguments.
- Preserve sufficient investigation context.
- Minimize avoidable false positives.
- Provide useful alerts to SOC analysts.
- Support repeatable validation and maintenance.

## 14. Future Improvements

Potential enhancements:

- Correlation with Windows process creation events.
- File hash and signer enrichment.
- Threat intelligence integration.
- Task configuration anomaly detection.
- Behavioral baselining.
- Correlation with suspicious authentication activity.
- Automated detection testing.
- Sigma rule implementation.

---

**Project:** Windows Persistence Detection

**Detection:** Suspicious Scheduled Task Execution

**Platform:** Microsoft Sentinel

**MITRE ATT&CK:** T1053.005

**Document status:** Portfolio specification — development and validation evidence should be updated as implementation progresses.
