# Scheduled Task Persistence — Analyst Investigation Runbook

## 1. Purpose

This runbook guides SOC analysts through investigating suspicious Windows scheduled-task creation and modification events detected by Microsoft Sentinel.

**MITRE ATT&CK:** T1053.005 — Scheduled Task/Job: Scheduled Task

**Relevant Windows Security Events:**
- 4698 — Scheduled task created
- 4702 — Scheduled task updated

Related events:
- 4699 — Scheduled task deleted
- 4700 — Scheduled task enabled
- 4701 — Scheduled task disabled

## 2. Detection Overview

The detection identifies scheduled-task activity involving potentially suspicious executable locations or execution arguments.

### Suspicious executable locations

Examples include:

- `C:\Users\Public\`
- `C:\Users\<user>\AppData\Roaming\`
- `C:\Users\<user>\AppData\Local\Temp\`
- `C:\Windows\Temp\`

These locations are not inherently malicious. They require investigation based on context.

### Suspicious execution arguments

Examples include:

- `-EncodedCommand`
- `-EC`
- `-WindowStyle Hidden`
- `-ExecutionPolicy Bypass`

These arguments may indicate concealed or unusual execution. They are not proof of malicious activity.

## 3. Initial Alert Triage

When an alert is generated, collect the following information:

| Field | Investigation purpose |
|---|---|
| TimeGenerated | Establish event time |
| Computer | Identify affected endpoint |
| EventID | Identify creation or modification |
| Account | Identify associated account |
| TaskName | Identify scheduled task |
| ExecutablePath | Identify executable location |
| Command | Understand execution mechanism |
| Arguments | Identify suspicious parameters |
| DetectionReason | Understand why the rule matched |

Use the actual verified Sentinel column names when implementing the investigation query.

## 4. Investigation Procedure

### Step 1 — Validate the scheduled-task event

Determine whether the event represents:

- A new scheduled task (4698)
- An existing scheduled task being modified (4702)

Inspect the task name, event timestamp, computer, and available task configuration.

### Step 2 — Investigate the executable

Inspect:

- Full executable path
- File name and extension
- Digital signature
- Publisher
- File hash
- File reputation
- File creation timestamp, if available

Pay particular attention to executables launched from user-writable directories.

A valid digital signature does not guarantee that the executable is being used legitimately.

### Step 3 — Analyze command-line arguments

Look for:

- Encoded PowerShell commands
- Hidden execution
- Execution-policy bypass
- Unusual script paths
- Unexpected interpreter or scripting-engine execution
- Obfuscated or chained commands

For encoded PowerShell, decode the command in a safe analysis environment before deciding whether it is malicious.

Never execute an unknown payload during routine triage.

### Step 4 — Investigate the creator account

Determine:

- Which account created or modified the task?
- Is the account expected to perform this activity?
- Is it a privileged account?
- Was the account recently created or modified?
- Are there unusual authentication events involving the account?
- Does the activity align with an approved administrative change?

Do not automatically trust privileged accounts. Attackers may compromise or create privileged accounts.

### Step 5 — Investigate surrounding process activity

Where process telemetry is available, inspect:

- Parent process
- Child processes
- Process command lines
- Execution timestamps
- Related file creation activity

Potential sources include Windows Security Event 4688 or Sysmon Event ID 1, if configured and collected.

### Step 6 — Check prevalence and environment context

Determine:

- Does the same task exist on other endpoints?
- Is the executable commonly observed?
- Is the task associated with approved enterprise software?
- Is the task expected on this particular endpoint?
- Was there a recent software installation or maintenance activity?

High prevalence is useful context, not proof of legitimacy.

## 5. False-Positive Analysis

Common legitimate scenarios include:

- Backup software creating scheduled maintenance tasks.
- Monitoring agents creating recurring tasks.
- Software updates modifying existing tasks.
- Approved administrative automation.
- Enterprise applications using AppData or ProgramData locations.

Before suppressing an alert, validate the executable, signer, hash, task identity, host scope, creator account, and expected behavior.

Avoid:
- Excluding all administrator-created tasks.
- Excluding every signed executable.
- Whitelisting entire AppData or Public directories.
- Suppressing all activity associated with a software vendor.

Any exception should be narrow, documented, justified, and periodically reviewed.

## 6. Alert Classification

### High-priority investigation candidate

Examples:
- Risky executable path combined with suspicious execution arguments.
- Unknown executable launched from a user-writable directory.
- Unusual creator account combined with suspicious task configuration.
- Suspicious task activity followed by unexpected PowerShell execution.

### Medium-priority investigation candidate

Examples:
- Risky executable path without additional suspicious arguments.
- Suspicious execution arguments from an otherwise expected location.
- Unexpected task modification requiring further validation.

Severity should be adjusted according to environmental context and confirmed evidence.

## 7. Investigation Outcomes

Classify each investigated alert as one of the following:

| Outcome | Meaning |
|---|---|
| True Positive | Malicious scheduled-task activity confirmed |
| Benign Positive | Detection matched legitimate but unusual activity |
| False Positive | Detection matched activity outside its intended scope |
| Inconclusive | Available evidence is insufficient |

Record the evidence supporting the decision.

## 8. Response and Escalation

For confirmed malicious activity:

1. Preserve relevant event and endpoint evidence.
2. Escalate to the incident response team.
3. Investigate related processes, files, accounts, and authentication activity.
4. Follow the organization's endpoint isolation and containment procedures.
5. Disable or remove malicious scheduled tasks only through approved response procedures.
6. Investigate additional persistence mechanisms.
7. Document remediation and recovery.

Do not disable scheduled tasks or isolate endpoints solely because an indicator matched. Follow incident response authorization procedures.

## 9. Evidence to Record

For every investigation, record:

- Alert and incident identifiers
- Affected endpoint
- Scheduled task name
- Event ID and timestamp
- Creator account
- Executable path
- Command and arguments
- File hash and signature information
- Parent and child process evidence, if available
- Related authentication activity
- Investigation findings
- Final classification
- Response actions
- Analyst notes

## 10. Detection Improvement Feedback

Investigation findings should feed back into detection engineering.

Examples:

- Repeated benign matches may justify narrow, evidence-based tuning.
- New attacker execution patterns may justify additional indicators.
- Missing telemetry may require data-collection improvements.
- Detection gaps may require additional rules or correlation logic.

Review detection performance periodically and maintain version-controlled documentation.

---

**Detection:** Scheduled Task Executable Path and Suspicious Execution Behavior

**Platform:** Microsoft Sentinel

**MITRE ATT&CK:** T1053.005

**Document type:** SOC Analyst Investigation Runbook

**Status:** Portfolio documentation — review and align with the deployed analytics rule before production use.
