# Scheduled Task Detection — False Positive Analysis and Tuning

## 1. Purpose

This document describes potential false positives in the Scheduled Task Persistence detection and the methods used to evaluate and reduce them.

The objective is to improve detection accuracy without creating blind spots or suppressing genuine attacker activity.

**Platform:** Microsoft Sentinel

**Data source:** Windows Security Events

**Relevant events:** 4698, 4702

**MITRE ATT&CK:** T1053.005 — Scheduled Task/Job: Scheduled Task

## 2. Detection Indicators

### Potentially risky executable paths

The detection examines paths such as:

- `C:\Users\Public\`
- `C:\Users\<user>\AppData\Roaming\`
- `C:\Users\<user>\AppData\Local\Temp\`
- `C:\Windows\Temp\`

These locations may be abused by attackers because they can be writable by ordinary users or used for temporary execution.

However, legitimate applications may also use these locations.

### Suspicious execution arguments

The detection examines:

- `-EncodedCommand`
- `-EC`
- `-WindowStyle Hidden`
- `-ExecutionPolicy Bypass`

These arguments may be associated with concealed or unusual script execution.

They should be evaluated alongside the executable, task configuration, account, and surrounding process activity.

## 3. False-Positive Scenarios

### Scenario A — Legitimate backup software

**Observed activity:**
- Scheduled task created by an approved administrator.
- Executable located under Program Files.
- Valid digital signature.
- Normal command-line arguments.
- Expected backup behavior.

**Assessment:** Likely benign, subject to validation.

**Tuning decision:**
- Do not automatically exclude the entire software vendor.
- Verify the file hash, signer, task identity, and expected behavior.
- Consider a narrow exception if evidence supports it.

### Scenario B — Suspicious executable in Public directory

**Observed activity:**
- Executable located in `C:\Users\Public\`.
- Unusual creator account.
- Hidden execution arguments.
- Unknown publisher.

**Assessment:** High-priority investigation candidate.

**Tuning decision:**
- Retain the detection.
- Investigate the executable and account.
- Inspect surrounding process activity.
- Escalate if malicious behavior is confirmed.

### Scenario C — Signed monitoring agent with unusual child process

**Observed activity:**
- Executable has a valid digital signature.
- Installed under Program Files.
- Launches an unexpected PowerShell child process.

**Assessment:** Suspicious behavior requiring investigation.

**Tuning decision:**
- Do not suppress based only on the digital signature.
- Investigate the child process command line.
- Validate expected application behavior.
- Check for possible abuse of legitimate software.

### Scenario D — Legitimate enterprise application using AppData

**Observed activity:**
- Scheduled task launches an executable from AppData.
- Software is known within the organization.
- Activity occurs across multiple expected endpoints.

**Assessment:** Potentially benign, but requires verification.

**Tuning decision:**
- Validate publisher, hash, software ownership, and task configuration.
- Compare behavior across endpoints.
- Use a narrow exception only after validation.

## 4. Prevalence Analysis

Prevalence helps identify common and unusual scheduled-task activity.

Useful measurements include:

- Event count
- Unique hosts
- Unique accounts
- First-seen timestamp
- Last-seen timestamp
- Task-name frequency

High prevalence does not establish legitimacy.

A widespread malicious executable or compromised enterprise application can affect many endpoints.

Low prevalence does not establish maliciousness either.

## 5. Suppression Strategy

Avoid broad suppression rules.

### Unsafe exclusions

Do not automatically exclude:

- All administrator accounts.
- All signed executables.
- Entire AppData directories.
- Entire Public directories.
- All tasks associated with known vendors.

### Preferred approach

Before introducing an exclusion, verify:

1. Executable signer and signature validity.
2. File hash and reputation.
3. Scheduled-task identity.
4. Expected creator account.
5. Expected command-line arguments.
6. Host prevalence.
7. Application-owner confirmation.
8. Expected parent and child process behavior.

Document every exclusion with its justification and review date.

## 6. Detection Tuning Strategy

The detection uses multiple indicators to provide useful investigation context.

| Detection condition | Proposed classification |
|---|---|
| Risky path + suspicious arguments | High-confidence candidate |
| Risky path only | Suspicious activity |
| Suspicious arguments only | Suspicious activity |
| No suspicious indicators | No detection |

These classifications are initial tuning decisions, not confirmed incident verdicts.

### Tuning principles

- Preserve broad hunting visibility.
- Use additional context to improve alert confidence.
- Avoid relying on individual indicators as proof.
- Maintain separate visibility for suspicious paths and execution behavior.
- Review analyst feedback periodically.
- Document every logic change.

## 7. Detection Validation

Synthetic test cases completed:

| Test case | Expected result | Result |
|---|---|---|
| Risky path + normal arguments | Match | Passed |
| Normal path + encoded PowerShell | Match | Passed |
| Legitimate path + normal arguments | No match | Passed |
| Risky path + hidden execution | Match | Passed |
| Legitimate monitoring path | No match | Passed |
| AppData Roaming path | Match | Passed |

**Synthetic validation:** 6/6 passed.

**Actual Sentinel telemetry:** User confirmed the detection query works against actual workspace telemetry.

Note: Full production validation still requires documented real-event positive and negative examples, including investigation outcomes.

## 8. Continuous Improvement

Review the detection periodically for:

- New attacker execution patterns.
- Newly observed suspicious paths.
- Legitimate software changes.
- False-positive trends.
- Changes in event collection.
- Detection gaps.
- Analyst feedback.

Any changes should be tested and version-controlled before production deployment.

## 9. Conclusion

Effective scheduled-task detection requires more than identifying suspicious directories or command-line arguments.

A reliable detection should combine executable location, execution behavior, creator identity, task configuration, prevalence, and surrounding endpoint activity.

The goal is to maintain strong detection coverage while reducing unnecessary alerts through evidence-based tuning.

---

**Project:** Windows Persistence Detection

**Detection:** Scheduled Task Executable Path and Suspicious Execution Behavior

**MITRE ATT&CK:** T1053.005

**Status:** Portfolio documentation — update with measured production false-positive rates and investigation evidence when available.
