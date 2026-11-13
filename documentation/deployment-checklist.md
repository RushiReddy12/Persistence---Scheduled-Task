# Scheduled Task Detection — Deployment Checklist

## 1. Project Information

| Property | Value |
|---|---|
| Detection name | Suspicious Scheduled Task Execution |
| Platform | Microsoft Sentinel |
| Data source | Windows Security Events |
| Primary table | SecurityEvent |
| Event IDs | 4698, 4702 |
| MITRE tactic | Persistence |
| MITRE technique | T1053.005 |
| Rule type | Scheduled query rule |

## 2. Pre-Deployment Validation

### Telemetry validation

- [ ] Confirm SecurityEvent table receives Windows security events.
- [ ] Confirm Event ID 4698 is available.
- [ ] Confirm Event ID 4702 is available.
- [ ] Verify EventData contains scheduled-task configuration.
- [ ] Verify task name extraction.
- [ ] Verify executable path extraction.
- [ ] Verify command-line argument extraction.
- [ ] Verify creator-account extraction.
- [ ] Confirm timestamps and host information are populated.

### Detection logic validation

- [ ] Risky executable path indicators implemented.
- [ ] Suspicious execution argument indicators implemented.
- [ ] Combined-indicator logic validated.
- [ ] DetectionReason populated correctly.
- [ ] Positive test cases passed.
- [ ] Negative test cases passed.
- [ ] Synthetic test results documented.
- [ ] Actual Sentinel telemetry validation documented.

### False-positive validation

- [ ] Review legitimate backup software.
- [ ] Review legitimate monitoring software.
- [ ] Review approved administrative tasks.
- [ ] Validate signed executable behavior.
- [ ] Review unusual privileged-account activity.
- [ ] Document narrow exclusions.
- [ ] Avoid broad path and account exclusions.

## 3. Analytics Rule Configuration

| Setting | Proposed configuration |
|---|---|
| Rule name | Suspicious Scheduled Task Execution |
| Rule type | Scheduled query rule |
| Severity | High as initial rule setting |
| MITRE tactic | Persistence |
| MITRE technique | T1053.005 |
| Query frequency | Every 5 hours — proposed |
| Lookup period | Last 5 hours — proposed |
| Alert threshold | Greater than 0 results |
| Rule status | Enable after validation |

**Important:** These are proposed initial settings. Review event volume, detection latency, duplicate alerts, and the Sentinel rule scheduling constraints before deployment.

## 4. Entity Mapping

Configure entity mappings using the actual query output fields.

### Host entity

- Identifier: HostName
- Value: Computer

### Account entity

- Identifier: Name or another supported account identifier
- Value: Verified account field

Validate the account format before deployment. Do not assume that the event's Account field always contains a simple username.

### Additional investigation context

Retain:

- TaskName
- ExecutablePath
- Command
- Arguments
- EventID
- DetectionReason
- TimeGenerated

These should remain available in alert details or custom details where supported.

## 5. Alert and Incident Grouping

- [ ] Review alert grouping settings.
- [ ] Group related alerts using appropriate endpoint and task context.
- [ ] Avoid combining unrelated scheduled tasks.
- [ ] Preserve original event timestamps.
- [ ] Preserve the underlying event details.
- [ ] Validate incident grouping separately from alert grouping.

## 6. Testing Before Enabling

Perform the following tests:

| Test | Expected result |
|---|---|
| Risky path + normal arguments | Suspicious path match |
| Normal path + encoded PowerShell | Suspicious argument match |
| Risky path + hidden execution | High-confidence candidate |
| Legitimate software + normal execution | No suspicious match |
| Task creation event | Event detected |
| Task modification event | Event detected |
| Missing optional fields | Query handles gracefully |

Record actual results and investigate unexpected matches.

## 7. Production Deployment

- [ ] Confirm correct Sentinel workspace.
- [ ] Confirm correct analytics-rule query.
- [ ] Confirm the query uses verified workspace fields.
- [ ] Configure scheduling.
- [ ] Configure severity.
- [ ] Configure MITRE mapping.
- [ ] Configure entity mapping.
- [ ] Configure alert grouping.
- [ ] Review incident creation settings.
- [ ] Add analyst-facing description.
- [ ] Add investigation runbook reference.
- [ ] Enable the rule after approval.

## 8. Post-Deployment Monitoring

During the initial monitoring period:

- [ ] Monitor alert volume.
- [ ] Review high-severity alerts.
- [ ] Review benign-positive matches.
- [ ] Identify repeated alerts.
- [ ] Check query execution and rule health.
- [ ] Validate entity mapping.
- [ ] Review analyst feedback.
- [ ] Document tuning decisions.

Do not introduce broad exclusions simply to reduce alert volume.

## 9. Rollback Plan

If the rule produces unexpected results or operational issues:

1. Disable the analytics rule through the approved change process.
2. Preserve existing alerts and investigation evidence.
3. Review the query and telemetry extraction logic.
4. Identify the cause of unexpected behavior.
5. Correct the detection logic.
6. Repeat validation tests.
7. Re-enable only after approval.

## 10. Change Management

Record:

- Detection version
- Change date
- Change owner
- Reason for change
- Query changes
- Test results
- False-positive impact
- Approval details
- Rollback details

Maintain the detection query and supporting documentation in version control.

## 11. Deployment Status

| Milestone | Status |
|---|---|
| Detection hypothesis | Completed |
| Synthetic validation | Passed 6/6 |
| Actual Sentinel telemetry | Confirmed working |
| False-positive review | In progress |
| Detection tuning | In progress |
| Analytics rule deployment | Pending confirmation |
| Entity mapping validation | Pending |
| Alert grouping validation | Pending |
| Production monitoring | Pending |

---

**Project:** Windows Persistence Detection

**Detection:** Suspicious Scheduled Task Execution

**MITRE ATT&CK:** T1053.005

**Platform:** Microsoft Sentinel

**Document status:** Portfolio draft — update deployment statuses with actual evidence.
