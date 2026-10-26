# KQL Detection Library — Nexus Financial Group

**Workspace:** law-nexus-sentinel  
**Tenant:** NexusFinancialGroup2.onmicrosoft.com  
**Author:** DeM White | **Date:** August 2026

All rules deployed via `Deploy-NFGAnalyticsRules-v2.ps1`. Each rule includes the KQL query, scheduling, MITRE ATT&CK mapping, and tuning notes.

---

## NFG-001 — Break Glass Account Sign-In

**Severity:** High  
**Schedule:** Every 5 minutes | Lookback: 5 minutes  
**MITRE ATT&CK:** T1078 — Valid Accounts  
**Data source:** SigninLogs

**Why this rule exists:** Break glass accounts are emergency-only credentials excluded from all Conditional Access policies. Any sign-in is either a genuine emergency or a breach. There is no legitimate routine use case. This rule should fire and be investigated every time without exception.

```kql
SigninLogs
| where UserPrincipalName in~ (
    "breakglass1@NexusFinancialGroup2.onmicrosoft.com",
    "breakglass2@NexusFinancialGroup2.onmicrosoft.com"
)
| project TimeGenerated, UserPrincipalName, IPAddress,
    Location, ResultType, AppDisplayName
```

**Tuning notes:** No tuning — zero tolerance. Every result is a true positive requiring immediate investigation.

**Playbook:** NFG-PB-001-BreakGlassAlert fires on this rule.

---

## NFG-002 — PIM Activation Outside Business Hours

**Severity:** Medium  
**Schedule:** Every 15 minutes | Lookback: 15 minutes  
**MITRE ATT&CK:** T1078 — Valid Accounts  
**Data source:** AuditLogs

**Why this rule exists:** Legitimate Global Administrator PIM activations occur during business hours for planned maintenance or incident response. Activations at 2am are a signal worth investigating — either an after-hours incident (which should also generate a ticket) or unauthorized privilege escalation.

```kql
AuditLogs
| where OperationName == "Add member to role completed (PIM activation)"
| extend ActivationHour = datetime_part("Hour", TimeGenerated)
| where ActivationHour < 8 or ActivationHour > 18
| extend InitiatedByUser = tostring(InitiatedBy.user.userPrincipalName)
| project TimeGenerated, OperationName, InitiatedByUser,
    TargetResources, Result, ActivationHour
```

**Tuning notes:** Adjust the hour thresholds (< 8 and > 18) to match actual business hours. Add suppression for known maintenance windows if recurring false positives occur.

---

## NFG-003 — Impossible Travel Detection

**Severity:** High  
**Schedule:** Every 30 minutes | Lookback: 30 minutes  
**MITRE ATT&CK:** T1078 — Valid Accounts  
**Data source:** SigninLogs

**Why this rule exists:** A user cannot physically authenticate from New York and London within 30 minutes. Multiple successful sign-ins from different geographic locations in a short window indicates either credential compromise, token theft, or VPN abuse. All three warrant investigation.

```kql
SigninLogs
| where ResultType == 0
| project TimeGenerated, UserPrincipalName, IPAddress, Location
| summarize Locations = make_set(Location),
    IPAddresses = make_set(IPAddress),
    SignInCount = count()
    by UserPrincipalName, bin(TimeGenerated, 30m)
| where array_length(Locations) > 1
| project TimeGenerated, UserPrincipalName, Locations,
    IPAddresses, SignInCount
```

**Tuning notes:** Users connecting via split-tunnel VPN may show multiple locations. Add known VPN exit node IPs to an exclusion watchlist if false positive rate is high. Consider filtering to only flag location pairs that are geographically implausible rather than any two locations.

---

## NFG-004 — MFA Failure Spike

**Severity:** Medium  
**Schedule:** Every 15 minutes | Lookback: 15 minutes  
**MITRE ATT&CK:** T1621 — Multi-Factor Authentication Request Generation  
**Data source:** SigninLogs

**Why this rule exists:** Three or more MFA failures for a single user in 15 minutes is the signature of an MFA fatigue attack — an attacker with valid credentials repeatedly sending push notifications hoping the user approves one out of frustration. It also catches brute force attempts against the MFA layer specifically.

Result codes covered:
- 50074 — Strong auth required
- 50076 — Strong auth required (sign-in interrupt)  
- 500121 — Authentication failed during strong authentication request

```kql
SigninLogs
| where ResultType in ("50074", "50076", "500121")
| summarize FailureCount = count()
    by UserPrincipalName, bin(TimeGenerated, 15m), IPAddress
| where FailureCount >= 3
| project TimeGenerated, UserPrincipalName, IPAddress, FailureCount
```

**Tuning notes:** Threshold of 3 is aggressive — tune up to 5 if legitimate MFA failures are common in the environment. Consider adding a whitelist for known helpdesk IPs that may generate MFA prompts during enrollment.

---

## NFG-005 — Brute Force: Failures Followed By Success

**Severity:** High  
**Schedule:** Every 30 minutes | Lookback: 1 hour  
**MITRE ATT&CK:** T1110 — Brute Force  
**Data source:** SigninLogs

**Why this rule exists:** Five or more failed authentication attempts followed by a successful sign-in for the same user is the clearest indicator of a successful credential brute force attack. The success after failures is what makes this high severity — the attacker got in.

```kql
let Failures = SigninLogs
| where ResultType != 0
| summarize FailCount = count()
    by UserPrincipalName, bin(TimeGenerated, 1h);
let Successes = SigninLogs
| where ResultType == 0
| project UserPrincipalName, SuccessTime = TimeGenerated, IPAddress;
Failures
| join kind=inner Successes on UserPrincipalName
| where FailCount >= 5
| project UserPrincipalName, FailCount, SuccessTime, IPAddress
```

**Tuning notes:** The join is time-unbound — failures and success in the same 1-hour bucket. If the lookback window generates too many joins, add a time filter so success must occur after failures. Threshold of 5 can be raised to 10 for environments with frequent legitimate failure patterns (expired passwords, legacy auth clients).

**Playbook:** NFG-PB-002-DisableCompromisedUser fires on this rule.

---

## NFG-006 — Sign-In From Outside United States

**Severity:** Medium  
**Schedule:** Every 1 hour | Lookback: 1 hour  
**MITRE ATT&CK:** T1078 — Valid Accounts  
**Data source:** SigninLogs

**Why this rule exists:** Nexus Financial Group has no international operations. A successful authentication from outside the US means either CA-004 was bypassed (which would be a separate high-severity finding), a break glass account was used (covered by NFG-001), or a legitimate user is traveling and authenticated via VPN. All three cases should be reviewed.

```kql
SigninLogs
| where ResultType == 0
| where Location !in ("US", "")
| project TimeGenerated, UserPrincipalName,
    IPAddress, Location, AppDisplayName
```

**Tuning notes:** If executive travel is common, add a watchlist of approved international locations and exclude them. Empty location strings are excluded to avoid false positives from private IP sign-ins.

---

## NFG-007 — Conditional Access Policy Modified

**Severity:** High  
**Schedule:** Every 15 minutes | Lookback: 15 minutes  
**MITRE ATT&CK:** T1556 — Modify Authentication Process  
**Data source:** AuditLogs

**Why this rule exists:** Conditional Access policies are the primary enforcement layer for MFA, device compliance, and geographic restrictions. An unauthorized modification — disabling MFA for all users, removing geographic blocking — would immediately weaken the entire security posture. Any change to CA policy should be a known, approved change with a ticket.

```kql
AuditLogs
| where OperationName in (
    "Add conditional access policy",
    "Update conditional access policy",
    "Delete conditional access policy"
)
| extend InitiatedByUser = tostring(InitiatedBy.user.userPrincipalName)
| project TimeGenerated, OperationName,
    InitiatedByUser, TargetResources, Result
```

**Tuning notes:** In environments with active CA policy development, add a suppression list of approved change windows or a change ticket field. In steady-state environments like NFG, any result here should be treated as high priority until confirmed authorized.

---

## NFG-008 — Global Admin Role Assigned Outside PIM

**Severity:** High  
**Schedule:** Every 15 minutes | Lookback: 15 minutes  
**MITRE ATT&CK:** T1098 — Account Manipulation  
**Data source:** AuditLogs

**Why this rule exists:** All Tier 0 role assignments at NFG must go through PIM — requiring justification, approval, and time-limiting. A direct role assignment bypasses all three controls. This is either a misconfiguration or an attacker who has compromised an admin account and is establishing persistence by granting themselves standing Global Admin access.

```kql
AuditLogs
| where OperationName == "Add member to role"
| where TargetResources has "Global Administrator"
| extend InitiatedByUser = tostring(InitiatedBy.user.userPrincipalName)
| where InitiatedByUser !contains "Microsoft.Azure.ActiveDirectory.PIM"
| project TimeGenerated, OperationName,
    InitiatedByUser, TargetResources, Result
```

**Tuning notes:** The filter excludes PIM-initiated assignments. If other automated systems legitimately assign Global Admin (unlikely), add their service principal names to the exclusion filter. Validate during simulation that PIM-initiated assignments correctly do not trigger this rule — confirmed in testing (PIM logged as "Add eligible member to role" not "Add member to role").

---

## NFG-009 — Guest Account Bulk Sign-In Activity

**Severity:** Medium  
**Schedule:** Every 30 minutes | Lookback: 30 minutes  
**MITRE ATT&CK:** T1078 — Valid Accounts  
**Data source:** SigninLogs

**Why this rule exists:** Guest accounts at NFG are vendor and auditor B2B accounts with JIT access and 1-hour session limits. Five or more successful sign-ins from a single guest account in 30 minutes is abnormal for this access pattern — it may indicate compromised vendor credentials being used for automated access or data enumeration.

```kql
SigninLogs
| where UserType == "Guest"
| where ResultType == 0
| summarize SignInCount = count()
    by UserPrincipalName, bin(TimeGenerated, 30m), IPAddress
| where SignInCount >= 5
| project TimeGenerated, UserPrincipalName,
    IPAddress, SignInCount
```

**Tuning notes:** Threshold of 5 may generate false positives for guest accounts with active integrations. Review the baseline sign-in frequency for each guest account before adjusting the threshold. Consider narrowing to specific high-risk guest accounts (vendors with full system access) rather than all guest users.

---

## NFG-010 — Bulk Audit Operations — Insider Manipulation Signal

**Severity:** High  
**Schedule:** Every 30 minutes | Lookback: 30 minutes  
**MITRE ATT&CK:** T1565 — Data Manipulation  
**Data source:** AuditLogs

**Why this rule exists:** This rule directly implements the detection gap identified in the Project 2 Firefly III threat model. Attack Scenario 2 documented a Finance Manager modifying transaction records via the REST API before a quarterly audit — rapid bulk updates in a short window. Ten or more update/delete operations by a single user in 30 minutes is the behavioral signature of that attack pattern.

```kql
AuditLogs
| where OperationName has_any ("Update", "Delete", "Modify")
| extend InitiatedByUser = tostring(InitiatedBy.user.userPrincipalName)
| where isnotempty(InitiatedByUser)
| summarize OperationCount = count(),
    Operations = make_set(OperationName)
    by InitiatedByUser, bin(TimeGenerated, 30m)
| where OperationCount >= 10
| project TimeGenerated, InitiatedByUser,
    OperationCount, Operations
```

**Tuning notes:** Threshold of 10 is a starting point. In environments with legitimate bulk operations (imports, migrations), tune upward or add a filter for specific OperationName values. The `make_set(OperationName)` output in alerts shows exactly which operations fired the rule — use this to differentiate legitimate bulk imports from targeted record manipulation.

**Playbook:** NFG-PB-003-BulkOperationAlert fires on this rule.

---

## Deployment

All rules deployed via PowerShell in a single script execution:

```powershell
# Azure Cloud Shell — PowerShell mode
# Authenticated as DeMWhite@NexusFinancialGroup2.onmicrosoft.com
./Deploy-NFGAnalyticsRules-v2.ps1
```

The script uses the Azure REST API (`Invoke-AzRestMethod`) with the Cloud Shell session token. No separate Graph or Sentinel SDK required.

---

## Known Constraints

**Subtechnique format:** The Sentinel API (version 2023-02-01) rejects subtechnique IDs in T####.### format. All techniques in this library use parent technique format only (T1078 not T1078.004).

**Incident pipeline:** Alert and incident generation is suppressed on workspaces connected to the Unified Security Operations Platform. Raw events are confirmed in the underlying log tables. Alert pipeline remediation requires disconnecting from the Unified SOC Platform.

**SigninLogs table name:** This workspace uses `SigninLogs` (lowercase i). Queries using `SignInLogs` (capital I) return a semantic error.
