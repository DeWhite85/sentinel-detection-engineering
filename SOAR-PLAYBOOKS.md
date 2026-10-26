# SOAR Playbooks — Nexus Financial Group

**Platform:** Azure Logic Apps (Consumption)  
**Workspace:** law-nexus-sentinel  
**Author:** DeM White | **Date:** August 2026

Three automated response playbooks deployed and attached to their corresponding analytics rules via the Sentinel automation rules API. Each playbook is triggered by a specific analytics rule alert and performs a defined containment or notification action without manual intervention.

---

## Deployment Notes

Playbooks require the **Microsoft Sentinel Automation Contributor** role granted to the Azure Security Insights service principal on each Logic App resource before automation rules can attach them. This is done via PowerShell:

```powershell
$SentinelSP = (Get-AzADServicePrincipal -DisplayName "Azure Security Insights").Id

New-AzRoleAssignment `
    -ObjectId $SentinelSP `
    -RoleDefinitionName "Microsoft Sentinel Automation Contributor" `
    -Scope "/subscriptions/{subId}/resourceGroups/{rg}/providers/Microsoft.Logic/workflows/{playbookName}"
```

Automation rules are then attached via the Sentinel REST API (`/automationRules` endpoint) — not the Defender portal UI, which has routing issues for workspaces connected to the Unified SOC Platform.

---

## NFG-PB-001 — Break Glass Alert

**Triggers on:** NFG-001 — Break Glass Account Sign-In  
**Type:** Notification  
**Response time:** Within 5 minutes of sign-in event  

**What it does:** Sends an immediate email alert to the security team when either break glass account (breakglass1 or breakglass2) authenticates. The alert includes the account name, timestamp, severity, and a clear instruction to investigate immediately.

**Logic App flow:**
```
Microsoft Sentinel Alert (trigger)
    ↓
Send email — Office 365 Outlook
    Subject: 🚨 CRITICAL — Break Glass Account Sign-In Detected
    Body: Alert details + investigate immediately instruction
```

**Why this matters:** Break glass accounts are excluded from all Conditional Access policies — including MFA and geographic blocking. A sign-in to these accounts cannot be stopped by automated controls. Human review within minutes is the only response mechanism. This playbook ensures the security team is notified immediately rather than finding the sign-in hours later in a log review.

**Automation rule:** NFG-AR-001 — attached to NFG-001, triggers on alert created.

---

## NFG-PB-002 — Disable Compromised User

**Triggers on:** NFG-005 — Brute Force: Failures Followed By Success  
**Type:** Automated containment  
**Response time:** Within minutes of alert  

**What it does:** When a successful sign-in follows five or more failures for the same user — the signature of a successful brute force attack — this playbook automatically disables the compromised user account in Entra ID. Disabling the account immediately prevents the attacker from maintaining access while the security team investigates.

**Logic App flow:**
```
Microsoft Sentinel Alert (trigger)
    ↓
Entities — Get Accounts (Microsoft Sentinel)
    Extracts account entities from the alert
    ↓
For each account
    ↓
    Update user (Azure AD)
        Account enabled: false
    ↓
    Revoke user access tokens (Azure Communication Services)
        Terminates active sessions
```

**Why this matters:** The window between a successful brute force and an attacker establishing persistence (creating backdoor accounts, exfiltrating data, modifying permissions) can be minutes. Manual response in that window is unreliable. Automated account disable closes the window immediately, giving the security team time to investigate without active attacker access.

**Tuning consideration:** This playbook takes an aggressive automated action — disabling a user account. In environments where false positives on NFG-005 are common, consider adding an approval step before the disable action or only triggering on high-confidence alerts. For NFG, the 5-failure threshold combined with a confirmed success is considered high-confidence.

**Automation rule:** NFG-AR-002 — attached to NFG-005, triggers on alert created.

---

## NFG-PB-003 — Bulk Operation Alert

**Triggers on:** NFG-010 — Bulk Audit Operations — Insider Manipulation Signal  
**Type:** Notification  
**Response time:** Within 30 minutes of detection window  

**What it does:** Sends an immediate alert to the security team when a single user performs 10 or more update/delete operations within 30 minutes in the audit log — the behavioral signature of the insider financial manipulation attack identified in the Project 2 Firefly III threat model.

**Logic App flow:**
```
Microsoft Sentinel Alert (trigger)
    ↓
Send email — Office 365 Outlook
    Subject: ⚠️ Insider Threat Signal — Bulk Audit Operations Detected
    Body: Alert details + instruction to review audit logs and cross-reference Firefly III records
```

**Why this matters:** The insider threat scenario from Project 2 showed that a Finance Manager modifying transaction records before a quarterly audit would go undetected without a SIEM alert — the changes sit in the application audit log until manual review, potentially months later. This playbook ensures the security team is notified within the same 30-minute window the attack occurs, not at the next audit cycle.

**Automation rule:** NFG-AR-003 — attached to NFG-010, triggers on alert created.

---

## Automation Rules Summary

| Rule | Playbook | Trigger condition | Action |
|---|---|---|---|
| NFG-AR-001 | NFG-PB-001-BreakGlassAlert | NFG-001 alert created | Email notification |
| NFG-AR-002 | NFG-PB-002-DisableCompromisedUser | NFG-005 alert created | Disable account + revoke sessions |
| NFG-AR-003 | NFG-PB-003-BulkOperationAlert | NFG-010 alert created | Email notification |

---

## Known Constraints

**Incident pipeline:** Automation rules trigger on alerts, not incidents. The Unified SOC Platform integration on this workspace suppresses incident generation. Automation rules are configured to trigger on alert creation (`triggersOn: Alerts`) which functions independently of the incident pipeline.

**Session revocation:** The Azure AD connector in Logic Apps does not include a native Revoke sign-in sessions action. The Azure Communication Services Identity connector's Revoke user access tokens action is used as a compensating control. For production deployments, session revocation via the Microsoft Graph API (POST /users/{id}/revokeSignInSessions) provides more complete coverage and should be implemented via an HTTP action in the Logic App.

**Email connector:** Office 365 Outlook connector requires an authenticated connection to a mailbox in the tenant. Connected to DeMWhite@NexusFinancialGroup2.onmicrosoft.com. In production, use a shared security team mailbox rather than an individual account.
