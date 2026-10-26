# Microsoft Sentinel — Detection Engineering Build

**Environment:** Microsoft Sentinel + Microsoft Entra ID  
**Author:** DeM White | **Date:** August 2026

This repository documents a detection engineering practice built on Microsoft Sentinel for the Nexus Financial Group environment. The work here is not a tutorial walkthrough — it's a functional detection library deployed to a live tenant, with attack simulations to validate each rule, automated response playbooks, and a security operations dashboard.

The detection gaps identified in Project 2 (Firefly III Threat Model) become the KQL rules built here. This project is a pipeline, not a standalone exercise.

---

## Why This Exists

Most security portfolios have a "built a SIEM" line that means someone turned on a tool and looked at the default dashboards. This project is different in two ways.

First, the rules are custom — 10 KQL detection rules written from scratch, each mapped to a specific MITRE ATT&CK technique, each with a documented reason for existing that traces back to either the IAM architecture built in Project 1 or the threat model built in Project 2. None of them are Microsoft's out-of-the-box templates.

Second, the deployment is automated — all 10 rules are deployed via PowerShell against the Sentinel REST API. No portal clicking. The script is in `/scripts/Deploy-NFGAnalyticsRules-v2.ps1` and deploys the full detection library in one run. That's how production security teams manage detection at scale.

---

## The Environment

Microsoft Sentinel deployed in the Nexus Financial Group tenant with Entra ID as the primary data source. Five log types connected:

- SigninLogs — every authentication attempt
- AuditLogs — all Entra ID configuration changes
- AADNonInteractiveUserSignInLogs — service and application sign-ins
- IdentityInfo — user identity and risk data
- Usage — workspace usage metrics

---

## Detection Library

10 custom KQL rules covering the highest-priority identity and insider threat vectors for a financial services environment.

| Rule | Technique | Severity | Data source |
|---|---|---|---|
| NFG-001 — Break Glass Account Sign-In | T1078 | High | SigninLogs |
| NFG-002 — PIM Activation Outside Business Hours | T1078 | Medium | AuditLogs |
| NFG-003 — Impossible Travel Detection | T1078 | High | SigninLogs |
| NFG-004 — MFA Failure Spike | T1621 | Medium | SigninLogs |
| NFG-005 — Brute Force: Failures Followed By Success | T1110 | High | SigninLogs |
| NFG-006 — Sign-In From Outside United States | T1078 | Medium | SigninLogs |
| NFG-007 — Conditional Access Policy Modified | T1556 | High | AuditLogs |
| NFG-008 — Global Admin Role Assigned Outside PIM | T1098 | High | AuditLogs |
| NFG-009 — Guest Account Bulk Sign-In Activity | T1078 | Medium | SigninLogs |
| NFG-010 — Bulk Audit Operations — Insider Manipulation Signal | T1565 | High | AuditLogs |

Full KQL for every rule is in `KQL-DETECTIONS.md`.

---

## SOAR Playbooks

Three Logic Apps deployed and attached to their corresponding analytics rules via the Sentinel automation rules API.

**NFG-PB-001 — Break Glass Alert**
Triggers on NFG-001. Sends immediate email notification to the security team when either break glass account authenticates. Any sign-in to these accounts is an emergency or a breach — the playbook fires within 5 minutes of the event.

**NFG-PB-002 — Disable Compromised User**
Triggers on NFG-005 (brute force success). Automatically disables the compromised user account in Entra ID via the Azure AD connector. Reduces the window between detection and containment from hours to minutes.

**NFG-PB-003 — Bulk Operation Alert**
Triggers on NFG-010 (insider manipulation signal). Sends an immediate alert to the security team when a single user performs 10+ update/delete operations within 30 minutes — the exact pattern identified in the Firefly III threat model as the insider financial manipulation attack chain.

Full playbook documentation is in `SOAR-PLAYBOOKS.md`.

---

## Deployment

All 10 rules deploy in a single PowerShell script run — no portal UI required.

```powershell
# Run in Azure Cloud Shell as DeMWhite@NexusFinancialGroup2
./Deploy-NFGAnalyticsRules-v2.ps1
```

The script uses `Invoke-AzRestMethod` against the Sentinel REST API with the Cloud Shell session token — no separate authentication needed. Output confirms each rule as deployed or failed with the full error response.

---

## Attack Simulations

Five simulations executed against the live tenant to validate rule coverage:

**NFG-001 — Break Glass Sign-In**
Authenticated as breakglass1@NexusFinancialGroup2.onmicrosoft.com. Raw sign-in event confirmed in SigninLogs.

**NFG-007 — CA Policy Modified**
Renamed and reverted CA-001-ALLUSERS-REQUIREMFA. Two AuditLogs events confirmed at 9:02 and 9:03 PM UTC — Update conditional access policy by DeMWhite, both success.

**NFG-008 — Global Admin Assignment**
Attempted direct Global Administrator assignment to jsmith. PIM intercepted and converted to an eligible assignment — logged as "Add eligible member to role." Rule correctly did not fire because PIM did its job. This is a true negative, not a miss.

**NFG-005 — Brute Force**
Five consecutive failed sign-in attempts against jsmith within 15 minutes. Failed authentication events confirmed in SigninLogs.

**NFG-002 — PIM Outside Hours**
Executed after 6pm — PIM activation event logged in AuditLogs outside the 08:00-18:00 business hours window.

**Known constraint:** Incident and alert generation is suppressed by the Defender XDR Unified Security Operations Platform integration on this workspace type. Raw events are confirmed in the underlying log tables — the detection logic is validated. Alert pipeline remediation requires disconnecting from the Unified SOC Platform and using classic incident creation mode.

---

## Security Operations Dashboard

Custom Azure Monitor Workbook — `NFG Security Operations Dashboard` — with four panels:

- Sign-In Activity Over Time — hourly authentication volume timechart
- Failed Sign-Ins By Location — geographic distribution of authentication failures
- PIM Activation History — all privileged role activation events with user and timestamp
- Audit Operations By User — operation volume per identity for behavioral baseline

---

## Implementation Notes

**Cross-tenant Sentinel deployment** is more complex than single-tenant. This environment has the Entra ID data in the Nexus Financial Group tenant and the Azure subscription under the DeMWhite pay-as-you-go account. The Microsoft Sentinel Analytics blade migrated to the Defender XDR portal mid-2026 — for new workspaces connected to the Unified SOC Platform, the legacy Azure portal Analytics blade redirects to Defender. All rule deployment was handled via PowerShell REST API to bypass the portal routing issue entirely.

**Subtechnique format** in the Sentinel API only accepts parent technique IDs in T#### format — subtechniques like T1078.004 are rejected with a 400 error. All techniques in this library use parent format.

**Playbook permissions** require the Microsoft Sentinel Automation Contributor role granted to the Azure Security Insights service principal on each Logic App resource before automation rules can attach playbooks. This is not documented clearly in Microsoft's official guidance.

**SigninLogs vs SignInLogs** — the table name in this workspace is `SigninLogs` (lowercase i), not `SignInLogs`. Queries using the capital I format return a semantic error.

---

## Carryover To Project 4

The CIS Azure Foundations Benchmark compliance automation project directly follows this one. The detection gaps identified here — no Identity Protection risk policies, no DDoS protection, excessive permissions — become the remediation targets in the compliance assessment. The Sentinel workspace continues running and will capture any new events generated during Project 4 work.

---

## Repository Contents

```
sentinel-detection-engineering/
├── README.md
├── KQL-DETECTIONS.md              — Full rule library with ATT&CK mapping
├── SOAR-PLAYBOOKS.md              — Playbook documentation
└── scripts/
    └── Deploy-NFGAnalyticsRules-v2.ps1    — Deploys all 10 rules via the Azure REST API
```

---

*Part of a six-project cloud security portfolio. All company names, users, and data are fictional.*
