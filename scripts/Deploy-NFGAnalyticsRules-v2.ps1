# ============================================================
# Deploy-NFGAnalyticsRules-v2.ps1
# Nexus Financial Group — Sentinel Detection Engineering
# Author: DeM White | August 2026
# ============================================================
# Run in Azure Cloud Shell (PowerShell) as DeMWhite
# Paste entire script and press Enter
# ============================================================

$Sub  = "5051c86b-e5b4-4d98-b5e7-f49688e9e5cd"
$RG   = "rg-nexus-sentinel-lab"
$WS   = "law-nexus-sentinel"
$Base = "https://management.azure.com/subscriptions/$Sub/resourceGroups/$RG/providers/Microsoft.OperationalInsights/workspaces/$WS/providers/Microsoft.SecurityInsights/alertRules"
$Api  = "?api-version=2023-02-01"

function Deploy-Rule($Id, $Body) {
    $Uri  = "$Base/$Id$Api"
    $Json = $Body | ConvertTo-Json -Depth 20
    $Resp = Invoke-AzRestMethod -Uri $Uri -Method PUT -Payload $Json
    if ($Resp.StatusCode -in 200,201) {
        Write-Host "  DEPLOYED: $($Body.properties.displayName)" -ForegroundColor Green
    } else {
        Write-Host "  FAILED:   $($Body.properties.displayName)" -ForegroundColor Red
        Write-Host "            $($Resp.Content)" -ForegroundColor Red
    }
}

Write-Host "`nDeploying NFG Sentinel Analytics Rules..." -ForegroundColor Cyan

# NFG-001 Break Glass Sign-In
Deploy-Rule "NFG-001-break-glass-signin" @{
    kind="Scheduled"
    properties=@{
        displayName="NFG-001 — Break Glass Account Sign-In"
        description="Any sign-in by Break Glass 01 or Break Glass 02 is an emergency event or potential breach. Investigate immediately."
        severity="High"; enabled=$true
        query=@"
SigninLogs
| where UserPrincipalName in~ (
    "breakglass1@NexusFinancialGroup2.onmicrosoft.com",
    "breakglass2@NexusFinancialGroup2.onmicrosoft.com"
)
| project TimeGenerated, UserPrincipalName, IPAddress, Location, ResultType, AppDisplayName
"@
        queryFrequency="PT5M"; queryPeriod="PT5M"
        triggerOperator="GreaterThan"; triggerThreshold=0
        suppressionEnabled=$false; suppressionDuration="PT1H"
        tactics=@("InitialAccess"); techniques=@("T1078")
        incidentConfiguration=@{ createIncident=$true; groupingConfiguration=@{ enabled=$false; reopenClosedIncident=$false; lookbackDuration="PT5M"; matchingMethod="AllEntities" } }
    }
}

# NFG-002 PIM Outside Hours
Deploy-Rule "NFG-002-pim-outside-hours" @{
    kind="Scheduled"
    properties=@{
        displayName="NFG-002 — PIM Activation Outside Business Hours"
        description="Global Administrator PIM activation detected outside 08:00-18:00. Legitimate activations should occur during business hours."
        severity="Medium"; enabled=$true
        query=@"
AuditLogs
| where OperationName == "Add member to role completed (PIM activation)"
| extend ActivationHour = datetime_part("Hour", TimeGenerated)
| where ActivationHour < 8 or ActivationHour > 18
| extend InitiatedByUser = tostring(InitiatedBy.user.userPrincipalName)
| project TimeGenerated, OperationName, InitiatedByUser, TargetResources, Result, ActivationHour
"@
        queryFrequency="PT15M"; queryPeriod="PT15M"
        triggerOperator="GreaterThan"; triggerThreshold=0
        suppressionEnabled=$false; suppressionDuration="PT1H"
        tactics=@("PrivilegeEscalation"); techniques=@("T1078")
        incidentConfiguration=@{ createIncident=$true; groupingConfiguration=@{ enabled=$false; reopenClosedIncident=$false; lookbackDuration="PT5M"; matchingMethod="AllEntities" } }
    }
}

# NFG-003 Impossible Travel
Deploy-Rule "NFG-003-impossible-travel" @{
    kind="Scheduled"
    properties=@{
        displayName="NFG-003 — Impossible Travel Detection"
        description="Single user authenticated successfully from multiple geographic locations within 30 minutes. Indicates credential compromise or token theft."
        severity="High"; enabled=$true
        query=@"
SigninLogs
| where ResultType == 0
| project TimeGenerated, UserPrincipalName, IPAddress, Location
| summarize Locations = make_set(Location), IPAddresses = make_set(IPAddress), SignInCount = count()
    by UserPrincipalName, bin(TimeGenerated, 30m)
| where array_length(Locations) > 1
| project TimeGenerated, UserPrincipalName, Locations, IPAddresses, SignInCount
"@
        queryFrequency="PT30M"; queryPeriod="PT30M"
        triggerOperator="GreaterThan"; triggerThreshold=0
        suppressionEnabled=$false; suppressionDuration="PT1H"
        tactics=@("InitialAccess"); techniques=@("T1078")
        incidentConfiguration=@{ createIncident=$true; groupingConfiguration=@{ enabled=$false; reopenClosedIncident=$false; lookbackDuration="PT5M"; matchingMethod="AllEntities" } }
    }
}

# NFG-004 MFA Failure Spike
Deploy-Rule "NFG-004-mfa-failure-spike" @{
    kind="Scheduled"
    properties=@{
        displayName="NFG-004 — MFA Failure Spike"
        description="Three or more MFA failures for a single user within 15 minutes. May indicate MFA fatigue attack or compromised credentials."
        severity="Medium"; enabled=$true
        query=@"
SigninLogs
| where ResultType in ("50074", "50076", "500121")
| summarize FailureCount = count() by UserPrincipalName, bin(TimeGenerated, 15m), IPAddress
| where FailureCount >= 3
| project TimeGenerated, UserPrincipalName, IPAddress, FailureCount
"@
        queryFrequency="PT15M"; queryPeriod="PT15M"
        triggerOperator="GreaterThan"; triggerThreshold=0
        suppressionEnabled=$false; suppressionDuration="PT1H"
        tactics=@("CredentialAccess"); techniques=@("T1621")
        incidentConfiguration=@{ createIncident=$true; groupingConfiguration=@{ enabled=$false; reopenClosedIncident=$false; lookbackDuration="PT5M"; matchingMethod="AllEntities" } }
    }
}

# NFG-005 Brute Force Success
Deploy-Rule "NFG-005-brute-force-success" @{
    kind="Scheduled"
    properties=@{
        displayName="NFG-005 — Brute Force: Failures Followed By Success"
        description="Five or more failed sign-in attempts followed by a successful authentication for the same user within one hour."
        severity="High"; enabled=$true
        query=@"
let Failures = SigninLogs
| where ResultType != 0
| summarize FailCount = count() by UserPrincipalName, bin(TimeGenerated, 1h);
let Successes = SigninLogs
| where ResultType == 0
| project UserPrincipalName, SuccessTime = TimeGenerated, IPAddress;
Failures
| join kind=inner Successes on UserPrincipalName
| where FailCount >= 5
| project UserPrincipalName, FailCount, SuccessTime, IPAddress
"@
        queryFrequency="PT30M"; queryPeriod="PT1H"
        triggerOperator="GreaterThan"; triggerThreshold=0
        suppressionEnabled=$false; suppressionDuration="PT1H"
        tactics=@("CredentialAccess"); techniques=@("T1110")
        incidentConfiguration=@{ createIncident=$true; groupingConfiguration=@{ enabled=$false; reopenClosedIncident=$false; lookbackDuration="PT5M"; matchingMethod="AllEntities" } }
    }
}

# NFG-006 New Country Sign-In
Deploy-Rule "NFG-006-new-country-signin" @{
    kind="Scheduled"
    properties=@{
        displayName="NFG-006 — Sign-In From Outside United States"
        description="Successful authentication from a non-US location. NFG operates US-only. Non-US success indicates CA-004 bypass or break glass use."
        severity="Medium"; enabled=$true
        query=@"
SigninLogs
| where ResultType == 0
| where Location !in ("US", "")
| project TimeGenerated, UserPrincipalName, IPAddress, Location, AppDisplayName
"@
        queryFrequency="PT1H"; queryPeriod="PT1H"
        triggerOperator="GreaterThan"; triggerThreshold=0
        suppressionEnabled=$false; suppressionDuration="PT1H"
        tactics=@("InitialAccess"); techniques=@("T1078")
        incidentConfiguration=@{ createIncident=$true; groupingConfiguration=@{ enabled=$false; reopenClosedIncident=$false; lookbackDuration="PT5M"; matchingMethod="AllEntities" } }
    }
}

# NFG-007 CA Policy Modified
Deploy-Rule "NFG-007-ca-policy-modified" @{
    kind="Scheduled"
    properties=@{
        displayName="NFG-007 — Conditional Access Policy Modified"
        description="Conditional Access policy created, updated, or deleted. Unauthorized modification could remove MFA requirements or open geographic access."
        severity="High"; enabled=$true
        query=@"
AuditLogs
| where OperationName in (
    "Add conditional access policy",
    "Update conditional access policy",
    "Delete conditional access policy"
)
| extend InitiatedByUser = tostring(InitiatedBy.user.userPrincipalName)
| project TimeGenerated, OperationName, InitiatedByUser, TargetResources, Result
"@
        queryFrequency="PT15M"; queryPeriod="PT15M"
        triggerOperator="GreaterThan"; triggerThreshold=0
        suppressionEnabled=$false; suppressionDuration="PT1H"
        tactics=@("DefenseEvasion"); techniques=@("T1556")
        incidentConfiguration=@{ createIncident=$true; groupingConfiguration=@{ enabled=$false; reopenClosedIncident=$false; lookbackDuration="PT5M"; matchingMethod="AllEntities" } }
    }
}

# NFG-008 Global Admin Assigned Outside PIM
Deploy-Rule "NFG-008-global-admin-outside-pim" @{
    kind="Scheduled"
    properties=@{
        displayName="NFG-008 — Global Admin Role Assigned Outside PIM"
        description="Global Administrator role assignment not initiated through PIM. All Tier 0 assignments must go through PIM approval workflow."
        severity="High"; enabled=$true
        query=@"
AuditLogs
| where OperationName == "Add member to role"
| where TargetResources has "Global Administrator"
| extend InitiatedByUser = tostring(InitiatedBy.user.userPrincipalName)
| where InitiatedByUser !contains "Microsoft.Azure.ActiveDirectory.PIM"
| project TimeGenerated, OperationName, InitiatedByUser, TargetResources, Result
"@
        queryFrequency="PT15M"; queryPeriod="PT15M"
        triggerOperator="GreaterThan"; triggerThreshold=0
        suppressionEnabled=$false; suppressionDuration="PT1H"
        tactics=@("PrivilegeEscalation"); techniques=@("T1098")
        incidentConfiguration=@{ createIncident=$true; groupingConfiguration=@{ enabled=$false; reopenClosedIncident=$false; lookbackDuration="PT5M"; matchingMethod="AllEntities" } }
    }
}

# NFG-009 Guest Bulk Sign-In
Deploy-Rule "NFG-009-guest-bulk-signin" @{
    kind="Scheduled"
    properties=@{
        displayName="NFG-009 — Guest Account Bulk Sign-In Activity"
        description="Five or more successful sign-ins from a single guest account within 30 minutes. May indicate compromised vendor credentials."
        severity="Medium"; enabled=$true
        query=@"
SigninLogs
| where UserType == "Guest"
| where ResultType == 0
| summarize SignInCount = count() by UserPrincipalName, bin(TimeGenerated, 30m), IPAddress
| where SignInCount >= 5
| project TimeGenerated, UserPrincipalName, IPAddress, SignInCount
"@
        queryFrequency="PT30M"; queryPeriod="PT30M"
        triggerOperator="GreaterThan"; triggerThreshold=0
        suppressionEnabled=$false; suppressionDuration="PT1H"
        tactics=@("InitialAccess"); techniques=@("T1078")
        incidentConfiguration=@{ createIncident=$true; groupingConfiguration=@{ enabled=$false; reopenClosedIncident=$false; lookbackDuration="PT5M"; matchingMethod="AllEntities" } }
    }
}

# NFG-010 Bulk Audit Operations
Deploy-Rule "NFG-010-bulk-audit-operations" @{
    kind="Scheduled"
    properties=@{
        displayName="NFG-010 — Bulk Audit Operations — Insider Manipulation Signal"
        description="Single user performs 10+ update/delete operations within 30 minutes. Matches Firefly III insider threat pattern from Project 2 threat model."
        severity="High"; enabled=$true
        query=@"
AuditLogs
| where OperationName has_any ("Update", "Delete", "Modify")
| extend InitiatedByUser = tostring(InitiatedBy.user.userPrincipalName)
| where isnotempty(InitiatedByUser)
| summarize OperationCount = count(), Operations = make_set(OperationName)
    by InitiatedByUser, bin(TimeGenerated, 30m)
| where OperationCount >= 10
| project TimeGenerated, InitiatedByUser, OperationCount, Operations
"@
        queryFrequency="PT30M"; queryPeriod="PT30M"
        triggerOperator="GreaterThan"; triggerThreshold=0
        suppressionEnabled=$false; suppressionDuration="PT1H"
        tactics=@("Impact"); techniques=@("T1565")
        incidentConfiguration=@{ createIncident=$true; groupingConfiguration=@{ enabled=$false; reopenClosedIncident=$false; lookbackDuration="PT5M"; matchingMethod="AllEntities" } }
    }
}

Write-Host "`nDone." -ForegroundColor Cyan
