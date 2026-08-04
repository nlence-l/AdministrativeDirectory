<#
.SYNOPSIS
    Lists security incidents from the Security event log.

.DESCRIPTION
    Scans the Security event log for events that indicate potential security
    concerns - failed logons, account lockouts, failed object access, account
    deletions/disables, and audit-log tampering - within an optional time
    window. Each match is reported with a severity and description so the
    results can be triaged. Also summarises repeated failed logons per user,
    which can indicate a brute-force attempt.

.PARAMETER Start
    Optional start of the time window.

.PARAMETER End
    Optional end of the time window.

.PARAMETER ComputerName
    Machine whose Security log to read. Defaults to the local machine.

.EXAMPLE
    .\Get-SecurityIncidents.ps1

.EXAMPLE
    .\Get-SecurityIncidents.ps1 -Start "2026-07-30 00:00" -End "2026-07-30 23:59"
#>

param(
    [datetime]$Start,

    [datetime]$End,

    [string]$ComputerName = $env:COMPUTERNAME
)

# Event IDs treated as security incidents, with a severity and description.
$incidentTypes = @{
    4625 = @{ Severity = 'Warning';  Desc = 'Failed logon' }
    4771 = @{ Severity = 'Warning';  Desc = 'Kerberos pre-authentication failed' }
    4776 = @{ Severity = 'Warning';  Desc = 'Credential validation failed' }
    4723 = @{ Severity = 'Info';     Desc = 'Password change attempt' }
    4724 = @{ Severity = 'Warning';  Desc = 'Password reset by another account' }
    4725 = @{ Severity = 'Warning';  Desc = 'User account disabled' }
    4726 = @{ Severity = 'High';     Desc = 'User account deleted' }
    4740 = @{ Severity = 'High';     Desc = 'Account locked out' }
    4767 = @{ Severity = 'Warning';  Desc = 'Account unlocked' }
    4719 = @{ Severity = 'High';     Desc = 'System audit policy changed' }
    1102 = @{ Severity = 'Critical'; Desc = 'Security audit log was cleared' }
    4964 = @{ Severity = 'High';     Desc = 'Special privileges assigned to new logon' }
}

$ids = @($incidentTypes.Keys)

$filter = @{
    LogName = 'Security'
    Id      = $ids
}
if ($Start) { $filter['StartTime'] = $Start }
if ($End)   { $filter['EndTime']   = $End }

try {
    $events = Get-WinEvent -ComputerName $ComputerName -FilterHashtable $filter -ErrorAction Stop
}
catch {
    if ($_.Exception -is [System.Diagnostics.Eventing.Reader.EventLogNotFoundException] -or
        $_.Exception.Message -match 'No events were found') {
        Write-Host "No security incidents found."
        return
    }
    throw
}

$incidents = foreach ($event in $events) {
    $xml = [xml]$event.ToXml()
    $data = @{}
    foreach ($d in $xml.Event.EventData.Data) {
        $data[$d.Name] = $d.'#text'
    }

    $info = $incidentTypes[[int]$event.Id]

    # Account name lives in different fields depending on the event
    $account = $data['TargetUserName']
    if (-not $account) { $account = $data['SubjectUserName'] }

    $ip = $data['IpAddress']

    [PSCustomObject]@{
        Time     = $event.TimeCreated
        Severity = $info.Severity
        EventID  = $event.Id
        Incident = $info.Desc
        Account  = $account
        SourceIP = if ($ip -and $ip -notin @('-','::1','127.0.0.1')) { $ip } else { '' }
    }
}

if (-not $incidents) {
    Write-Host "No security incidents found."
    return
}

# Order severity from most to least serious for the main table
$severityRank = @{ 'Critical' = 0; 'High' = 1; 'Warning' = 2; 'Info' = 3 }

Write-Host "`n=== Security Incidents ===" -ForegroundColor Cyan
$incidents |
    Sort-Object @{ Expression = { $severityRank[$_.Severity] } }, Time |
    Format-Table -AutoSize

# Highlight possible brute-force: 5+ failed logons for the same account
Write-Host "`n=== Possible brute-force (5+ failed logons per account) ===" -ForegroundColor Cyan
$bruteForce = $incidents |
    Where-Object { $_.EventID -eq 4625 } |
    Group-Object Account |
    Where-Object { $_.Count -ge 5 } |
    ForEach-Object {
        [PSCustomObject]@{
            Account       = $_.Name
            FailedLogons  = $_.Count
            FirstAttempt  = ($_.Group.Time | Sort-Object)[0]
            LastAttempt   = ($_.Group.Time | Sort-Object)[-1]
        }
    }

if ($bruteForce) {
    $bruteForce | Sort-Object FailedLogons -Descending | Format-Table -AutoSize
} else {
    Write-Host "None detected."
}