<#
.SYNOPSIS
    Automated response to brute-force attempts found in the Security log.

.DESCRIPTION
    Scans recent failed-logon events (Event ID 4625), counts them per account,
    and for any account exceeding the threshold takes automated action:
    disables the AD account and writes an entry to a response log. This turns
    detection of repeated failed logons into an automatic containment action -
    the "response" layer a SIEM provides on top of logging.

    Intended to be run on a schedule (e.g. every few minutes via Task Scheduler)
    so it reacts to attacks shortly after they occur.

.PARAMETER Threshold
    Number of failed logons within the window that triggers a response. Default 7
    (escalation tier above the GPO's 5-failure lockout).

.PARAMETER Minutes
    How far back to look, in minutes. Default 30.

.PARAMETER LogPath
    File to append response actions to. Default C:\SIEM\response.log.

.PARAMETER WhatIf
    Report what WOULD be disabled without actually disabling anything (dry run).

.EXAMPLE
    .\Invoke-IncidentResponse.ps1

.EXAMPLE
    .\Invoke-IncidentResponse.ps1 -Threshold 3 -Minutes 30 -WhatIf
#>

param(
    [int]$Threshold = 7,

    [int]$Minutes = 30,

    [string]$LogPath = "C:\SIEM\response.log",

    [switch]$WhatIf
)

Import-Module ActiveDirectory

$start = (Get-Date).AddMinutes(-$Minutes)

# Pull recent failed logons (4625) within the window
$filter = @{
    LogName   = 'Security'
    Id        = 4625
    StartTime = $start
}

try {
    $events = Get-WinEvent -FilterHashtable $filter -ErrorAction Stop
}
catch [Exception] {
    if ($_.Exception.Message -match 'No events were found') {
        Write-Host "No failed logons in the last $Minutes minutes. Nothing to do."
        return
    }
    throw
}

# Count failures per targeted account
$failures = foreach ($event in $events) {
    $xml = [xml]$event.ToXml()
    $data = @{}
    foreach ($d in $xml.Event.EventData.Data) { $data[$d.Name] = $d.'#text' }

    $account = $data['TargetUserName']

    # Ignore machine/system accounts
    if ($account -match '\$$' -or
        $account -in @('SYSTEM','LOCAL SERVICE','NETWORK SERVICE','')) {
        continue
    }
    $account
}

$offenders = $failures |
    Group-Object |
    Where-Object { $_.Count -ge $Threshold }

if (-not $offenders) {
    Write-Host "No accounts exceeded $Threshold failed logons in the last $Minutes minutes."
    return
}

# Ensure the log directory exists
$logDir = Split-Path $LogPath -Parent
if (-not (Test-Path $logDir)) {
    New-Item -Path $logDir -ItemType Directory -Force | Out-Null
}

foreach ($offender in $offenders) {
    $account = $offender.Name
    $count   = $offender.Count
    $stamp   = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

    # Confirm the account actually exists in AD before acting
    $adUser = Get-ADUser -Filter "SamAccountName -eq '$account'" -ErrorAction SilentlyContinue
    if (-not $adUser) {
        Write-Host "Skipping '$account' - not a domain account ($count failures)."
        continue
    }

    if ($WhatIf) {
        $msg = "$stamp [DRY RUN] Would disable '$account' ($count failed logons in $Minutes min)"
    }
    else {
        Disable-ADAccount -Identity $adUser
        $msg = "$stamp [ACTION] Disabled '$account' ($count failed logons in $Minutes min)"
    }

    Write-Host $msg -ForegroundColor Yellow
    Add-Content -Path $LogPath -Value $msg
}