<#
.SYNOPSIS
    Shows Security-log events concerning a single user between two points in time.

.DESCRIPTION
    Queries the Security event log for events involving a given user account
    within a time window. Matches the username whether the user is the actor
    (SubjectUserName) or the account acted upon (TargetUserName), so it captures
    logons, account changes, group changes, folder access, and more for that user.

.PARAMETER Username
    The account to report on (SamAccountName, e.g. "jdoe"). Matched case-insensitively.

.PARAMETER Start
    Start of the time window (e.g. "2026-07-30 08:00").

.PARAMETER End
    End of the time window (e.g. "2026-07-30 18:00").

.PARAMETER ComputerName
    Machine whose Security log to read. Defaults to the local machine.

.EXAMPLE
    .\Get-UserEvents.ps1 -Username jdoe -Start "2026-07-30 08:00" -End "2026-07-30 18:00"
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$Username,

    [Parameter(Mandatory = $true)]
    [datetime]$Start,

    [Parameter(Mandatory = $true)]
    [datetime]$End,

    [string]$ComputerName = $env:COMPUTERNAME
)

# Friendly descriptions for the security Event IDs this project cares about,
# so the output is readable instead of raw numbers.
$eventDescriptions = @{
    4624 = 'Logon'
    4625 = 'Failed logon'
    4634 = 'Logoff'
    4647 = 'User-initiated logoff'
    4648 = 'Logon with explicit credentials'
    4720 = 'User account created'
    4722 = 'User account enabled'
    4723 = 'Password change attempt'
    4724 = 'Password reset'
    4725 = 'User account disabled'
    4726 = 'User account deleted'
    4738 = 'User account changed'
    4740 = 'Account locked out'
    4767 = 'Account unlocked'
    4728 = 'Member added to security group'
    4729 = 'Member removed from security group'
    4732 = 'Member added to local group'
    4733 = 'Member removed from local group'
    4756 = 'Member added to universal group'
    4757 = 'Member removed from universal group'
    4662 = 'Directory service access'
    4663 = 'Object access attempt'
    4660 = 'Object deleted'
}

# Pull all events in the window, then filter by username in code (the username
# can live in different fields depending on the event, so we can't pre-filter it).
$filter = @{
    LogName   = 'Security'
    StartTime = $Start
    EndTime   = $End
}

try {
    $events = Get-WinEvent -ComputerName $ComputerName -FilterHashtable $filter -ErrorAction Stop
}
catch [Exception] {
    if ($_.Exception.Message -match 'No events were found') {
        Write-Host "No events found between $Start and $End."
        return
    }
    throw
}

$results = foreach ($event in $events) {
    $xml = [xml]$event.ToXml()
    $data = @{}
    foreach ($d in $xml.Event.EventData.Data) {
        $data[$d.Name] = $d.'#text'
    }

    # The user may appear as the subject (actor) or the target (acted upon)
    $subject = $data['SubjectUserName']
    $target  = $data['TargetUserName']

    if ($subject -ne $Username -and $target -ne $Username) {
        continue
    }

    $description = if ($eventDescriptions.ContainsKey([int]$event.Id)) {
        $eventDescriptions[[int]$event.Id]
    } else {
        $event.TaskDisplayName
    }

    # Note which role the user played in this event
    $role = if ($subject -eq $Username -and $target -eq $Username) { 'Self' }
            elseif ($subject -eq $Username) { 'Actor' }
            else { 'Target' }

    [PSCustomObject]@{
        Time        = $event.TimeCreated
        EventID     = $event.Id
        Description = $description
        Role        = $role
    }
}

if (-not $results) {
    Write-Host "No events found for user '$Username' between $Start and $End."
    return
}

$results | Sort-Object Time | Format-Table -AutoSize