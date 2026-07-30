<#
.SYNOPSIS
    Lists users who connected (logged on) between two points in time.

.DESCRIPTION
    Queries the Security event log for logon events (Event ID 4624) within a
    given time window and reports which accounts connected, when, the logon
    type, and the source workstation/IP where available.

.PARAMETER Start
    Start of the time window (e.g. "2026-07-30 08:00").

.PARAMETER End
    End of the time window (e.g. "2026-07-30 18:00").

.PARAMETER ComputerName
    Machine whose Security log to read. Defaults to the local machine.

.EXAMPLE
    .\Get-ConnectedUsers.ps1 -Start "2026-07-30 08:00" -End "2026-07-30 18:00"
#>

param(
    [Parameter(Mandatory = $true)]
    [datetime]$Start,

    [Parameter(Mandatory = $true)]
    [datetime]$End,

    [string]$ComputerName = $env:COMPUTERNAME
)

# Human-readable labels for the logon type code carried in each 4624 event
$logonTypes = @{
    2  = "Interactive"
    3  = "Network"
    4  = "Batch"
    5  = "Service"
    7  = "Unlock"
    8  = "NetworkCleartext"
    9  = "NewCredentials"
    10 = "RemoteInteractive"
    11 = "CachedInteractive"
}

# Build the filter: Security log, Event ID 4624 (successful logon), within the window
$filter = @{
    LogName   = 'Security'
    Id        = 4624
    StartTime = $Start
    EndTime   = $End
}

try {
    $events = Get-WinEvent -ComputerName $ComputerName -FilterHashtable $filter -ErrorAction Stop
}
catch [Exception] {
    if ($_.Exception.Message -match 'No events were found') {
        Write-Host "No logon events found between $Start and $End."
        return
    }
    throw
}

$results = foreach ($event in $events) {
    # Parse the event's XML to pull named fields reliably
    $xml = [xml]$event.ToXml()
    $data = @{}
    foreach ($d in $xml.Event.EventData.Data) {
        $data[$d.Name] = $d.'#text'
    }

    $account = $data['TargetUserName']
    $domain  = $data['TargetDomainName']
    $type    = [int]$data['LogonType']
    $srcIp   = $data['IpAddress']
    $srcHost = $data['WorkstationName']

    # Skip system/computer accounts and machine logons - keep real user logons
    if ($account -match '\$$' -or
        $account -in @('SYSTEM','LOCAL SERVICE','NETWORK SERVICE','ANONYMOUS LOGON')) {
        continue
    }

    [PSCustomObject]@{
        Time        = $event.TimeCreated
        User        = "$domain\$account"
        LogonType   = if ($logonTypes.ContainsKey($type)) { $logonTypes[$type] } else { $type }
        SourceIP    = if ($srcIp -and $srcIp -ne '-') { $srcIp } else { '' }
        SourceHost  = $srcHost
    }
}

if (-not $results) {
    Write-Host "No user logon events found between $Start and $End."
    return
}

$results | Sort-Object Time | Format-Table -AutoSize