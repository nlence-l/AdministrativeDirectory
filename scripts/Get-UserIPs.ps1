<#
.SYNOPSIS
    Lists the IP addresses used by each user.

.DESCRIPTION
    Queries the Security event log for logon events (Event ID 4624, and
    optionally 4625 for failed logons) and extracts the source IP address
    from each. Groups the results by user so you can see every distinct IP
    each account has connected from, with counts and first/last seen times.

.PARAMETER Start
    Optional start of the time window.

.PARAMETER End
    Optional end of the time window.

.PARAMETER User
    Optional single user to report on (SamAccountName). If omitted, reports all users.

.PARAMETER IncludeFailed
    Also include failed logons (Event ID 4625) in the analysis.

.PARAMETER ComputerName
    Machine whose Security log to read. Defaults to the local machine.

.EXAMPLE
    .\Get-UserIPs.ps1

.EXAMPLE
    .\Get-UserIPs.ps1 -User jdoe -Start "2026-07-30 00:00" -End "2026-07-30 23:59"
#>

param(
    [datetime]$Start,

    [datetime]$End,

    [string]$User,

    [switch]$IncludeFailed,

    [string]$ComputerName = $env:COMPUTERNAME
)

# 4624 = successful logon; 4625 = failed logon (optional)
$ids = @(4624)
if ($IncludeFailed) { $ids += 4625 }

$filter = @{
    LogName = 'Security'
    Id      = $ids
}
if ($Start) { $filter['StartTime'] = $Start }
if ($End)   { $filter['EndTime']   = $End }

try {
    $events = Get-WinEvent -ComputerName $ComputerName -FilterHashtable $filter -ErrorAction Stop
}
catch [Exception] {
    if ($_.Exception.Message -match 'No events were found') {
        Write-Host "No logon events found."
        return
    }
    throw
}

$records = foreach ($event in $events) {
    $xml = [xml]$event.ToXml()
    $data = @{}
    foreach ($d in $xml.Event.EventData.Data) {
        $data[$d.Name] = $d.'#text'
    }

    $account = $data['TargetUserName']
    $ip      = $data['IpAddress']

    # Skip machine/system accounts - keep real users
    if ($account -match '\$$' -or
        $account -in @('SYSTEM','LOCAL SERVICE','NETWORK SERVICE','ANONYMOUS LOGON')) {
        continue
    }

    # Skip entries with no usable IP (local logons record "-" or ::1)
    if (-not $ip -or $ip -in @('-','::1','127.0.0.1')) {
        continue
    }

    # If a single user was requested, keep only theirs (case-insensitive)
    if ($User -and $account -ine $User) {
        continue
    }

    [PSCustomObject]@{
        User = $account
        IP   = $ip
        Time = $event.TimeCreated
    }
}

if (-not $records) {
    Write-Host "No user/IP records found."
    return
}

# Group by user + IP so each distinct pairing is one row, with counts and timespan
$results = $records |
    Group-Object User, IP |
    ForEach-Object {
        $times = $_.Group.Time | Sort-Object
        [PSCustomObject]@{
            User       = $_.Group[0].User
            IP         = $_.Group[0].IP
            Count      = $_.Count
            FirstSeen  = $times[0]
            LastSeen   = $times[-1]
        }
    }

$results | Sort-Object User, IP | Format-Table -AutoSize