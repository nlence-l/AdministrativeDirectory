<#
.SYNOPSIS
    Isolates access and modification events for a certain folder.

.DESCRIPTION
    Reports every audited access and modification on a given folder (and its
    contents): who accessed it, what kind of access (read / write / delete),
    and when. Reads object-access events (Event ID 4663) and deletion events
    (Event ID 4660) from the Security log, keeping only those whose target
    object is inside the requested folder.

    ------------------------------------------------------------------------
    PREREQUISITES - the script returns nothing unless BOTH are configured:

      1. "Audit File System" must be enabled (Object Access category), via
         GPO-Audit or:
             auditpol /set /subcategory:"File System" /success:enable /failure:enable

      2. The target folder must have a SACL (auditing entry). Set it in
         Folder > Properties > Security > Advanced > Auditing tab, or with
         Get-Acl -Audit / Set-Acl (see project docs).
    ------------------------------------------------------------------------

.PARAMETER Path
    The folder to isolate activity for (e.g. "D:\WorkPlan").

.PARAMETER Start
    Optional start of the time window.

.PARAMETER End
    Optional end of the time window.

.PARAMETER ComputerName
    Machine whose Security log to read. Defaults to the local machine
    (use the server that hosts the folder - here, the DC).

.EXAMPLE
    .\Get-FolderActivity.ps1 -Path "D:\WorkPlan"

.EXAMPLE
    .\Get-FolderActivity.ps1 -Path "E:\Client" -Start "2026-07-30 08:00" -End "2026-07-30 18:00"
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$Path,

    [datetime]$Start,

    [datetime]$End,

    [string]$ComputerName = $env:COMPUTERNAME
)

# The AccessMask field in a 4663 event is a hex code describing the kind of
# access. Decode the common ones into readable labels.
$accessMasks = @{
    '0x1'     = 'ReadData / ListDirectory'
    '0x2'     = 'WriteData / AddFile'
    '0x4'     = 'AppendData / AddSubdirectory'
    '0x10'    = 'ReadEA'
    '0x20'    = 'WriteEA'
    '0x40'    = 'Execute / Traverse'
    '0x80'    = 'DeleteChild'
    '0x100'   = 'ReadAttributes'
    '0x200'   = 'WriteAttributes'
    '0x10000' = 'Delete'
    '0x20000' = 'ReadControl (read permissions)'
    '0x40000' = 'WriteDAC (change permissions)'
}

# 4663 = object access attempt; 4660 = object deleted
$filter = @{
    LogName = 'Security'
    Id      = @(4663, 4660)
}
if ($Start) { $filter['StartTime'] = $Start }
if ($End)   { $filter['EndTime']   = $End }

try {
    $events = Get-WinEvent -ComputerName $ComputerName -FilterHashtable $filter -ErrorAction Stop
}
catch [Exception] {
    if ($_.Exception.Message -match 'No events were found') {
        Write-Host "No object-access events found."
        Write-Host "Check that File System auditing is enabled and the folder has a SACL."
        return
    }
    throw
}

$results = foreach ($event in $events) {
    # Parse the event XML into a name -> value map of its fields
    $xml = [xml]$event.ToXml()
    $data = @{}
    foreach ($d in $xml.Event.EventData.Data) {
        $data[$d.Name] = $d.'#text'
    }

    $objectName = $data['ObjectName']
    $folderName = $Path  -replace '^[A-Za-z]:', ''
    $normalizedFolderName = $folderName -replace '/', '\'

    # Keep only events whose object is the folder or something inside it
    if (-not $objectName -or $objectName -notlike "*$normalizedFolderName*") {
         continue
    }

    $account = $data['SubjectUserName']
    $domain  = $data['SubjectDomainName']
    $mask    = $data['AccessMask']
    $process = $data['ProcessName']

    # Skip machine/system accounts to focus on real users
    if ($account -match '\$$' -or
        $account -in @('SYSTEM','LOCAL SERVICE','NETWORK SERVICE')) {
        continue
    }

    # Translate the event into a readable access description
    $accessLabel = if ($event.Id -eq 4660) {
        'Delete (object deleted)'
    }
    elseif ($accessMasks.ContainsKey($mask)) {
        $accessMasks[$mask]
    }
    else {
        $mask   # unknown mask - show the raw hex
    }

    [PSCustomObject]@{
        Time    = $event.TimeCreated
        User    = "$domain\$account"
        Access  = $accessLabel
        Object  = $objectName
        Process = $process
    }
}

if (-not $results) {
    Write-Host "No user access events found for '$Path'."
    Write-Host "Verify: (1) File System auditing is on, (2) a SACL exists on the folder,"
    Write-Host "        (3) some access has actually occurred since auditing was enabled."
    return
}

$results | Sort-Object Time | Format-Table -AutoSize