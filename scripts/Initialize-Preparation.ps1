# Import the ActiveDirectory module
Import-Module ActiveDirectory

$domainDN = (Get-ADDomain).DistinguishedName

# Create the OUs
$ous = @("Workspace", "Administration")

foreach ($ou in $ous) {
    if (-not (Get-ADOrganizationalUnit -Filter "Name -eq '$ou'" -ErrorAction SilentlyContinue)) {
        New-ADOrganizationalUnit -Name $ou -Path $domainDN
        Write-Host "Created OU: $ou"
    } else {
        Write-Host "OU already exists, skipping: $ou"
    }
}

# Create the groups inside the OUs
$groups = @(
    "Worker",
    "Direction",
    "Secretary"
)

foreach ($group in $groups) {
    if (-not (Get-ADGroup -Filter "Name -eq '$group'" -ErrorAction SilentlyContinue)) {
        New-ADGroup -Name $group -GroupScope Global -GroupCategory Security -Path "OU=Workspace,$domainDN"
        Write-Host "Created group: $group"
    } else {
        Write-Host "Group already exists, skipping: $group"
    }
}

if (-not (Get-ADGroup -Filter "Name -eq 'Administrator'" -ErrorAction SilentlyContinue)) {
    New-ADGroup -Name "Administrator" -GroupScope Global -GroupCategory Security -Path "OU=Administration,$domainDN"
    Write-Host "Created group: Administrator"
} else {
    Write-Host "Group already exists, skipping: Administrator"
}

# Create the disks
# Shrink C: to free ~7GB for D: and E:
if (-not (Get-Volume -DriveLetter D -ErrorAction SilentlyContinue) -and
    -not (Get-Volume -DriveLetter E -ErrorAction SilentlyContinue)) {
    Resize-Partition -DriveLetter C -Size 24GB
}

if (-not (Get-Volume -DriveLetter D -ErrorAction SilentlyContinue)) {
    New-Partition -DiskNumber 0 -Size 3GB -DriveLetter D |
        Format-Volume -FileSystem NTFS -NewFileSystemLabel "Data" -Confirm:$false
    Write-Host "Created disk D:"
}

if (-not (Get-Volume -DriveLetter E -ErrorAction SilentlyContinue)) {
    New-Partition -DiskNumber 0 -Size 3GB -DriveLetter E |
        Format-Volume -FileSystem NTFS -NewFileSystemLabel "Data2" -Confirm:$false
    Write-Host "Created disk E:"
}

# Create the folders
$folders = @(
    "D:\WorkPlan",
    "D:\Management",
    "E:\HumanResources",
    "E:\Estimate",
    "E:\Client"
)

foreach ($folder in $folders) {
    if (-not (Test-Path $folder)) {
        New-Item -Path $folder -ItemType Directory | Out-Null
        Write-Host "Created folder: $folder"
    } else {
        Write-Host "Folder already exists, skipping: $folder"
    }
}