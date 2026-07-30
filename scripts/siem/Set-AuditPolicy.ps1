# Usage: .\Set-AuditPolicy.ps1 -Category "File System" -Action Enable
param(
    [Parameter(Mandatory)][string]$Category,
    [Parameter(Mandatory)][ValidateSet('Enable','Disable')][string]$Action
)
$flag = if ($Action -eq 'Enable') { 'enable' } else { 'disable' }
auditpol /set /subcategory:"$Category" /success:$flag /failure:$flag
auditpol /get /subcategory:"$Category"   # show the result

