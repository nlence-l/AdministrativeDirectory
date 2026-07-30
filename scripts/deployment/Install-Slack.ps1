$pkg = "\\42MULHO-288BSM5.domolia.local\Software\Slack.msix"
   if (-not (Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -like "*Slack*" })) {
       Add-AppxProvisionedPackage -Online -PackagePath $pkg -SkipLicense
   }