# Remove HP Support Assistant Appx package for all existing users
Get-AppxPackage -AllUsers |
Where-Object {
    $_.Name -like "*HPSupportAssistant*" -or
    $_.Name -eq "AD2F1837.HPSupportAssistant"
} |
ForEach-Object {
    try {
        Remove-AppxPackage -Package $_.PackageFullName -AllUsers -ErrorAction Stop
        Write-Output "Removed Appx package: $($_.Name)"
    }
    catch {
        Write-Output "Failed to remove Appx package: $($_.Name) - $($_.Exception.Message)"
    }
}

# Remove provisioned package so it does not install for new user profiles
Get-AppxProvisionedPackage -Online |
Where-Object {
    $_.DisplayName -like "*HPSupportAssistant*" -or
    $_.DisplayName -eq "AD2F1837.HPSupportAssistant"
} |
ForEach-Object {
    try {
        Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName -ErrorAction Stop
        Write-Output "Removed provisioned package: $($_.DisplayName)"
    }
    catch {
        Write-Output "Failed to remove provisioned package: $($_.DisplayName) - $($_.Exception.Message)"
    }
}