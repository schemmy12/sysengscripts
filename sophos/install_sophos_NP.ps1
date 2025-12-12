# Install-SophosNonProfit.ps1
# Purpose: Install Sophos Non-Profit endpoint silently with logging.
# This is meant to be run as SYSTEM via Endpoint Central.

param(
    [string]$InstallerName = "TSFFSophosSetup.exe",
    [string]$InstallerArgs = "--quiet"
)

$ErrorActionPreference = 'Stop'

# ---- Logging setup ---------------------------------------------------------
$logRoot = 'C:\Windows\Temp\MEEC-SophosNP'
if (-not (Test-Path $logRoot)) {
    New-Item -Path $logRoot -ItemType Directory -Force | Out-Null
}
$logFile = Join-Path $logRoot ("Install-SophosNP_{0}.log" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('INFO','WARN','ERROR')]
        [string]$Level = 'INFO'
    )

    $line = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    Add-Content -Path $logFile -Value $line
}

Write-Log "----- Sophos Non-Profit install starting -----"

try {
    # Where Endpoint Central drops the script + dependencies
    $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
    Write-Log "Script directory: $scriptDir"

    $exePath = Join-Path $scriptDir $InstallerName
    Write-Log "Expected installer path: $exePath"

    if (-not (Test-Path $exePath)) {
        Write-Log "Installer not found at $exePath" 'ERROR'
        exit 2
    }

    # Optional: quick pre-check for existing Sophos services (for logging only)
    $existing = Get-Service *Sophos* -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Log ("Sophos-related services detected before install: " +
                  ($existing.Name -join ', '))
    }
    else {
        Write-Log "No Sophos services detected before install."
    }

    Write-Log "Launching installer with arguments: $InstallerArgs"

    $proc = Start-Process -FilePath $exePath `
                          -ArgumentList $InstallerArgs `
                          -PassThru -Wait

    Write-Log "Installer exit code: $($proc.ExitCode)"

    if ($proc.ExitCode -ne 0) {
        Write-Log "Installer failed with non-zero exit code." 'ERROR'
        exit $proc.ExitCode
    }

    # Post-check: see if core services appeared
    Start-Sleep -Seconds 20
    $postServices = Get-Service *Sophos* -ErrorAction SilentlyContinue
    if ($postServices) {
        Write-Log ("Sophos services after install: " +
                  ($postServices.Name -join ', '))
    }
    else {
        Write-Log "No Sophos services detected after install." 'WARN'
    }

    Write-Log "Sophos Non-Profit installer completed successfully."
    exit 0
}
catch {
    Write-Log ("Unhandled error: " + $_.Exception.Message) 'ERROR'
    exit 999
}
