<# 
    Remove all Sophos endpoint components, best-effort, silently where possible.
    Tested on Win 11 with Sophos Endpoint Agent.

    Recommended:
      - Run as SYSTEM
      - Ensure tamper protection is disabled
      - Reboot after run
#>

$ErrorActionPreference = 'Stop'

# ------------------ Logging ------------------

$LogRoot = "C:\Windows\Temp\MEEC-Sophos-Migration"
if (-not (Test-Path $LogRoot)) {
    New-Item -ItemType Directory -Path $LogRoot -Force | Out-Null
}

$LogFile = Join-Path $LogRoot ("Remove-Sophos_" + $env:COMPUTERNAME + "_" + (Get-Date -Format 'yyyyMMdd_HHmmss') + ".log")

function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    $line = "[{0}] [{1}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level.ToUpper(), $Message
    Write-Host $line
    Add-Content -Path $LogFile -Value $line
}

Write-Log "==== Sophos removal script starting on $env:COMPUTERNAME ===="

# ------------------ Uninstallers ------------------

$uninstallers = @(
    "C:\Program Files\Sophos\Sophos Endpoint Agent\SophosUninstall.exe",
    "C:\Program Files\Sophos\AutoUpdate\SophosAutoUpdateUninstall.exe",
    "C:\Program Files\Sophos\Endpoint Defense\SEUninstall.exe",
    "C:\Program Files\Sophos\Endpoint Firewall\SophosFWUninstall.exe",
    "C:\Program Files\Sophos\Endpoint Self Help\SophosSHUninstall.exe",
    "C:\Program Files\Sophos\Health\SophosHealthUninstall.exe",
    "C:\Program Files\Sophos\Live Query\SophosLiveQueryUninstall.exe",
    "C:\Program Files\Sophos\Live Terminal\SophosLiveTerminalUninstall.exe",
    "C:\Program Files\Sophos\Sophos AMSI Protection\SophosAmsiUninstall.exe",
    "C:\Program Files\Sophos\Sophos Diagnostic Utility\SophosSDUninstall.exe",
    "C:\Program Files\Sophos\Sophos File Scanner\SophosFSUninstall.exe",
    "C:\Program Files\Sophos\Sophos ML Engine\SophosMELUninstall.exe",
    "C:\Program Files\Sophos\Sophos Network Threat Protection\SophosNTPUninstall.exe",
    "C:\Program Files\Sophos\Sophos Standalone Engine\SophosSSEUninstall.exe",
    "C:\Program Files\Sophos\Sophos UI\SophosUIUninstall.exe",
    "C:\Program Files (x86)\Sophos\Management Communications System\Endpoint\SophosMCSUninstall.exe"
)

foreach ($exe in $uninstallers) {

    if (Test-Path $exe) {
        Write-Log "Running: $exe"

        try {
            # 1) Try with --quiet first
            Write-Log "Attempting quiet uninstall..." "DEBUG"
            $p = Start-Process -FilePath $exe -ArgumentList "--quiet" -PassThru -WindowStyle Hidden -ErrorAction Continue
            $p.WaitForExit(600000) # wait up to 10 minutes

            if ($p.ExitCode -ne 0) {
                Write-Log "$exe returned exit code $($p.ExitCode) with --quiet. Retrying without args." "WARN"

                # 2) Retry without arguments
                $p2 = Start-Process -FilePath $exe -PassThru -WindowStyle Hidden -ErrorAction Continue
                $p2.WaitForExit(600000)
                Write-Log "$exe (no-arg) exit code: $($p2.ExitCode)"
            }
            else {
                Write-Log "$exe completed successfully with exit code 0."
            }
        }
        catch {
            Write-Log "Error running $exe : $_" "ERROR"
        }
    }
    else {
        Write-Log "Uninstaller not found (already removed?): $exe" "DEBUG"
    }
}

# ------------------ Service cleanup ------------------

Write-Log "Cleaning up any remaining Sophos services..."

try {
    $services = Get-Service *Sophos* -ErrorAction SilentlyContinue
    if ($services) {
        $services | ForEach-Object {
            try {
                Write-Log "Stopping service $($_.Name)..." "DEBUG"
                Stop-Service $_.Name -Force -ErrorAction SilentlyContinue

                Write-Log "Deleting service $($_.Name)..." "DEBUG"
                sc.exe delete $_.Name | Out-Null
            }
            catch {
                Write-Log "Failed to remove service $($_.Name): $($_.Exception.Message)" "WARN"
            }
        }
    }
    else {
        Write-Log "No Sophos services found."
    }
}
catch {
    Write-Log "Error querying Sophos services: $_" "ERROR"
}

# ------------------ Folder cleanup ------------------

Write-Log "Cleaning up leftover Sophos folders..."

$paths = @(
    "C:\Program Files\Sophos",
    "C:\Program Files (x86)\Sophos",
    "C:\ProgramData\Sophos"
)

foreach ($path in $paths) {
    if (Test-Path $path) {
        try {
            Write-Log "Removing $path ..." "INFO"
            Remove-Item -Path $path -Recurse -Force -ErrorAction Stop
        }
        catch {
            Write-Log "Could not fully remove $path : $($_.Exception.Message)" "WARN"
        }
    }
    else {
        Write-Log "Path not found (already gone): $path" "DEBUG"
    }
}

Write-Log "Sophos removal finished. A reboot is strongly recommended."
Write-Log "Log saved to: $LogFile"
Write-Log "==== Script completed on $env:COMPUTERNAME ===="

exit 0
