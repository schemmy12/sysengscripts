<#
.SYNOPSIS
  Validates Sophos migration state on a Windows endpoint.

.PARAMETER Phase
  PostUninstall  - Check that Sophos has been fully removed.
  PostInstall    - Check that the new Sophos Central agent is installed and healthy.

.NOTES
  Designed for use with MEEC "Custom Script (Computer)" configs.
  Exit code 0 = OK, 1 = Failed.
#>

param(
    [ValidateSet('PostUninstall','PostInstall')]
    [string]$Phase = 'PostInstall'
)

$ErrorActionPreference = 'Stop'

# ---------- Logging ----------
$LogRoot = 'C:\Windows\Temp\MEEC-SophosMigration'
if (-not (Test-Path $LogRoot)) {
    New-Item -ItemType Directory -Path $LogRoot -Force | Out-Null
}

$LogFile = Join-Path $LogRoot ("Test-SophosMigration_{0}_{1}.log" -f $env:COMPUTERNAME,(Get-Date -Format 'yyyyMMdd_HHmmss'))

function Write-Log {
    param(
        [string]$Message,
        [string]$Level = 'INFO'
    )
    $line = "{0} [{1}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level.ToUpper(), $Message
    Write-Host $line
    Add-Content -Path $LogFile -Value $line
}

Write-Log "Starting Sophos migration validation. Phase = $Phase"

# ---------- Helpers ----------
function Get-SophosServices {
    Get-Service | Where-Object { $_.DisplayName -like 'Sophos*' -or $_.Name -like 'Mcs*' }
}

function Test-PathSafe {
    param([string]$Path)
    try {
        return (Test-Path -Path $Path -ErrorAction Stop)
    } catch {
        Write-Log "Error testing path '$Path': $($_.Exception.Message)" 'WARN'
        return $false
    }
}

$hasError = $false

# ---------- Phase: PostUninstall ----------
if ($Phase -eq 'PostUninstall') {
    Write-Log "Running PostUninstall checks..."

    $services = Get-SophosServices
    if ($services) {
        Write-Log "Found Sophos-related services after uninstall:" 'ERROR'
        $services | ForEach-Object {
            Write-Log ("  {0} ({1}) - Status: {2}" -f $_.DisplayName,$_.Name,$_.Status) 'ERROR'
        }
        $hasError = $true
    } else {
        Write-Log "No Sophos-related services found. ✅"
    }

    $paths = @(
        'C:\Program Files\Sophos',
        'C:\Program Files (x86)\Sophos',
        'C:\ProgramData\Sophos'
    )

    foreach ($p in $paths) {
        if (Test-PathSafe $p) {
            Write-Log "Path still exists after uninstall: $p" 'WARN'
            # If you want leftover folders to be a hard failure, flip this:
            # $hasError = $true
        } else {
            Write-Log "Path not found (as expected): $p"
        }
    }
}

# ---------- Phase: PostInstall ----------
if ($Phase -eq 'PostInstall') {
    Write-Log "Running PostInstall checks..."

    # Basic presence of agent folder
    $agentPath = 'C:\Program Files\Sophos\Sophos Endpoint Agent'
    if (Test-PathSafe $agentPath) {
        Write-Log "Agent folder present: $agentPath ✅"
    } else {
        Write-Log "Agent folder NOT found: $agentPath" 'ERROR'
        $hasError = $true
    }

    # Expect at least a few Sophos services to be running
    $services = Get-SophosServices
    if (-not $services) {
        Write-Log "No Sophos-related services found post-install." 'ERROR'
        $hasError = $true
    } else {
        $running = $services | Where-Object Status -eq 'Running'
        Write-Log ("Found {0} Sophos-related services, {1} running." -f $services.Count,$running.Count)

        if ($running.Count -lt 3) {
            Write-Log "Expected more running Sophos services; check endpoint health." 'ERROR'
            $hasError = $true
        }
    }

    # Optional: confirm there are no legacy AutoUpdate folders
    $legacyPath = 'C:\Program Files (x86)\Sophos\AutoUpdate'
    if (Test-PathSafe $legacyPath) {
        Write-Log "Legacy AutoUpdate folder present: $legacyPath (may indicate old install remnants)." 'WARN'
        # Not necessarily fatal, leave as warning by default
    }
}

if ($hasError) {
    Write-Log "Validation FAILED for phase $Phase" 'ERROR'
    exit 1
} else {
    Write-Log "Validation PASSED for phase $Phase ✅"
    exit 0
}
