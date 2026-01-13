<#
.SYNOPSIS
  Pins common enterprise apps to the Windows taskbar using TaskbarLayoutModification.xml.

.NOTES
  - This is the *supported* mechanism (layout XML), but behavior varies:
      * Reliable for NEW user profiles (Default user layout).
      * For EXISTING users: may require sign-out/sign-in; may not override existing pins.
  - Run as SYSTEM (MEEC) is fine; script writes to Default profile + ProgramData.
  - If an app is missing, it will be skipped (and logged).
#>

[CmdletBinding()]
param(
  [switch]$ApplyToCurrentUser = $true,
  [switch]$RestartExplorer = $true
)

$ErrorActionPreference = "Stop"

# ---------- Logging ----------
$LogRoot = "C:\Windows\Temp\MEEC-TaskbarPins"
New-Item -ItemType Directory -Force -Path $LogRoot | Out-Null
$LogFile = Join-Path $LogRoot ("TaskbarPins_{0}.log" -f (Get-Date -Format "yyyyMMdd_HHmmss"))

function Write-Log {
  param([string]$Message, [ValidateSet("INFO","WARN","ERROR")] [string]$Level = "INFO")
  $line = "{0} [{1}] {2}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Level, $Message
  Add-Content -Path $LogFile -Value $line
  Write-Host $line
}

# ---------- Helpers ----------
function Get-CommonStartMenuProgramsPath {
  # Common Start Menu Programs (all users)
  return Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs"
}

function Ensure-Shortcut {
  <#
    Ensures a .lnk exists in the Common Start Menu Programs folder for pinning.
    If it already exists, we reuse it. If not, we create it pointing at TargetPath.
  #>
  param(
    [Parameter(Mandatory)] [string]$ShortcutRelativePath,  # e.g. "Company\Slack.lnk"
    [Parameter(Mandatory)] [string]$TargetPath,            # e.g. "C:\Program Files\...\slack.exe"
    [string]$Arguments = "",
    [string]$WorkingDirectory = ""
  )

  $base = Get-CommonStartMenuProgramsPath
  $shortcutFullPath = Join-Path $base $ShortcutRelativePath

  $shortcutDir = Split-Path $shortcutFullPath -Parent
  if (-not (Test-Path $shortcutDir)) {
    New-Item -ItemType Directory -Force -Path $shortcutDir | Out-Null
  }

  if (Test-Path $shortcutFullPath) {
    Write-Log "Shortcut exists: $shortcutFullPath"
    return $shortcutFullPath
  }

  if (-not (Test-Path $TargetPath)) {
    Write-Log "Target EXE not found; cannot create shortcut. TargetPath=$TargetPath" "WARN"
    return $null
  }

  $wsh = New-Object -ComObject WScript.Shell
  $lnk = $wsh.CreateShortcut($shortcutFullPath)
  $lnk.TargetPath = $TargetPath
  if ($Arguments) { $lnk.Arguments = $Arguments }
  if ($WorkingDirectory) { $lnk.WorkingDirectory = $WorkingDirectory }
  $lnk.Save()

  Write-Log "Created shortcut: $shortcutFullPath -> $TargetPath"
  return $shortcutFullPath
}

function Resolve-App {
  <#
    Attempts to resolve common install locations for apps.
    You can hardcode paths if your org installs differently.
  #>
  param(
    [Parameter(Mandatory)] [string]$Name
  )

  switch ($Name.ToLower()) {

    "chrome" {
      $candidates = @(
        "$env:ProgramFiles\Google\Chrome\Application\chrome.exe",
        "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe"
      )
    }

    "zoom" {
      $candidates = @(
        "$env:ProgramFiles\Zoom\bin\Zoom.exe",
        "${env:ProgramFiles(x86)}\Zoom\bin\Zoom.exe",
        "$env:AppData\Zoom\bin\Zoom.exe" # user install
      )
    }

    "slack" {
      $candidates = @(
        "$env:ProgramFiles\Slack\slack.exe",
        "${env:ProgramFiles(x86)}\Slack\slack.exe",
        "$env:LocalAppData\slack\slack.exe" # per-user
      )
    }

    "outlook" {
      $candidates = @(
        "$env:ProgramFiles\Microsoft Office\root\Office16\OUTLOOK.EXE",
        "${env:ProgramFiles(x86)}\Microsoft Office\root\Office16\OUTLOOK.EXE"
      )
    }

    "edge" {
      $candidates = @(
        "$env:SystemRoot\SystemApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\MicrosoftEdge.exe",
        "$env:ProgramFiles (x86)\Microsoft\Edge\Application\msedge.exe",
        "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe"
      )
    }

    default {
      $candidates = @()
    }
  }

  foreach ($p in $candidates) {
    if ($p -and (Test-Path $p)) {
      Write-Log "Resolved $Name -> $p"
      return $p
    }
  }

  Write-Log "Could not resolve install path for: $Name" "WARN"
  return $null
}

function New-TaskbarLayoutXml {
  param(
    [Parameter(Mandatory)] [string[]]$ShortcutPaths
  )

  # Taskbar pins use DesktopApplicationLinkPath to .lnk files.
  $pinsXml = $ShortcutPaths | ForEach-Object {
    "          <taskbar:DesktopApp DesktopApplicationLinkPath=""$($_)"" />"
  } | Out-String

  $xml = @"
<?xml version="1.0" encoding="utf-8"?>
<LayoutModificationTemplate
  xmlns="http://schemas.microsoft.com/Start/2014/LayoutModification"
  xmlns:defaultlayout="http://schemas.microsoft.com/Start/2014/FullDefaultLayout"
  xmlns:start="http://schemas.microsoft.com/Start/2014/StartLayout"
  xmlns:taskbar="http://schemas.microsoft.com/Start/2014/TaskbarLayout"
  Version="1">
  <CustomTaskbarLayoutCollection PinListPlacement="Replace">
    <defaultlayout:TaskbarLayout>
      <taskbar:TaskbarPinList>
$pinsXml      </taskbar:TaskbarPinList>
    </defaultlayout:TaskbarLayout>
  </CustomTaskbarLayoutCollection>
</LayoutModificationTemplate>
"@

  return $xml
}

function Write-LayoutFiles {
  param(
    [Parameter(Mandatory)] [string]$XmlContent
  )

  # Default profile (best for new users)
  $defaultShellDir = "C:\Users\Default\AppData\Local\Microsoft\Windows\Shell"
  New-Item -ItemType Directory -Force -Path $defaultShellDir | Out-Null
  $defaultXmlPath = Join-Path $defaultShellDir "TaskbarLayoutModification.xml"
  Set-Content -Path $defaultXmlPath -Value $XmlContent -Encoding UTF8
  Write-Log "Wrote Default profile layout XML: $defaultXmlPath"

  if ($ApplyToCurrentUser) {
    # Try to apply to existing users (may or may not override on Win11)
    # If running as SYSTEM, "current user" is SYSTEM; so we also drop it into Public as reference
    $publicShellDir = "C:\Users\Public\TaskbarLayout"
    New-Item -ItemType Directory -Force -Path $publicShellDir | Out-Null
    $publicXmlPath = Join-Path $publicShellDir "TaskbarLayoutModification.xml"
    Set-Content -Path $publicXmlPath -Value $XmlContent -Encoding UTF8
    Write-Log "Wrote a copy for reference: $publicXmlPath"

    # Attempt: apply to all existing user profiles by dropping into each profile Shell folder
    $profiles = Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue |
      Where-Object { $_.Name -notin @("Public","Default","Default User","All Users") }

    foreach ($p in $profiles) {
      $shellDir = Join-Path $p.FullName "AppData\Local\Microsoft\Windows\Shell"
      if (Test-Path $shellDir) {
        $xmlPath = Join-Path $shellDir "TaskbarLayoutModification.xml"
        try {
          Set-Content -Path $xmlPath -Value $XmlContent -Encoding UTF8
          Write-Log "Wrote layout XML for user profile $($p.Name): $xmlPath"
        } catch {
          Write-Log "Failed writing layout XML for $($p.Name): $($_.Exception.Message)" "WARN"
        }
      }
    }
  }
}

function Restart-ExplorerShell {
  if (-not $RestartExplorer) { return }
  try {
    Write-Log "Restarting Explorer..."
    Get-Process explorer -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Process explorer.exe
    Write-Log "Explorer restarted. Users may still need sign-out/sign-in for pins to update."
  } catch {
    Write-Log "Explorer restart failed: $($_.Exception.Message)" "WARN"
  }
}

# ---------- Configure your stack here ----------
# Each entry:
#   DisplayName: used for logging
#   ResolveName: used by Resolve-App (or set TargetPath directly)
#   ShortcutRelativePath: where the .lnk will be created under ProgramData Start Menu
#   TargetPath: optional; if set, used directly (preferred if you know exact exe path)
$AppsToPin = @(
  @{
    DisplayName = "Google Chrome"
    ResolveName = "chrome"
    ShortcutRelativePath = "Hillspire\Google Chrome.lnk"
    TargetPath = $null
  },
  @{
    DisplayName = "Slack"
    ResolveName = "slack"
    ShortcutRelativePath = "Hillspire\Slack.lnk"
    TargetPath = $null
  },
  @{
    DisplayName = "Zoom"
    ResolveName = "zoom"
    ShortcutRelativePath = "Hillspire\Zoom.lnk"
    TargetPath = $null
  }
)

# ---------- Main ----------
Write-Log "=== Taskbar pinning started ==="

$shortcutPathsForPins = @()

foreach ($app in $AppsToPin) {
  $target = $app.TargetPath
  if (-not $target) {
    $target = Resolve-App -Name $app.ResolveName
  }

  if (-not $target) {
    Write-Log "Skipping $($app.DisplayName) (target not found)" "WARN"
    continue
  }

  $lnk = Ensure-Shortcut -ShortcutRelativePath $app.ShortcutRelativePath -TargetPath $target
  if ($lnk) {
    # Taskbar XML expects absolute path
    $shortcutPathsForPins += $lnk
  }
}

if ($shortcutPathsForPins.Count -eq 0) {
  Write-Log "No shortcuts created/found. Nothing to pin." "ERROR"
  exit 1
}

$xml = New-TaskbarLayoutXml -ShortcutPaths $shortcutPathsForPins
Write-LayoutFiles -XmlContent $xml
Restart-ExplorerShell

Write-Log "=== Taskbar pinning completed ==="
Write-Log "Log file: $LogFile"