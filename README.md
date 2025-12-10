# System Engineering Scripts Repository

This repository contains production-ready automation scripts used for
endpoint management and environment maintenance of Hillspires Manage Engine Environment.

---

## 📂 Repository Structure

## Sophos Scripts

### Remove-SophosALL-MEEC.ps1
Location: `sophos/Remove-SophosALL-MEEC.ps1`

Safely removes Sophos Endpoint from Windows machines managed by MEEC.

**What it does:**
- Runs all known Sophos uninstallers (with `--quiet` first, then no-arg fallback).
- Stops and deletes remaining `Sophos*` services.
- Deletes leftover folders from:
  - `C:\Program Files\Sophos`
  - `C:\Program Files (x86)\Sophos`
  - `C:\ProgramData\Sophos`

**Intended use:**
- Run as a **Custom Script (Computer)** in ManageEngine Endpoint Central.
- Use on Windows 10/11 devices where **Tamper Protection is already disabled**.
- Typically followed by installing the new **Nonprofit** Sophos package.



### Test-SophosMigration.ps1
Location: `sophos/Test-SophosMigration.ps1`

Validation script used during Sophos license migration.
Checks:

- Services running or removed
- Folder presence
- Sophos Central health (post-install)
- Logs results to MEEC and local log file

Supports:
`-Phase PostUninstall`
`-Phase PostInstall`

Use this script after uninstall/removal or after Non-Profit install.


