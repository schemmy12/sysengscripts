$ErrorActionPreference = "Stop"

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$python = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"

if (-not (Test-Path -LiteralPath $python)) {
    Write-Host "Tee-time venv not found at $python" -ForegroundColor Yellow
    Write-Host "Run setup from integrations\tee_time_alerts first:" -ForegroundColor Yellow
    Write-Host "  python -m venv .venv"
    Write-Host "  .\.venv\Scripts\python -m pip install -r requirements.txt"
    exit 1
}

Write-Host "Serving Tee Time Radar at http://localhost:8000/integrations/tee_time_alerts/tee_time_dashboard.html" -ForegroundColor Green
Set-Location $repoRoot
& $python -m http.server 8000
