# Starts the vulnerable lab (8080) and the platform (8000) in separate windows.
# Optional switches to demo the retest-FIXED flow:
#   -PatchIdor    ownership check enforced on /api/reports/<id>
#   -FixHeaders   strict security headers enabled
param(
    [switch]$PatchIdor,
    [switch]$FixHeaders
)
$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent
Set-Location $root

if (-not (Test-Path "$root\.venv\Scripts\python.exe")) {
    Write-Host "ERROR: .venv not found. Run setup first (see README)."
    exit 1
}

$labEnv = ""
if ($PatchIdor)  { $labEnv = "`$env:WM_LAB_PATCH_IDOR='1'; " }
if ($FixHeaders) { $labEnv = $labEnv + "`$env:WM_LAB_FIX_HEADERS='1'; " }

$labCmd = "$labEnv" + ".venv\Scripts\python.exe lab\vulnerable-world-monitor\app.py"
$appCmd = ".venv\Scripts\python.exe -m uvicorn backend.main:app --host 127.0.0.1 --port 8000"

Write-Host "Starting vulnerable lab on http://127.0.0.1:8080 $(if($labEnv){'(fix toggles ON)'})"
Start-Process powershell -ArgumentList "-NoExit", "-Command", $labCmd -WorkingDirectory $root

Start-Sleep -Seconds 2
Write-Host "Starting platform UI+API on http://127.0.0.1:8000"
Start-Process powershell -ArgumentList "-NoExit", "-Command", $appCmd -WorkingDirectory $root

Write-Host ""
Write-Host "  Platform : http://127.0.0.1:8000"
Write-Host "  Lab      : http://127.0.0.1:8080   (INTENTIONALLY VULNERABLE - localhost only)"
Write-Host "  Login    : admin@example.com / ChangeMe_Admin_2026!"
