# One-command dev runner (Windows) ? starts lab :8080 + platform :8000 + real app :3000 (optional)
# Usage: powershell -ExecutionPolicy Bypass -File scripts/start_all.ps1
#        powershell -ExecutionPolicy Bypass -File scripts/start_all.ps1 -FixHeaders -PatchIdor
# Or directly: python scripts/start_all.py  (cross-platform, preferred)
param(
    [switch]$FixHeaders,
    [switch]$PatchIdor,
    [switch]$PatchSqli,
    [switch]$Ratelimit,
    [switch]$EnableFuzzing,
    [switch]$NoRealApp
)
$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent
Set-Location $root
$py = "$root\.venv\Scripts\python.exe"
if (-not (Test-Path $py)) { $py = "python" }
$args = @("scripts/start_all.py")
if ($FixHeaders) { $args += "--fix-headers" }
if ($PatchIdor) { $args += "--patch-idor" }
if ($PatchSqli) { $args += "--patch-sqli" }
if ($Ratelimit) { $args += "--ratelimit" }
if ($EnableFuzzing) { $args += "--enable-fuzzing" }
if ($NoRealApp) { $args += "--no-real-app" }
Write-Host "[start_all.ps1] delegating to: $py $($args -join ' ')" -ForegroundColor Cyan
& $py @args
exit $LASTEXITCODE
