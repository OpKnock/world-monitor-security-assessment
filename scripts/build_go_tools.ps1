# Builds the two Go scanner binaries used by subprocess adapters.
# Sources are taken from a local clone if present, otherwise cloned from GitHub.
param(
    [string]$CandidatesDir = (Join-Path $PSScriptRoot "_sources\candidates")
)
$ErrorActionPreference = "Stop"

$root = Split-Path $PSScriptRoot -Parent
$bin = Join-Path $root "bin"
New-Item -ItemType Directory -Force -Path $bin | Out-Null
$CandidatesDir = [System.IO.Path]::GetFullPath($CandidatesDir)
Write-Host "Using candidates dir: $CandidatesDir"

function Build-Tool {
    param([string]$Repo, [string]$CmdPath, [string]$OutName, [object[]]$Patches = @())
    $src = [System.IO.Path]::GetFullPath((Join-Path $CandidatesDir $Repo))
    if (-not (Test-Path $src)) {
        Write-Host "Cloning $Repo ..."
        git clone --depth 1 "https://github.com/OpKnock/$Repo.git" $src
        if ($LASTEXITCODE -ne 0) { throw "git clone failed for $Repo" }
    }
    # Apply documented upstream bugfixes before building (see docs/repository-audit.md)
    foreach ($p in $Patches) {
        $file = [System.IO.Path]::GetFullPath((Join-Path $src $p.File))
        if (-not (Test-Path $file)) { throw "patch target missing: $file" }
        $text = [System.IO.File]::ReadAllText($file)
        $nl = if ($text -match "`r`n") { "`r`n" } else { "`n" }
        $patched = $text
        if ($p.Find) {
            $patched = $patched.Replace($p.Find, $p.Replace)
        }
        if ($p.InsertAfter) {
            $anchorIdx = $patched.IndexOf($p.InsertAfter)
            if ($anchorIdx -ge 0 -and -not $patched.Contains($p.Line)) {
                $insertAt = $anchorIdx + $p.InsertAfter.Length
                $patched = $patched.Insert($insertAt, $nl + "`t" + $p.Line)
            }
        }
        if ($patched -ne $text) {
            [System.IO.File]::WriteAllText($file, $patched, (New-Object System.Text.UTF8Encoding($false)))
            Write-Host "  patched $($p.File): $($p.Note)"
        }
    }
    Write-Host "Building $Repo -> bin/$OutName ..."
    Push-Location $src
    try {
        go build -trimpath -o (Join-Path $bin $OutName) $CmdPath
        if ($LASTEXITCODE -ne 0) { throw "go build failed for $Repo" }
    } finally {
        Pop-Location
    }
    Write-Host "  OK: $(Join-Path $bin $OutName)"
}

Build-Tool -Repo "secrets-scanner" -CmdPath "./cmd/portia" -OutName "portia.exe" -Patches @(
    @{
        File   = "internal/cli/root.go"
        Find   = "rootCmd.Context()"
        Replace = "context.Background()"
        Note   = "fix nil-parent context panic in signal.NotifyContext (upstream bug)"
    }
    @{
        File       = "internal/cli/root.go"
        InsertAfter = "import ("
        Line       = '"context"'
        Note       = "import context package (required by nil-parent fix)"
    }
)
Build-Tool -Repo "sbom-generator-vulnerability-matcher" -CmdPath "./cmd/bomber" -OutName "bomber.exe"
Build-Tool -Repo "supply-chain-security-analyzer" -CmdPath "./cmd/scanner" -OutName "chainscanner.exe"
Write-Host ""
Write-Host "All Go tools built."
