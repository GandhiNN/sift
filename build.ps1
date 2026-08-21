<#
.SYNOPSIS
    Build script for sift (PowerShell equivalent of Makefile)
.PARAMETER Target
    Build target: build, clean, test, lint, tidy, install, fmt, run, all
.PARAMETER Args
    Additional arguments to pass to the build target
#>
param(
    [Parameter(Position = 0)]
    [ValidateSet("build", "clean", "test", "lint", "tidy", "install", "fmt", "run", "all")]
    [string]$Target = "build",
    [Parameter(Position = 1, ValueFromRemainingArguments = $true)]
    [string[]]$ExtraArgs
)

$ErrorActionPreference = "Stop"

# Version info
$Version = (git describe --tags --always --dirty 2>$null)
if (-not $Version) {
    $Version = "dev"
}
$Commit = (git rev-parse --short HEAD 2>$null)
if (-not $Commit) {
    $Commit = "unknown"
}
$Date = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

$Binary = ".\bin\sift.exe"
$LDFlags = "-s -w -X main.version=$Version -X main.commit=$Commit -X main.date=$Date"

function Invoke-Build {
    if (-not (Test-Path ".\bin")) {
        New-Item -ItemType Directory -Path ".\bin" | Out-Null
    }
    Write-Host "Building sift $Version ($Commit) at $Date" -ForegroundColor Cyan
    go build -ldflags "$LDFlags" -o $Binary .
    if ($LASTEXITCODE -ne 0) { throw "Build failed" }
    Write-Host "Built: $Binary" -ForegroundColor Green
}

function Invoke-Clean {
    if (Test-Path "bin") { Remove-Item -Recurse -Force "bin" }
    Write-Host "Cleaned." -ForegroundColor Green
}

function Invoke-Test {
    Write-Host "Running tests..." -ForegroundColor Cyan
    go test ./...
    if ($LASTEXITCODE -ne 0) { throw "Tests failed" }
}

function Invoke-Lint {
    Write-Host "Running vet..." -ForegroundColor Cyan
    go vet ./...
    if ($LASTEXITCODE -ne 0) { throw "Vet failed" }
}

function Invoke-Tidy {
    go mod tidy
    if ($LASTEXITCODE -ne 0) { throw "Tidy failed" }
}

function Invoke-Install {
    Invoke-Build
    $installDir = Join-Path $env:USERPROFILE ".local\bin"
    if (-not (Test-Path $installDir)) {
        New-Item -ItemType Directory -Path $installDir -Force | Out-Null
    }
    Write-Host "Installing sift..." -ForegroundColor Cyan
    Copy-Item $Binary (Join-Path $installDir "sift.exe") -Force
    Write-Host "Installed sift to $installDir\sift.exe" -ForegroundColor Green
    Write-Host "Make sure $installDir is in your PATH." -ForegroundColor Yellow
}

function Invoke-Fmt {
    Write-Host "Running gofmt..." -ForegroundColor Cyan
    go fmt ./...
    if ($LASTEXITCODE -ne 0) { throw "gofmt failed" }
}

function Invoke-Run {
    $runArgs = @("-ldflags", "$LDFlags", ".")
    if ($ExtraArgs) {
        $runArgs += $ExtraArgs
    }
    go run @runArgs
}

function Invoke-All {
    Invoke-Tidy
    Invoke-Lint
    Invoke-Test
    Invoke-Build
}

# Dispatch
switch ($Target) {
    "build" { Invoke-Build }
    "clean" { Invoke-Clean }
    "test" { Invoke-Test }
    "lint" { Invoke-Lint }
    "tidy" { Invoke-Tidy }
    "install" { Invoke-Install }
    "fmt" { Invoke-Fmt }
    "run" { Invoke-Run }
    "all" { Invoke-All }
    default { throw "Unknown target: $Target" }
}