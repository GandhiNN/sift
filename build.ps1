# Windows build script for sift
param(
    [string]$output = "bin\sift.exe"
)

$ErrorActionPreference = "Stop"

$version = git describe --tags --always --dirty 2>$null
if (-not $version) { $version = "dev" }

$commit = git rev-parse --short HEAD 2>$null
if (-not $commit) { $commit = "unknown" }

$date = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

$ldflags = "-s -w -X main.version=$version -X main.commit=$commit -X main.date=$date"

Write-Host "Building sift $version ($commit) ..." -ForegroundColor Cyan

$outDir = Split-Path $Output
if ($outDir -and -not (Test-Path $outDir)) {
    New-Item -ItemType Directory -Path $outDir -Force | Out-Null
}

go build -ldflags $ldflags -o $Output .

if ($LASTEXITCODE -eq 0) {
    Write-Host "Built: $Output" -ForegroundColor Green
} else {
    Write-Host "Build failed" -ForegroundColor Red
    exit 1
}