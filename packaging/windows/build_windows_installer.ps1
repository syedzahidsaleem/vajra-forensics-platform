# ============================================================================
# Vajra Platform — Windows Installer Build Automation Script
# ============================================================================

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$rootDir = (Get-Item "$scriptDir\..\..").FullName

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Building Vajra Windows NSIS Installer Package" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

# 1. Verify / Locate NSIS Compiler
$makensis = Get-Command makensis.exe -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source
if (-not $makensis) {
    $candidates = @(
        "$env:LOCALAPPDATA\NSIS\nsis-3.10\makensis.exe",
        "$env:LOCALAPPDATA\NSIS\nsis-3.10\Bin\makensis.exe",
        "C:\Program Files (x86)\NSIS\makensis.exe",
        "C:\Program Files\NSIS\makensis.exe"
    )
    foreach ($cand in $candidates) {
        if (Test-Path $cand) {
            $makensis = $cand
            break
        }
    }
}

if (-not $makensis) {
    Write-Error "makensis.exe (NSIS Compiler) was not found. Please install NSIS or download the portable release."
}

Write-Host "[+] Using NSIS Compiler: $makensis" -ForegroundColor Green

# 2. Compile NSIS Installer
$nsiScript = "$scriptDir\installer.nsi"
Write-Host "[+] Compiling $nsiScript..." -ForegroundColor Yellow

& $makensis $nsiScript

if ($LASTEXITCODE -ne 0) {
    Write-Error "NSIS compilation failed with exit code $LASTEXITCODE"
}

$outputInstaller = "$rootDir\target\release\Vajra-0.1.0-Setup.exe"
if (Test-Path $outputInstaller) {
    $item = Get-Item $outputInstaller
    $sizeMb = [math]::Round($item.Length / 1MB, 2)
    Write-Host "[OK] Windows Installer Successfully Generated: $outputInstaller ($sizeMb MB)" -ForegroundColor Green
} else {
    Write-Error "Expected installer output was not generated."
}
