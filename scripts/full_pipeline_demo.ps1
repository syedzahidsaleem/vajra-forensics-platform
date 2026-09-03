<#
.SYNOPSIS
  Vajra Digital Forensics Platform — Full Pipeline Integration Demonstration (PowerShell Runner)
.DESCRIPTION
  Launches the complete, end-to-end integration demo script inside WSL2 with elevated block-device
  read permissions, executing all 8 steps across the platform.
#>

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $ScriptDir

Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "     VAJRA DIGITAL FORENSICS PLATFORM — FULL PIPELINE INTEGRATION RUN (PS1)    " -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "Repository Root: $RepoRoot"
Write-Host "Launching: scripts/full_pipeline_demo.sh via WSL..." -ForegroundColor Yellow

# Ensure Unix line endings
(Get-Content -Path "$RepoRoot\scripts\full_pipeline_demo.sh" -Raw) -replace "`r`n", "`n" | Set-Content -Path "$RepoRoot\scripts\full_pipeline_demo.sh" -NoNewline

wsl -u root bash -c "chmod +x /mnt/d/Coding/Vajra/scripts/full_pipeline_demo.sh && /mnt/d/Coding/Vajra/scripts/full_pipeline_demo.sh"
