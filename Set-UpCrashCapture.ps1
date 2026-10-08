#requires -Version 5.1
#requires -RunAsAdministrator
$ErrorActionPreference='Stop'
$run=Join-Path $PSScriptRoot ('evidence\paging-setup-'+(Get-Date -Format 'yyyyMMdd-HHmmss'))
$null=New-Item -ItemType Directory -Path $run
. (Join-Path $PSScriptRoot 'RebootReadiness.ps1')
Ensure-CrashCapturePrerequisites
Write-Host "Paging evidence: $run"
