#requires -Version 5.1
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$projectRoot = Split-Path -Parent $PSScriptRoot
$auditScript = Join-Path $projectRoot 'Invoke-PCIntegrityAudit.ps1'
$evidenceRoot = Join-Path $projectRoot 'evidence'
$windowsPowerShell = Join-Path $env:windir 'System32\WindowsPowerShell\v1.0\powershell.exe'

if (-not (Test-Path -LiteralPath $auditScript -PathType Leaf)) {
    [Console]::Error.WriteLine('Missing audit script: ' + $auditScript)
    exit 10
}
if (-not (Test-Path -LiteralPath $windowsPowerShell -PathType Leaf)) {
    [Console]::Error.WriteLine('Windows PowerShell 5.1 was not found: ' + $windowsPowerShell)
    exit 11
}

$tokens = $null
$parseErrors = $null
$null = [System.Management.Automation.Language.Parser]::ParseFile($auditScript, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -gt 0) {
    foreach ($parseError in $parseErrors) {
        [Console]::Error.WriteLine('PARSE_ERROR line=' + $parseError.Extent.StartLineNumber + ' message=' + $parseError.Message)
    }
    exit 1
}
Write-Host 'PARSE_OK Invoke-PCIntegrityAudit.ps1'

$evidenceExistedBefore = Test-Path -LiteralPath $evidenceRoot
& $windowsPowerShell -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $auditScript -SelfTest
$selfTestExitCode = $LASTEXITCODE
if ($selfTestExitCode -ne 0) {
    [Console]::Error.WriteLine('SELFTEST_PROCESS_FAILED exit_code=' + $selfTestExitCode)
    exit 2
}
if (-not $evidenceExistedBefore -and (Test-Path -LiteralPath $evidenceRoot)) {
    [Console]::Error.WriteLine('SELFTEST_SAFETY_FAILED: self-test unexpectedly created the evidence directory.')
    exit 3
}

Write-Host 'TEST_RUNNER_OK parse=pass synthetic_checks=pass no_system_repair=verified'
exit 0
