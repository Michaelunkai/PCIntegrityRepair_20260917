param([Parameter(Mandatory=$true)][string]$RunDirectory)
$ErrorActionPreference='Stop'
$result=Get-Content -Raw -LiteralPath (Join-Path $RunDirectory 'result.json') | ConvertFrom-Json
$gate=Get-Content -Raw -LiteralPath (Join-Path $RunDirectory 'reboot-readiness.json') | ConvertFrom-Json
$acceptance=Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot 'package-acceptance.json') | ConvertFrom-Json
$trust=@($gate.NativeChecks | Where-Object Name -Like 'Trust *')
$summary=[ordered]@{
 RecordedUtc=[datetime]::UtcNow.ToString('o')
 ActiveProject=$PSScriptRoot
 Evidence=$RunDirectory
 Integrity=$result.IntegrityOutcome
 RebootReadiness=$gate.Status
 NativePackageExitCode=$acceptance.NativeExitCode
 TestedScriptSHA256=$acceptance.SHA256
 CatalogsAddedInFinalRun=@($result.CatalogsAdded).Count
 TrustChecks=$trust.Count
 TrustChecksPassed=@($trust | Where-Object Passed -eq $true).Count
 FailedNativeChecks=@($gate.NativeChecks | Where-Object Passed -eq $false)
 AttentionItems=$gate.Issues
 PendingQueueUnchanged=$result.QueueUnchanged
 RebootPerformed=$false
 UniversalSafetyGuarantee=$false
 OriginalFilesVerifiedDuringRelocation=2485
 RecoveryCopy='C:\Users\Admin\.codex\PCIntegrityRepair_20260917.pre-move-recovery'
}
$summary | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $PSScriptRoot 'readiness-checkpoint.json') -Encoding UTF8
$summary | ConvertTo-Json -Depth 8 | Write-Output
