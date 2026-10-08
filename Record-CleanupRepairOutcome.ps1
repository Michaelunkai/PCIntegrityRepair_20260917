$ErrorActionPreference='Stop'
$repair=Get-Content -Raw (Join-Path $PSScriptRoot 'readiness-checkpoint.json') | ConvertFrom-Json
$regression=Get-Content -Raw (Join-Path $PSScriptRoot 'cleanup-regression.json') | ConvertFrom-Json
if($repair.Integrity -ne 'VerifiedClean' -or $regression.FastffExitCode -ne 0){throw 'Cannot record a successful corruption repair without both live checks passing'}
$sources=@(
 'F:\study\Shells\powershell\scripts\misc\ccsizes\ccsizes-cleanup-patterns-v2.ps1',
 'F:\study\Learning\01\01\Shells\powershell\profile-functions\windows\cleanup\system-clean\CleanCSystemCleanup\Invoke-cleanc.ps1',
 'F:\study\repos\shells\powershell\fixfixfix.ps1',
 'C:\Users\Admin\Documents\WindowsPowerShell\ProfileSources\ps5-profile-portable\Microsoft.PowerShell_profile.runtime.ps1',
 'C:\Users\Admin\Documents\WindowsPowerShell\ProfileSources\ps5-profile-portable\Microsoft.PowerShell_profile.ps1',
 'C:\Users\Admin\Documents\WindowsPowerShell\ProfileSources\ps5-profile-portable\Microsoft.PowerShell_profile.full.ps1',
 'C:\Users\Admin\Documents\WindowsPowerShell\ProfileSources\ps5-profile-portable\Microsoft.PowerShell_profile.full.definitions.ps1',
 'C:\Users\Admin\Documents\WindowsPowerShell\ProfileSources\ps5-profile-portable\legacy-safe-functions\profile-wrappers.ps1'
)
$report=[ordered]@{
 RecordedUtc=[datetime]::UtcNow.ToString('o')
 Cause='fastcc -> ccsizes explicitly removed Windows catroot and CatRoot2 contents; later SFC reported 152 PnP repair failures.'
 Corrections=@('Excluded all Windows directory patterns, installer caches and crash evidence','Protected catalog/recovery trees and profile runtimes, including ancestor matches','Disabled system-root and protected-subtree cleanc sweeps','Removed forced recursive temp deletion from all ccsizes profile snapshots','Cache cleanup deletes only files older than seven days; skips reparse trees and locked files; never queues reboot deletion','fastff honors 5-30 second status intervals; servicing wait no longer capped to five seconds')
 SourceHashes=@($sources | ForEach-Object {Microsoft.PowerShell.Utility\Get-FileHash -LiteralPath $_ -Algorithm SHA256} | Select-Object Path,Hash)
 CatalogsRestored=$repair.CatalogsAddedInFinalRun
 Integrity=$repair.Integrity
 SignatureChecksPassed=$repair.TrustChecksPassed
 SignatureChecksTotal=$repair.TrustChecks
 CleanupRegression=$regression
 RebootReadiness=$repair.RebootReadiness
 UnresolvedNativeChecks=$repair.FailedNativeChecks
 AttentionItems=$repair.AttentionItems
 RebootPerformed=$false
 UniversalSafetyGuarantee=$false
}
$report | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $PSScriptRoot 'cleanup-repair-outcome.json') -Encoding UTF8
Write-Host 'Saved cleanup-repair-outcome.json: actual cleanup regression and integrity results; reboot warnings retained.'
