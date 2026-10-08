$ErrorActionPreference='Stop'
$cache='F:\study\Shells\powershell\scripts\misc\ccsizes\ccsizes-cleanup-patterns-v2.ps1'
$rootCleanup='F:\study\Learning\01\01\Shells\powershell\profile-functions\windows\cleanup\system-clean\CleanCSystemCleanup\Invoke-cleanc.ps1'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($cache,[ref]$tokens,[ref]$errors)
if($errors.Count){throw ($errors | Out-String)}
$guard=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Test-CCSizesProtectedPath'},$true)
. ([scriptblock]::Create($guard.Extent.Text))
$protectedRoots=@($env:windir,'C:\Recovery',(Join-Path $env:LOCALAPPDATA 'Codex\PowerShellFastStartup'),(Join-Path $env:USERPROFILE '.cache\codex-runtimes'))
$protectedMatches=@{}
foreach($path in @('C:\Windows','C:\Windows\System32\catroot\test.cat','C:\Windows\System32\catroot2\test','C:\Windows\Installer\test.msi','C:\Windows\Logs\CBS\CBS.log','C:\Recovery\test','C:\Users\Admin\AppData\Local\Package Cache\test','C:\Users\Admin\.cache\codex-runtimes\test')){
 if(-not (Test-CCSizesProtectedPath $path)){throw "Not protected: $path"}
}
if(Test-CCSizesProtectedPath 'C:\Users\Admin\AppData\Local\npm-cache\test'){throw 'Application cache incorrectly protected'}
$body=Get-Content -Raw -LiteralPath $cache
if($body -match 'Remove-Item[^\r\n]*-Recurse'){throw 'Recursive cache deletion remains'}
& $rootCleanup
if($LASTEXITCODE -ne 0){throw 'System-root guard failed'}
& $rootCleanup -RootPath 'C:\Windows\System32\catroot'
if($LASTEXITCODE -ne 0){throw 'Protected-subtree guard failed'}
Import-Module 'C:\Users\Admin\Documents\WindowsPowerShell\Modules\CodexProfileFunctions\CodexProfileFunctions.psd1' -Force -DisableNameChecking
$resolved=& (Get-Module CodexProfileFunctions) { Resolve-ProfileLazyFunction -Name ccsizes }
if(($resolved | Out-String) -match '\bffrm\b'){throw 'Resolved ccsizes still wipes the temp root'}
Write-Host 'PASS: Windows/catalogs/installer/logs/recovery protected; no recursive cache deletion; system-root sweep disabled; fresh profile ccsizes resolved.'
