#requires -Version 5.1
$ErrorActionPreference='Stop'
$path=Join-Path $PSScriptRoot 'Repair-WindowsCatalogCorruption.ps1'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
if($errors.Count) {throw ($errors.Message -join "`n")}
$definition=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Test-Clean'},$true)
. ([scriptblock]::Create($definition.Extent.Text))
if(-not (Test-Clean ([pscustomobject]@{ExitCode=0;Output='Windows Resource Protection did not find any integrity violations.'}))) {throw 'Clean result rejected.'}
foreach($case in @(
    [pscustomobject]@{ExitCode=0;Output='Windows Resource Protection found corrupt files and successfully repaired them.'},
    [pscustomobject]@{ExitCode=0;Output='Windows Resource Protection found corrupt files but was unable to fix some of them.'},
    [pscustomobject]@{ExitCode=1;Output='Windows Resource Protection did not find any integrity violations.'},
    [pscustomobject]@{ExitCode=0;Output=''}
)) {if(Test-Clean $case) {throw 'False clean result accepted.'}}
$source=$ast.Find({param($n) $n -is [Management.Automation.Language.StringConstantExpressionAst] -and $n.Value -like '*public static class StandaloneCatalogEvidence*'},$true).Value
Add-Type -TypeDefinition $source
$driver=Join-Path $env:windir 'System32\drivers\mpsdrv.sys'
$catalog=Join-Path $env:windir 'WinSxS\Catalogs\fbc943848826f205637944ff56d4d65876b1aab914759cd14474c4e311965286.cat'
$hash=[StandaloneCatalogEvidence]::Hash($driver)
if($hash -ne '491DF33C7D3973FE076AC0C0060B71110D11C90374047F172A9C4275D493354F') {throw 'Reference driver changed; update test evidence rather than assume success.'}
if(@([StandaloneCatalogEvidence]::Matches($catalog,@($hash))).Count -ne 1) {throw 'Known catalog member not found.'}
if(@([StandaloneCatalogEvidence]::Matches($catalog,@('0000000000000000000000000000000000000000000000000000000000000000'))).Count) {throw 'Nonmember incorrectly matched.'}
Write-Output 'PASS: parser; five clean-result cases; embedded C# compilation; known catalog hash/member; nonmember rejection. No repair executed.'
