$ErrorActionPreference='Stop'
$errors=$null;$tokens=$null
$source=Join-Path $PSScriptRoot 'WindowsCatalogRepair-Package\Repair-WindowsCatalogCorruption.ps1'
$ast=[Management.Automation.Language.Parser]::ParseFile($source,[ref]$tokens,[ref]$errors)
if($errors.Count){throw ($errors | Out-String)}
$function=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Get-RebootGateOutcome'},$true)
if(-not $function){throw 'Readiness code was not embedded'}
. ([scriptblock]::Create($function.Extent.Text))
$finalFunction=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Get-FinalRepairOutcome'},$true)
. ([scriptblock]::Create($finalFunction.Extent.Text))
foreach($case in @(@($true,'ChecksPassed_NotBootTested','VerifiedClean'),@($true,'NeedsAttention','NeedsAttention'),@($false,'ChecksPassed_NotBootTested','Incomplete'),@($true,'Unknown','Incomplete'))){if((Get-FinalRepairOutcome $case[0] $case[1]) -ne $case[2]){throw 'Final integrity gate failed'}}
foreach($case in @(@(0,$true,$true,'ChecksPassed_NotBootTested'),@(1,$true,$true,'NeedsAttention'),@(0,$false,$true,'NeedsAttention'),@(0,$true,$false,'NeedsAttention'))){if((Get-RebootGateOutcome $case[0] $case[1] $case[2]) -ne $case[3]){throw 'Gate decision failed'}}
$fn=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Invoke-RebootReadiness'},$true)
$body=$fn.Find({param($n) $n -is [Management.Automation.Language.StringConstantExpressionAst] -and $n.Value.StartsWith('param([string]$OutputDirectory)')},$true)
if(-not $body){throw 'Embedded inventory worker missing'}
$null=[Management.Automation.Language.Parser]::ParseInput($body.Value,[ref]$tokens,[ref]$errors)
if($errors.Count){throw ($errors | Out-String)}
Write-Host 'PASS: packaged PS1 and embedded inventory parse; readiness rejects issues, unavailable inventory, and failed native checks.'
