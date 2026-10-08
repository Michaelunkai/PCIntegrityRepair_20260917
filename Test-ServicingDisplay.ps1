$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'Repair-WindowsCatalogCorruption.ps1'),[ref]$tokens,[ref]$errors)
if($errors.Count){throw ($errors.Message -join "`n")}
$function=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Wait-Servicing'},$true)
. ([scriptblock]::Create($function.Extent.Text))
# Bounded read-only observation of real servicing; no scan or repair is launched.
try {Wait-Servicing -MaxSeconds 10} catch {
    if($_.Exception.Message -notmatch 'still present after 10 seconds'){throw}
    Write-Host ('EXPECTED BOUNDED STOP: '+$_.Exception.Message)
}
