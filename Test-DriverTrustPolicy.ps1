$ErrorActionPreference='Stop'
$errors=$null;$tokens=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'Repair-WindowsCatalogCorruption.ps1'),[ref]$tokens,[ref]$errors)
if($errors.Count){throw ($errors | Out-String)}
$function=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Invoke-DriverTrust'},$true)
. ([scriptblock]::Create($function.Extent.Text))
$tool='mock-verified-helper';$script:calls=@();$script:codes=@(0)
function Invoke-Native($Exe,$Arguments,$Label){$script:calls+=$Arguments;$code=$script:codes[0];$script:codes=@($script:codes | Select-Object -Skip 1);return [pscustomobject]@{ExitCode=$code}}
if((Invoke-DriverTrust 'driver.sys' 'case').ExitCode -ne 0 -or $script:calls.Count -ne 1){throw 'Primary-pass case failed'}
$script:calls=@();$script:codes=@(1,0)
if((Invoke-DriverTrust 'driver.sys' 'case').ExitCode -ne 0 -or $script:calls[1] -notmatch '/ms /r "Microsoft Root Certificate Authority"' -or $script:calls[1] -match '/pa'){throw 'Microsoft secondary-signature case failed'}
$script:calls=@();$script:codes=@(1,1)
if((Invoke-DriverTrust 'driver.sys' 'case').ExitCode -eq 0){throw 'Invalid trust incorrectly accepted'}
Write-Host 'PASS: primary signature, Microsoft-root secondary signature, and rejection of failed trust.'
