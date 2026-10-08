#requires -Version 5.1
#requires -RunAsAdministrator
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$file='C:\Program Files\Windows Media Player\wmpnetwk.exe'
$catalog='C:\Windows\WinSxS\Catalogs\4e2a03c65e7aad5f660441c6a4364fbf5431c9c98da800ae9290d853d13f7695.cat'
$tool='C:\Program Files (x86)\Windows Kits\10\Tools\bin\i386\signtool.exe'
$run=Join-Path $PSScriptRoot ('evidence\media-catalog-repair-'+(Get-Date -Format 'yyyyMMdd-HHmmss-fff'))
$null=New-Item -ItemType Directory -Path $run
$before=(Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash
$signature=Get-AuthenticodeSignature -LiteralPath $catalog
if($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'CN=Microsoft Windows,') {throw 'Catalog signature is not the expected valid Microsoft Windows signature.'}
$preflight=& $tool verify /pa /v /c $catalog $file 2>&1
$preflightExit=$LASTEXITCODE
$preflight | Set-Content -LiteralPath (Join-Path $run 'preflight.txt')
if($preflightExit -ne 0) {throw 'Exact-file catalog verification failed; no registration performed.'}
$ErrorActionPreference='Continue'
$automatic=& $tool verify /a /pa /v $file 2>&1
$automaticExit=$LASTEXITCODE
$ErrorActionPreference='Stop'
$automatic | Set-Content -LiteralPath (Join-Path $run 'automatic-before.txt')
$registered=$false
if($automaticExit -ne 0) {
    $registration=& $tool catdb /u /v $catalog 2>&1
    $registrationExit=$LASTEXITCODE
    $registration | Set-Content -LiteralPath (Join-Path $run 'registration.txt')
    if($registrationExit -ne 0) {throw 'Catalog registration failed; inspect receipt.'}
    $registered=$true
}
$verified=& $tool verify /a /pa /v $file 2>&1
$verifiedExit=$LASTEXITCODE
$verified | Set-Content -LiteralPath (Join-Path $run 'automatic-after.txt')
$after=(Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash
$result=[ordered]@{File=$file; Catalog=$catalog; Registered=$registered; AutomaticBeforeExit=$automaticExit; AutomaticAfterExit=$verifiedExit; HashBefore=$before; HashAfter=$after; FileUnchanged=($before -eq $after); ServiceStarted=$false; CompletedUtc=[datetime]::UtcNow.ToString('o')}
$result | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $run 'result.json') -Encoding UTF8
Write-Output ('Report='+$run+'; VerifiedExit='+$verifiedExit+'; FileUnchanged='+$result.FileUnchanged)
if($verifiedExit -ne 0 -or -not $result.FileUnchanged) {exit 3}
