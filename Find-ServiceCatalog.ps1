#requires -Version 5.1
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
Add-Type -Path (Join-Path $PSScriptRoot 'CatalogEvidence.cs')
$file='C:\Program Files\Windows Media Player\wmpnetwk.exe'
$hash=[PCIntegrityCatalogRead]::Hash($file)
$matches=@()
$errors=@()
foreach($catalog in @(Get-ChildItem -LiteralPath "$env:windir\WinSxS\Catalogs" -File -Filter *.cat)) {
    try {
        if (@([PCIntegrityCatalogRead]::Matches($catalog.FullName,@($hash))).Count) {
            $matches += $catalog.FullName
        }
    } catch { $errors += $_.Exception.Message }
}
$run=Join-Path $PSScriptRoot ('evidence\service-catalog-'+(Get-Date -Format 'yyyyMMdd-HHmmss-fff'))
$null=New-Item -ItemType Directory -Path $run
[ordered]@{File=$file; Hash=$hash; Matches=$matches; Errors=$errors; ChangesMade=$false; MembershipOnly=$true} | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $run 'result.json') -Encoding UTF8
Write-Output ('Report='+$run)
$matches
Write-Output ('ReadErrors='+$errors.Count)
