#requires -Version 5.1
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$CBSLog)
$ErrorActionPreference = 'Stop'
Add-Type -Path (Join-Path $PSScriptRoot 'CatalogEvidence.cs')
$driver = Join-Path $env:windir 'System32\drivers\mpsdrv.sys'
$knownCatalog = Join-Path $env:windir 'WinSxS\Catalogs\fbc943848826f205637944ff56d4d65876b1aab914759cd14474c4e311965286.cat'
$knownHash = [PCIntegrityCatalogRead]::Hash($driver)
if ($knownHash -ne '491DF33C7D3973FE076AC0C0060B71110D11C90374047F172A9C4275D493354F' -or @([PCIntegrityCatalogRead]::Matches($knownCatalog,@($knownHash))).Count -ne 1) { throw 'Independent SignTool reference validation failed.' }
$files = @(Select-String -LiteralPath $CBSLog -Pattern 'DEPLOY \[Pnp\] Corrupt file: (.+)$' | ForEach-Object { $_.Matches[0].Groups[1].Value.Trim() } | Sort-Object -Unique)
$hashMap = @{}
foreach ($file in $files) {
    if (-not $file.StartsWith((Join-Path $env:windir 'System32\'),[StringComparison]::OrdinalIgnoreCase)) { throw ('Unexpected target: ' + $file) }
    $hash = [PCIntegrityCatalogRead]::Hash($file)
    if (-not $hashMap.ContainsKey($hash)) { $hashMap[$hash] = @() }
    $hashMap[$hash] += $file
}
$run = Join-Path $PSScriptRoot ('evidence\pnp-catalog-index-' + (Get-Date -Format 'yyyyMMdd-HHmmss-fff'))
$null = New-Item -ItemType Directory -Path $run
$found = @()
$errors = @()
$covered = @{}
$catalogs = @(Get-ChildItem -LiteralPath (Join-Path $env:windir 'WinSxS\Catalogs') -Filter *.cat -File -Force)
$count = 0
foreach ($cat in $catalogs) {
    try {
        foreach ($hash in [PCIntegrityCatalogRead]::Matches($cat.FullName,[string[]]@($hashMap.Keys))) {
            $found += [pscustomobject]@{Catalog=$cat.FullName; Hash=$hash; Files=$hashMap[$hash]}
            $covered[$hash] = $true
        }
    } catch { $errors += @{Catalog=$cat.FullName; Error=$_.Exception.Message} }
    $count++
    if ($count % 1000 -eq 0) { Write-Output ('Indexed ' + $count + '/' + $catalogs.Count) }
}
$unmatched = @($hashMap.Keys | Where-Object { -not $covered.ContainsKey($_) } | ForEach-Object { $hashMap[$_] })
$result = [ordered]@{SourceCBSLog=$CBSLog; FileCount=$files.Count; CatalogCount=$catalogs.Count; Matches=$found; UnmatchedFiles=$unmatched; ReadErrors=$errors; MembershipOnly=$true; SystemChanges=$false}
$result | ConvertTo-Json -Depth 7 | Set-Content (Join-Path $run 'result.json') -Encoding UTF8
Write-Output ('Evidence=' + $run + '; files=' + $files.Count + '; unmatched=' + $unmatched.Count + '; readErrors=' + $errors.Count)
