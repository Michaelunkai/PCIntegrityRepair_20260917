#requires -Version 5.1
#requires -RunAsAdministrator
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$IndexReport,[switch]$Apply)
$ErrorActionPreference = 'Stop'
$index = Get-Content -Raw -LiteralPath $IndexReport | ConvertFrom-Json
if (@($index.UnmatchedFiles).Count -or @($index.ReadErrors).Count) { throw 'Catalog membership indexing is incomplete.' }
$run = Join-Path $PSScriptRoot ('evidence\pnp-catalog-restore-' + (Get-Date -Format 'yyyyMMdd-HHmmss-fff'))
$null = New-Item -ItemType Directory -Path $run
$systemRoot = [IO.Path]::GetFullPath((Join-Path $env:windir 'System32\'))
$catalogRoot = [IO.Path]::GetFullPath((Join-Path $env:windir 'WinSxS\Catalogs\'))
$tool = 'C:\Program Files (x86)\Windows Kits\10\Tools\bin\i386\signtool.exe'
function Invoke-Tool([string]$Arguments,[string]$Label) {
    [IO.File]::WriteAllText((Join-Path $run ($Label + '.command.txt')),$Arguments,[Text.Encoding]::UTF8)
    $p = New-Object Diagnostics.Process
    $p.StartInfo.FileName=$tool; $p.StartInfo.Arguments=$Arguments
    $p.StartInfo.UseShellExecute=$false; $p.StartInfo.CreateNoWindow=$true
    $p.StartInfo.RedirectStandardOutput=$true; $p.StartInfo.RedirectStandardError=$true
    $null=$p.Start(); $o=$p.StandardOutput.ReadToEndAsync(); $e=$p.StandardError.ReadToEndAsync()
    $p.WaitForExit(); $code=$p.ExitCode
    [IO.File]::WriteAllText((Join-Path $run ($Label + '.txt')),$o.Result+$e.Result,[Text.Encoding]::UTF8)
    $p.Dispose(); return $code
}
function Get-ToolPath([string]$File) {
    $full=[IO.Path]::GetFullPath($File)
    if (-not $full.StartsWith($systemRoot,[StringComparison]::OrdinalIgnoreCase)) { throw ('Target outside System32: '+$full) }
    return '"' + (Join-Path $env:windir ('Sysnative\'+$full.Substring($systemRoot.Length))) + '"'
}
$allFiles = @($index.Matches | ForEach-Object Files | Sort-Object -Unique)
if ($allFiles.Count -ne $index.FileCount -or -not $allFiles.Count) { throw 'Incomplete file-to-catalog coverage.' }
$uncovered = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
foreach ($file in $allFiles) { $null=$uncovered.Add($file); $null=Get-ToolPath $file }
$groups = @($index.Matches | Group-Object Catalog)
$plan = @()
while ($uncovered.Count) {
    $best = $null; $bestFiles = @()
    foreach ($group in $groups) {
        $files = @($group.Group | ForEach-Object Files | Sort-Object -Unique | Where-Object { $uncovered.Contains($_) })
        if ($files.Count -gt $bestFiles.Count) { $best=$group; $bestFiles=$files }
    }
    if (-not $best) { throw 'Could not construct full coverage.' }
    $cat = [IO.Path]::GetFullPath($best.Name)
    if (-not $cat.StartsWith($catalogRoot,[StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetExtension($cat) -ne '.cat') { throw 'Catalog outside the local component store.' }
    $plan += [pscustomobject]@{ Catalog=$cat; Files=$bestFiles; CatalogHash=(Get-FileHash -LiteralPath $cat).Hash }
    foreach ($file in $bestFiles) { $null=$uncovered.Remove($file) }
}
$beforeHashes = @(foreach ($file in $allFiles) { Get-FileHash -LiteralPath $file | Select-Object Path,Hash })
$beforeHashes | ConvertTo-Json | Set-Content (Join-Path $run 'files-before.json') -Encoding UTF8
$i=0
foreach ($item in $plan) {
    $i++
    $signature=Get-AuthenticodeSignature -LiteralPath $item.Catalog
    if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'CN=Microsoft Windows,') { throw ('Not a valid Microsoft Windows catalog: '+$item.Catalog) }
    $paths=@($item.Files | ForEach-Object { Get-ToolPath $_ })
    # This installed SignTool rejects /o combined with /kp; retain kernel policy on the current host.
    $verifyArguments='verify /kp /hash SHA256 /v /c "'+$item.Catalog+'" '+($paths -join ' ')
    if ((Invoke-Tool $verifyArguments ('preflight-'+$i)) -ne 0) { throw ('Exact catalog verification failed; no registrations made. Evidence: '+$run) }
}
$plan | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $run 'validated-plan.json') -Encoding UTF8
Write-Output ('Validated '+$plan.Count+' Microsoft catalogs covering '+$allFiles.Count+' installed files. Evidence='+$run)
if (-not $Apply) { return }
$beforeCats=@(Get-ChildItem -LiteralPath (Join-Path $env:windir 'System32\CatRoot') -Recurse -File -Force -Filter *.cat | Select-Object -ExpandProperty FullName)
$i=0
foreach ($item in $plan) {
    $i++
    if ((Get-FileHash -LiteralPath $item.Catalog).Hash -cne $item.CatalogHash) { throw 'Catalog changed after validation.' }
    if ((Invoke-Tool ('catdb /u /v "'+$item.Catalog+'"') ('registration-'+$i)) -ne 0) { throw ('Registration failed after '+($i-1)+' additions. Inspect saved receipts.') }
}
$afterCats=@(Get-ChildItem -LiteralPath (Join-Path $env:windir 'System32\CatRoot') -Recurse -File -Force -Filter *.cat | Select-Object -ExpandProperty FullName)
$paths=@($allFiles | ForEach-Object { Get-ToolPath $_ })
$verification=Invoke-Tool ('verify /a /kp /hash SHA256 /v '+($paths -join ' ')) 'automatic-after'
$changed=@(foreach ($entry in $beforeHashes) { if ((Get-FileHash -LiteralPath $entry.Path).Hash -cne $entry.Hash) { $entry.Path } })
$result=[ordered]@{CompletedUtc=[DateTime]::UtcNow.ToString('o'); CatalogsRegistered=$plan.Count; FileCount=$allFiles.Count; AutomaticVerificationExit=$verification; ChangedFileContents=$changed; AddedCatalogFiles=@($afterCats | Where-Object {$_ -notin $beforeCats}); Evidence=$run}
$result | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $run 'result.json') -Encoding UTF8
$result | ConvertTo-Json -Depth 5 | Write-Output
if ($verification -ne 0 -or $changed.Count) { exit 3 }
