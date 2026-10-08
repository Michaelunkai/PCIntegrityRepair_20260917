#requires -Version 5.1
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$tool = 'C:\Program Files (x86)\Windows Kits\10\Tools\bin\i386\signtool.exe'
$run = Join-Path $PSScriptRoot ('evidence\catalog-search-' + (Get-Date -Format 'yyyyMMdd-HHmmss-fff'))
$null = New-Item -ItemType Directory -Path $run
$catalogs = @(Get-ChildItem -LiteralPath (Join-Path $env:windir 'WinSxS\Catalogs') -Filter *.cat -File -Force | Sort-Object LastWriteTime -Descending)
$checked = 0
$matched = $null
$otherFailures = @()
foreach ($catalog in $catalogs) {
    $proc = New-Object Diagnostics.Process
    $proc.StartInfo.FileName = $tool
    # This installed SignTool is x86. Sysnative addresses the real 64-bit driver.
    $proc.StartInfo.Arguments = 'verify /q /kp /hash SHA256 /c "' + $catalog.FullName + '" "' + $env:windir + '\Sysnative\drivers\mpsdrv.sys"'
    $proc.StartInfo.UseShellExecute = $false
    $proc.StartInfo.CreateNoWindow = $true
    $proc.StartInfo.RedirectStandardOutput = $true
    $proc.StartInfo.RedirectStandardError = $true
    $null = $proc.Start()
    $outTask = $proc.StandardOutput.ReadToEndAsync()
    $errTask = $proc.StandardError.ReadToEndAsync()
    $proc.WaitForExit()
    $output = $outTask.Result + $errTask.Result
    $code = $proc.ExitCode
    $proc.Dispose()
    $checked++
    if ($code -eq 0) { $matched = $catalog.FullName; break }
    if ($output -notmatch 'File not found in the specified catalog') { $otherFailures += @{Catalog=$catalog.FullName; ExitCode=$code; Output=$output} }
    if ($checked % 250 -eq 0) { Write-Output ('Catalogs checked: ' + $checked + '/' + $catalogs.Count) }
}
$result = @{ CompletedUtc=[DateTime]::UtcNow.ToString('o'); Checked=$checked; CatalogCount=$catalogs.Count; VerifiedCatalog=$matched; OtherFailures=$otherFailures; SystemChanges=$false }
$result | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $run 'result.json') -Encoding UTF8
Write-Output ('Evidence: ' + $run)
[pscustomobject]$result | Select-Object Checked,CatalogCount,VerifiedCatalog | Format-List
