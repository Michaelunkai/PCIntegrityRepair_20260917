# Run after the catalog repair has finished, in a fresh elevated PS5 profile.
$ErrorActionPreference='Stop'
$run=Join-Path $PSScriptRoot ('evidence\cleanup-regression-'+(Get-Date -Format 'yyyyMMdd-HHmmss'))
$null=New-Item -ItemType Directory -Path $run
Start-Transcript -Path (Join-Path $run 'console.txt') | Out-Null
try {
 $watch=[Diagnostics.Stopwatch]::StartNew()
 while(@(Get-Process sfc,dism,TiWorker,TrustedInstaller -ErrorAction SilentlyContinue).Count){
  if($watch.Elapsed.TotalSeconds -ge 600){throw 'Windows servicing still active; no cleanup or scan started'}
  Write-Progress -Activity 'Waiting for servicing before cleanup regression test' -Status ('Elapsed '+[int]$watch.Elapsed.TotalSeconds+'s; limit 600s')
  Start-Sleep -Seconds 5
 }
 Write-Progress -Activity 'Waiting for servicing before cleanup regression test' -Completed
 $catroot=Join-Path $env:windir 'System32\catroot'
 $before=@(Get-ChildItem -LiteralPath $catroot -File -Recurse | ForEach-Object {Microsoft.PowerShell.Utility\Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256} | Sort-Object Path | Select-Object Path,Hash)
 $queueBefore=@((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager').PendingFileRenameOperations)
 $before | ConvertTo-Json -Depth 3 | Set-Content (Join-Path $run 'catalogs-before.json') -Encoding UTF8
 Write-Host 'Running the real corrected ccsizes and cleanc profile commands.'
 ccsizes
 if($LASTEXITCODE -ne 0){throw 'ccsizes failed'}
 cleanc
 if($LASTEXITCODE -ne 0){throw 'cleanc failed'}
 $after=@(Get-ChildItem -LiteralPath $catroot -File -Recurse | ForEach-Object {Microsoft.PowerShell.Utility\Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256} | Sort-Object Path | Select-Object Path,Hash)
 $queueAfter=@((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager').PendingFileRenameOperations)
 if(Compare-Object $before $after -Property Path,Hash){throw 'Catalog files changed during cleanup'}
 if([string]::Join([char]0,[string[]]$queueBefore) -cne [string]::Join([char]0,[string[]]$queueAfter)){throw 'Pending reboot queue changed during cleanup'}
 Write-Host ('PASS: '+$before.Count+' catalog files unchanged; pending reboot queue unchanged. Starting actual fastff repair/verification.')
 fastff -StatusIntervalSeconds 10 -ServicingWaitSeconds 600
 $code=$LASTEXITCODE
 [ordered]@{CompletedUtc=[datetime]::UtcNow.ToString('o');CatalogFilesUnchanged=$before.Count;PendingQueueUnchanged=$true;FastffExitCode=$code;Evidence=$run} | ConvertTo-Json | Set-Content (Join-Path $PSScriptRoot 'cleanup-regression.json') -Encoding UTF8
 if($code -ne 0){throw "Actual fastff failed with exit $code; inspect transcript"}
 Write-Host 'PASS: corrected cleanup preserved catalogs and actual fastff finished successfully.'
} finally {Stop-Transcript | Out-Null}
