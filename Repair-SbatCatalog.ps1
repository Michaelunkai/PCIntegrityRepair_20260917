#requires -Version 5.1
#requires -RunAsAdministrator
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$target = Join-Path $env:windir 'System32\catroot\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}\SbatLevel.cat'
$run = Join-Path $PSScriptRoot ('evidence\sbat-repair-' + (Get-Date -Format 'yyyyMMdd-HHmmss-fff'))
$null = New-Item -ItemType Directory -Path $run
$watch = [Diagnostics.Stopwatch]::StartNew()
$quietSince = $null
$lastNotice = -30
while ($true) {
    $workers = @(Get-Process dism,sfc,TiWorker,TrustedInstaller -ErrorAction SilentlyContinue)
    if ($workers.Count) { $quietSince=$null } elseif ($null -eq $quietSince) { $quietSince=$watch.Elapsed.TotalSeconds }
    if ($null -ne $quietSince -and $watch.Elapsed.TotalSeconds-$quietSince -ge 30) { break }
    if ($watch.Elapsed.TotalSeconds -ge 300) { throw 'Servicing did not settle; no single-file repair started.' }
    if ($watch.Elapsed.TotalSeconds-$lastNotice -ge 30) {
        Write-Output ('Waiting for servicing quiet interval; live workers='+(($workers | ForEach-Object { $_.Name+":"+$_.Id }) -join ', '))
        $lastNotice=$watch.Elapsed.TotalSeconds
    }
    Start-Sleep -Seconds 1
}
$markers = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired',
    (Join-Path $env:windir 'WinSxS\pending.xml')
)
foreach ($marker in $markers) { if (Test-Path -LiteralPath $marker) { throw ('Native servicing reboot marker present: '+$marker) } }
if (@(Get-Process dism,sfc,TiWorker,TrustedInstaller -ErrorAction SilentlyContinue).Count) { throw 'Servicing appeared before launch.' }
$key='HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
$queueBefore=@((Get-ItemProperty -LiteralPath $key).PendingFileRenameOperations)
$existedBefore=Test-Path -LiteralPath $target
$p=New-Object Diagnostics.Process
$p.StartInfo.FileName=Join-Path $env:windir 'System32\sfc.exe'
$p.StartInfo.Arguments='/scanfile='+$target
$p.StartInfo.UseShellExecute=$false; $p.StartInfo.CreateNoWindow=$true
$p.StartInfo.RedirectStandardOutput=$true; $p.StartInfo.RedirectStandardError=$true
$p.StartInfo.StandardOutputEncoding=[Text.Encoding]::Unicode
$null=$p.Start(); $o=$p.StandardOutput.ReadToEndAsync(); $e=$p.StandardError.ReadToEndAsync()
Write-Output ('Single-file SFC PID='+$p.Id+'; evidence='+$run)
$p.WaitForExit()
$queueAfter=@((Get-ItemProperty -LiteralPath $key).PendingFileRenameOperations)
$result=[ordered]@{CompletedUtc=[DateTime]::UtcNow.ToString('o'); Target=$target; ExistedBefore=$existedBefore; ExistsAfter=(Test-Path -LiteralPath $target); ExitCode=$p.ExitCode; Output=$o.Result; ErrorOutput=$e.Result; QueueBefore=$queueBefore; QueueAfter=$queueAfter; QueueUnchanged=([string]::Join([char]0,[string[]]$queueBefore) -ceq [string]::Join([char]0,[string[]]$queueAfter))}
$result | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $run 'result.json') -Encoding UTF8
Write-Output $o.Result
Write-Output ('ExistsAfter='+$result.ExistsAfter+'; QueueUnchanged='+$result.QueueUnchanged)
$p.Dispose()
