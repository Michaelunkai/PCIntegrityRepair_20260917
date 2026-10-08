#requires -Version 5.1
#requires -RunAsAdministrator
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$run = Join-Path $PSScriptRoot ('evidence\component-scan-' + (Get-Date -Format 'yyyyMMdd-HHmmss-fff'))
$null = New-Item -ItemType Directory -Path $run
$elapsed = [Diagnostics.Stopwatch]::StartNew()
$quiet = [Diagnostics.Stopwatch]::StartNew()
while ($quiet.Elapsed.TotalSeconds -lt 30) {
    $workers = @(Get-Process dism,sfc,TiWorker,TrustedInstaller -ErrorAction SilentlyContinue)
    if ($workers.Count) { $quiet.Restart() }
    if ($elapsed.Elapsed.TotalSeconds -gt 300) { throw 'Servicing did not settle; no scan started.' }
    Start-Sleep -Seconds 1
}
foreach ($marker in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired', "$env:windir\WinSxS\pending.xml")) {
    if (Test-Path -LiteralPath $marker) { throw "Native servicing marker present: $marker" }
}
$key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
$before = @((Get-ItemProperty -LiteralPath $key).PendingFileRenameOperations)
$result = [ordered]@{ StartedUtc=[datetime]::UtcNow.ToString('o'); Operation='Repair-WindowsImage -Online -ScanHealth -NoRestart'; RepairRequested=$false; QueueBefore=$before; EvidenceDirectory=$run }
try {
    Import-Module Dism -ErrorAction Stop
    Write-Output ('Component scan starting; evidence=' + $run)
    $state = Repair-WindowsImage -Online -ScanHealth -NoRestart -LogPath (Join-Path $run 'dism.log') -ErrorAction Stop
    $result.ImageHealthState = [string]$state.ImageHealthState
    $result.RestartNeeded = $state.RestartNeeded
    $result.Error = $null
} catch { $result.Error = $_.Exception.Message }
$after = @((Get-ItemProperty -LiteralPath $key).PendingFileRenameOperations)
$result.QueueAfter = $after
$result.QueueUnchanged = [string]::Join([char]0,[string[]]$before) -ceq [string]::Join([char]0,[string[]]$after)
$result.CompletedUtc = [datetime]::UtcNow.ToString('o')
$result | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $run 'result.json') -Encoding UTF8
Write-Output ('Health=' + $result.ImageHealthState + '; Error=' + $result.Error + '; QueueUnchanged=' + $result.QueueUnchanged)
if ($result.Error -or $result.ImageHealthState -ne 'Healthy') { exit 3 }
