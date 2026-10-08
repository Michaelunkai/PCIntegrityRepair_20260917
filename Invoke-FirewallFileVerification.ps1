#requires -Version 5.1
[CmdletBinding()]
param(
    [ValidateSet('FirewallDriver','All')][string]$Scope = 'FirewallDriver',
    [ValidateRange(0,600)][int]$WaitForServicingSeconds = 0
)
$ErrorActionPreference = 'Stop'
$workers = @(Get-Process dism,sfc,TiWorker,TrustedInstaller -ErrorAction SilentlyContinue)
$settle = [Diagnostics.Stopwatch]::StartNew()
$lastNotice = -30
while ($workers.Count -and $settle.Elapsed.TotalSeconds -lt $WaitForServicingSeconds) {
    if ($settle.Elapsed.TotalSeconds-$lastNotice -ge 30) {
        Write-Output ('Waiting for live servicing workers: '+(($workers | ForEach-Object { $_.Name+":"+$_.Id }) -join ', '))
        $lastNotice=$settle.Elapsed.TotalSeconds
    }
    Start-Sleep -Seconds 1
    $workers = @(Get-Process dism,sfc,TiWorker,TrustedInstaller -ErrorAction SilentlyContinue)
}
if ($workers.Count) { throw ('Servicing is active: ' + (($workers | ForEach-Object { $_.Name + ':' + $_.Id }) -join ', ')) }
$run = Join-Path $PSScriptRoot ('evidence\firewall-verify-' + (Get-Date -Format 'yyyyMMdd-HHmmss-fff'))
$null = New-Item -ItemType Directory -Path $run
$key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
$before = @((Get-ItemProperty -LiteralPath $key).PendingFileRenameOperations)
$target = Join-Path $env:windir 'System32\drivers\mpsdrv.sys'
$started = Get-Date
$argument = if ($Scope -eq 'All') { '/verifyonly' } else { '/verifyfile=' + $target }
$proc = New-Object System.Diagnostics.Process
$proc.StartInfo.FileName = Join-Path $env:windir 'System32\sfc.exe'
$proc.StartInfo.Arguments = $argument
$proc.StartInfo.UseShellExecute = $false
$proc.StartInfo.CreateNoWindow = $true
$proc.StartInfo.RedirectStandardOutput = $true
$proc.StartInfo.RedirectStandardError = $true
$proc.StartInfo.StandardOutputEncoding = [Text.Encoding]::Unicode
$null = $proc.Start()
$stdoutTask = $proc.StandardOutput.ReadToEndAsync()
$stderrTask = $proc.StandardError.ReadToEndAsync()
Write-Output ('Verification PID=' + $proc.Id + ' Evidence=' + $run)
$running=[Diagnostics.Stopwatch]::StartNew()
$lastNotice=0
while (-not $proc.WaitForExit(1000)) {
    if ($running.Elapsed.TotalSeconds-$lastNotice -ge 30) { Write-Output ('SFC verification running; PID='+$proc.Id); $lastNotice=$running.Elapsed.TotalSeconds }
}
$after = @((Get-ItemProperty -LiteralPath $key).PendingFileRenameOperations)
$output = $stdoutTask.Result
[IO.File]::WriteAllText((Join-Path $run 'sfc-stderr.txt'), $stderrTask.Result, [Text.Encoding]::UTF8)
[IO.File]::WriteAllText((Join-Path $run 'sfc-decoded.txt'), $output, [Text.Encoding]::UTF8)
$result = [ordered]@{ StartedUtc=$started.ToUniversalTime().ToString('o'); CompletedUtc=[DateTime]::UtcNow.ToString('o'); Command=('sfc ' + $argument); ExitCode=$proc.ExitCode; Output=$output; QueueBefore=$before; QueueAfter=$after; QueueUnchanged=([string]::Join([char]0,[string[]]$before) -ceq [string]::Join([char]0,[string[]]$after)); RepairRequested=$false }
$result | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $run 'result.json') -Encoding UTF8
($output -split '[\r\n]+' | Where-Object { $_ -match '^Windows Resource Protection' }) | Write-Output
Write-Output ('QueueUnchanged=' + $result.QueueUnchanged + '; exit=' + $proc.ExitCode)
