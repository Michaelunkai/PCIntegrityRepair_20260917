#requires -Version 5.1
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$CBSLog)
$ErrorActionPreference = 'Stop'
$files = @(Select-String -LiteralPath $CBSLog -Pattern 'DEPLOY \[Pnp\] Corrupt file: (.+)$' | ForEach-Object { $_.Matches[0].Groups[1].Value.Trim() } | Sort-Object -Unique)
if (-not $files.Count) { throw 'No PnP file findings in supplied log.' }
$system32 = Join-Path $env:windir 'System32\'
$nativeFiles = foreach ($file in $files) {
    if (-not $file.StartsWith($system32,[StringComparison]::OrdinalIgnoreCase)) { throw ('Unexpected target: ' + $file) }
    '"' + (Join-Path $env:windir ('Sysnative\' + $file.Substring($system32.Length))) + '"'
}
$run = Join-Path $PSScriptRoot ('evidence\pnp-signatures-' + (Get-Date -Format 'yyyyMMdd-HHmmss-fff'))
$null = New-Item -ItemType Directory -Path $run
$p = New-Object Diagnostics.Process
$p.StartInfo.FileName = 'C:\Program Files (x86)\Windows Kits\10\Tools\bin\i386\signtool.exe'
$p.StartInfo.Arguments = 'verify /a /kp /hash SHA256 /v ' + ($nativeFiles -join ' ')
$p.StartInfo.UseShellExecute = $false
$p.StartInfo.CreateNoWindow = $true
$p.StartInfo.RedirectStandardOutput = $true
$p.StartInfo.RedirectStandardError = $true
$null = $p.Start()
$o = $p.StandardOutput.ReadToEndAsync()
$e = $p.StandardError.ReadToEndAsync()
$p.WaitForExit()
[IO.File]::WriteAllText((Join-Path $run 'verification.txt'), $o.Result + $e.Result, [Text.Encoding]::UTF8)
$result = [ordered]@{ CompletedUtc=[DateTime]::UtcNow.ToString('o'); SourceCBSLog=$CBSLog; TargetCount=$files.Count; ExitCode=$p.ExitCode; Files=$files; SystemChanges=$false }
$result | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $run 'result.json') -Encoding UTF8
Write-Output ('Evidence=' + $run + '; targets=' + $files.Count + '; exit=' + $p.ExitCode)
$p.Dispose()
