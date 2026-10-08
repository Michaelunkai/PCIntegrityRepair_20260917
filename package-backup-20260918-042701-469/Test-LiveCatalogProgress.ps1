param([string]$ScriptPath=(Join-Path $PSScriptRoot 'Repair-WindowsCatalogCorruption.ps1'))
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($ScriptPath,[ref]$tokens,[ref]$errors)
if($errors.Count){throw ($errors.Message -join "`n")}
$function=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Invoke-Native'},$true)
. ([scriptblock]::Create($function.Extent.Text))
$run=Join-Path $PSScriptRoot ('evidence\progress-test-'+(Get-Date -Format 'yyyyMMdd-HHmmss-fff'))
$null=New-Item -ItemType Directory -Path $run
$NativeTimeoutSeconds=30
$exe="$env:windir\System32\WindowsPowerShell\v1.0\powershell.exe"
$payload='$ProgressPreference="SilentlyContinue"; [Console]::OutputEncoding=[Text.Encoding]::Unicode; [Console]::Write("progress 10%`r"); Start-Sleep -Seconds 2; [Console]::Write("progress 100%`r"); $w=New-Object IO.StreamWriter([Console]::OpenStandardError(),[Text.Encoding]::UTF8);$w.WriteLine("stderr preserved");$w.Flush(); exit 7'
$encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($payload))
$receipt=Invoke-Native $exe ('-NoProfile -NonInteractive -OutputFormat Text -EncodedCommand '+$encoded) 'stream-test' -Unicode
if($receipt.ExitCode -ne 7 -or $receipt.Output -notmatch '10%' -or $receipt.Output -notmatch '100%' -or $receipt.ErrorOutput -notmatch 'stderr preserved'){throw 'Streaming/encoding/exit-code failure.'}
$NativeTimeoutSeconds=10
$payload='Start-Sleep -Seconds 13; [Console]::WriteLine("completed after timeout"); exit 0'
$encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($payload))
$timedOut=$false
try{$null=Invoke-Native $exe ('-NoProfile -NonInteractive -EncodedCommand '+$encoded) 'timeout-test'}catch{if($_.Exception.Message -notlike '*Observation timeout*'){throw};$timedOut=$true;Write-Host $_.Exception.Message}
if(-not $timedOut){throw 'Expected timeout did not occur.'}
$watch=[Diagnostics.Stopwatch]::StartNew()
while(-not (Test-Path -LiteralPath (Join-Path $run 'timeout-test.json')) -and $watch.Elapsed.TotalSeconds -lt 20){Start-Sleep -Milliseconds 200}
$later=Get-Content -Raw -LiteralPath (Join-Path $run 'timeout-test.json') | ConvertFrom-Json
if($later.ExitCode -ne 0 -or $later.Output -notmatch 'completed after timeout'){throw 'Worker did not survive controller timeout.'}
Write-Host ('PASS: streamed Unicode/CR output, stderr, nonzero exit propagation, timeout, and independent worker completion. Evidence='+$run)
