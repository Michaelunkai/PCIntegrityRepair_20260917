param([switch]$Child,[string]$Directory)
$ErrorActionPreference='Stop'
if($Child){
 $run=$Directory;$NativeTimeoutSeconds=30;$errors=$null;$tokens=$null
 $ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'Repair-WindowsCatalogCorruption.ps1'),[ref]$tokens,[ref]$errors)
 $fn=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Invoke-Native'},$true)
 . ([scriptblock]::Create($fn.Extent.Text))
 $r=Invoke-Native "$env:windir\System32\WindowsPowerShell\v1.0\powershell.exe" '-NoProfile -NonInteractive -Command "[Console]::Out.Write(''FIRST'');[Console]::Out.Flush();Start-Sleep -Seconds 6;[Console]::Out.Write(''LAST'')"' 'short-fragment'
 if($r.ExitCode -ne 0){throw 'Synthetic child failed'}
 exit 0
}
$Directory=Join-Path $PSScriptRoot ('evidence\first-output-'+(Get-Date -Format 'yyyyMMdd-HHmmss-fff'))
$null=New-Item -ItemType Directory -Path $Directory
$watch=[Diagnostics.Stopwatch]::StartNew()
$p=Start-Process "$env:windir\System32\WindowsPowerShell\v1.0\powershell.exe" -ArgumentList ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$PSCommandPath+'" -Child -Directory "'+$Directory+'"') -WindowStyle Hidden -PassThru
$first=$null
while($watch.Elapsed.TotalSeconds -lt 5 -and -not $p.HasExited){
 $path=Join-Path $Directory 'short-fragment-stdout.txt'
 if(Test-Path -LiteralPath $path){try{$stream=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite);$reader=[IO.StreamReader]::new($stream);try{$text=$reader.ReadToEnd()}finally{$reader.Dispose()};if($text -match 'FIRST'){$first=$watch.Elapsed.TotalSeconds;break}}catch [IO.IOException]{}}
 Start-Sleep -Milliseconds 100
}
if($null -eq $first){throw 'First short output did not arrive while the child was still running'}
if(-not $p.WaitForExit(15000)){throw 'Synthetic child did not finish'}
if($p.ExitCode -ne 0){throw 'Synthetic controller failed'}
$receipt=Get-Content -Raw (Join-Path $Directory 'short-fragment.json') | ConvertFrom-Json
if($receipt.Output -notmatch 'FIRSTLAST'){throw 'Output was lost'}
@{FirstFragmentSeconds=$first;ChildDelaySeconds=6;Passed=$true} | ConvertTo-Json | Set-Content (Join-Path $Directory 'test-result.json') -Encoding UTF8
Write-Host ('PASS: short FIRST fragment visible after {0:N2}s, before child completion; final output preserved.' -f $first)
