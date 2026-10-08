#requires -Version 5.1
#requires -RunAsAdministrator
[CmdletBinding()]
param([switch]$Apply)
$ErrorActionPreference='Stop'
$names=@('{4921084d-b227-11f1-95fd-806e6f6e6963}.TxR.0.regtrans-ms','{4921084d-b227-11f1-95fd-806e6f6e6963}.TxR.1.regtrans-ms','{4921084d-b227-11f1-95fd-806e6f6e6963}.TxR.2.regtrans-ms','{4921084d-b227-11f1-95fd-806e6f6e6963}.TxR.blf','{4921084e-b227-11f1-95fd-806e6f6e6963}.TM.blf','{4921084e-b227-11f1-95fd-806e6f6e6963}.TMContainer00000000000000000001.regtrans-ms','{4921084e-b227-11f1-95fd-806e6f6e6963}.TMContainer00000000000000000002.regtrans-ms')
$root='C:\Windows\System32\config\TxR'
$key=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SYSTEM\CurrentControlSet\Control\Session Manager',$Apply.IsPresent)
try {
    $value='PendingFileRenameOperations'
    if($key.GetValueKind($value) -ne [Microsoft.Win32.RegistryValueKind]::MultiString) {throw 'Unexpected registry type.'}
    [string[]]$before=$key.GetValue($value)
    if($before.Count % 2) {throw 'Odd queue length.'}
    $keep=New-Object 'System.Collections.Generic.List[string]'
    $removed=@()
    for($i=0;$i -lt $before.Count;$i+=2) {
        $matched=$false
        foreach($name in $names) {
            $path=Join-Path $root $name
            if($before[$i] -ceq ('*1\??\'+$path) -and $before[$i+1] -ceq ('*1!\??\'+$path+'.old')) {
                if(-not (Test-Path -LiteralPath $path -PathType Leaf)) {throw 'Expected transaction file absent.'}
                if(Test-Path -LiteralPath ($path+'.old')) {throw 'Destination exists; needs fresh investigation.'}
                $removed += [pscustomobject]@{Source=$before[$i]; Destination=$before[$i+1]}
                $matched=$true
                break
            }
        }
        if(-not $matched) {$keep.Add($before[$i]);$keep.Add($before[$i+1])}
    }
    if($removed.Count -ne 7) {throw ('Expected exactly seven matching requests, found '+$removed.Count)}
    $run=Join-Path $PSScriptRoot ('evidence\txr-queue-'+(Get-Date -Format 'yyyyMMdd-HHmmss-fff'))
    $null=New-Item -ItemType Directory -Path $run
    [ordered]@{Before=$before; Removed=$removed; ProposedAfter=$keep.ToArray()} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $run 'backup-and-plan.json') -Encoding UTF8
    & "$env:windir\System32\reg.exe" export 'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager' (Join-Path $run 'session-manager-before.reg') /y | Out-Null
    if($LASTEXITCODE -ne 0) {throw 'Registry backup failed.'}
    [string[]]$fresh=$key.GetValue($value)
    if([string]::Join([char]0,$before) -cne [string]::Join([char]0,$fresh)) {throw 'Queue changed during review; no write.'}
    if($Apply) {$key.SetValue($value,$keep.ToArray(),[Microsoft.Win32.RegistryValueKind]::MultiString);$key.Flush()}
    [string[]]$after=$key.GetValue($value)
    $expected=if($Apply){$keep.ToArray()}else{$before}
    $verified=[string]::Join([char]0,$after) -ceq [string]::Join([char]0,[string[]]$expected)
    [ordered]@{Applied=$Apply.IsPresent; RemovedOperations=if($Apply){7}else{0}; OriginalPairs=$before.Count/2; ActualPairs=$after.Count/2; ExactReadback=$verified; FilesDeletedOrRenamed=$false; After=$after; CompletedUtc=[datetime]::UtcNow.ToString('o')} | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $run 'result.json') -Encoding UTF8
    Write-Output ('Evidence='+$run+'; Applied='+$Apply+'; ExactReadback='+$verified)
    if(-not $verified) {throw 'Readback mismatch; inspect saved evidence before further writes.'}
} finally {$key.Close()}
