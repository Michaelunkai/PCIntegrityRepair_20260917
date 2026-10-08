#requires -Version 5.1
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$run=Join-Path $PSScriptRoot ('evidence\boot-operations-'+(Get-Date -Format 'yyyyMMdd-HHmmss-fff'))
$null=New-Item -ItemType Directory -Path $run
$raw=@((Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager').PendingFileRenameOperations)
if($raw.Count % 2) {throw 'Incomplete pending operation pair.'}
function Get-DisplayPath([string]$RawPath) {
    # Strip markers only to inspect the referenced file; this does not interpret boot-time flag semantics.
    $p=$RawPath -replace '^\*[12]','' -replace '^!',''
    if($p.StartsWith('\??\')) {$p=$p.Substring(4)}
    if($p -notmatch '^[A-Za-z]:\\') {return $null}
    return $p
}
$drivers=@(Get-CimInstance Win32_SystemDriver)
$rows=@()
for($i=0;$i -lt $raw.Count;$i+=2) {
    $source=Get-DisplayPath $raw[$i]
    $destination=if($raw[$i+1]){Get-DisplayPath $raw[$i+1]}else{$null}
    $exists=if($source){Test-Path -LiteralPath $source}else{$null}
    $destExists=if($destination){Test-Path -LiteralPath $destination}else{$null}
    $refs=@()
    if($source) {
        $leaf=[IO.Path]::GetFileName($source)
        $refs=@($drivers | Where-Object { $_.PathName -and [IO.Path]::GetFileName(($_.PathName.Trim('"'))) -eq $leaf } | Select-Object Name,State,StartMode)
    }
    $signature=if($exists -and $source.EndsWith('.sys')){[string](Get-AuthenticodeSignature -LiteralPath $source).Status}else{$null}
    $rows += [pscustomobject]@{Pair=$i/2;RawSource=$raw[$i];RawDestination=$raw[$i+1];Source=$source;Destination=$destination;SourceExists=$exists;DestinationExists=$destExists;DriverReferences=$refs;SignatureStatus=$signature}
}
$markers=@()
foreach($marker in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired',"$env:windir\WinSxS\pending.xml")) {
    $markers += [pscustomobject]@{Path=$marker;Exists=(Test-Path -LiteralPath $marker)}
}
$report=[ordered]@{CapturedUtc=[datetime]::UtcNow.ToString('o');PairCount=$rows.Count;Operations=$rows;NativeMarkers=$markers;ChangesMade=$false;Caveat='File existence and driver references alone do not prove reboot safety. Prefixes are preserved verbatim; stripping is only for metadata inspection.'}
$report | ConvertTo-Json -Depth 7 | Set-Content -LiteralPath (Join-Path $run 'report.json') -Encoding UTF8
Write-Output ('Report='+$run)
$rows | Select-Object Pair,Source,SourceExists,DestinationExists,SignatureStatus,@{Name='DriverRefs';Expression={$_.DriverReferences.Count}} | Format-Table -AutoSize
$markers | Format-Table -AutoSize
