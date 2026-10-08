#requires -Version 5.1
#requires -RunAsAdministrator
<##
Standalone repair for the catalog-registration/SbatLevel corruption proven on this PC.
Run in elevated 64-bit Windows PowerShell 5.1. No companion project scripts or old
evidence are required. Repair needs the installed Windows SDK x86 SignTool when
fresh CBS records identify PnP catalog failures. No downloads, reboots, queue edits,
repository resets, or signature-policy changes are performed.
Exit 0: explicit clean full SFC result. Exit 3: unresolved/blocked/error.
-CheckOnly performs full SFC verification without repair.
##>
[CmdletBinding()]
param([switch]$CheckOnly,[ValidateRange(10,86400)][int]$NativeTimeoutSeconds=1800)
$ErrorActionPreference='Stop'
if($PSVersionTable.PSEdition -ne 'Desktop' -or -not [Environment]::Is64BitProcess) {throw 'Use elevated 64-bit Windows PowerShell 5.1.'}
$run=Join-Path $PSScriptRoot ('evidence\catalog-corruption-'+(Get-Date -Format 'yyyyMMdd-HHmmss-fff'))
$null=New-Item -ItemType Directory -Path $run
$result=[ordered]@{StartedUtc=[datetime]::UtcNow.ToString('o'); CheckOnly=$CheckOnly.IsPresent; Outcome='Incomplete'; CatalogsAdded=@(); SbatRepairAttempted=$false; RebootRequested=$false; Error=$null}
$key='HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
$queueBefore=@((Get-ItemProperty -LiteralPath $key).PendingFileRenameOperations)
$result.QueueBefore=$queueBefore
function Wait-Servicing {
    param([ValidateRange(5,600)][int]$MaxSeconds=600)
    $watch=[Diagnostics.Stopwatch]::StartNew(); $quiet=$null; $notice=-5
    $lastWorkers=$null;$lastPhase=$null;$lastLogWrite=$null;$lastCpu=@{}
    $cbs=Join-Path $env:windir 'Logs\CBS\CBS.log'
    Write-Host 'PRECHECK: Checking for existing Windows servicing before starting our scan.'
    Write-Host 'If servicing is busy, Windows owns that work; this script has not started a repair. Activity below comes from CBS.log and process CPU counters.'
    try {
    while($true) {
        $workers=@(Get-Process dism,sfc,TiWorker,TrustedInstaller -ErrorAction SilentlyContinue)
        if($workers.Count) {$quiet=$null} elseif($null -eq $quiet) {$quiet=$watch.Elapsed.TotalSeconds}
        if($null -ne $quiet -and $watch.Elapsed.TotalSeconds-$quiet -ge 30) {break}
        if($watch.Elapsed.TotalSeconds -ge $MaxSeconds) {throw "Windows servicing is still present after $MaxSeconds seconds. Our scan was not started. Latest observed activity: $lastPhase. No worker was terminated."}
        if($watch.Elapsed.TotalSeconds-$notice -ge 5) {
            $workerKey=(@($workers | Sort-Object Id | ForEach-Object { $_.Name+' PID '+$_.Id }) -join ', ')
            if($workerKey -ne $lastWorkers) {
                if($workers.Count){Write-Host ('WAITING FOR WINDOWS: '+$workerKey)}else{Write-Host 'Windows servicing processes exited. Checking for a continuous 30-second quiet interval.'}
                $lastWorkers=$workerKey
            }
            $cpuDelta=0.0
            foreach($w in $workers){$idKey=[string]$w.Id;if($lastCpu.ContainsKey($idKey)){$cpuDelta += [Math]::Max(0,$w.CPU-$lastCpu[$idKey])};$lastCpu[$idKey]=$w.CPU}
            $logAge='unavailable'
            try {
                $log=Get-Item -LiteralPath $cbs -ErrorAction Stop
                $logAge=('{0:N0}s' -f [Math]::Max(0,((Get-Date)-$log.LastWriteTime).TotalSeconds))
                if($log.LastWriteTimeUtc -ne $lastLogWrite) {
                    $tail=@(Get-Content -LiteralPath $cbs -Tail 80 -ErrorAction Stop)
                    $line=$tail | Where-Object {$_ -match '\[SR\]|Appl: Evaluating package applicability|Initiating changes|Processing|Session:|Reboot|corrupt|Failed|Error|Finaliz|Completed'} | Select-Object -Last 1
                    if(-not $line){$line=$tail | Where-Object {$_ -match '\S'} | Select-Object -Last 1}
                    $phase=[string]$line
                    # Keep source time, but suppress repeat records of the same activity.
                    $identity=$phase -replace '^.{19},\s*\w+\s+(CBS|CSI)\s+','' -replace '^\w{8}\s+',''
                    if($identity -and $identity -ne $lastPhase){Write-Host ('WINDOWS ACTIVITY (latest CBS record): '+$phase);$lastPhase=$identity}
                    $lastLogWrite=$log.LastWriteTimeUtc
                }
            }catch{if($lastPhase -ne 'CBS unavailable'){Write-Host ('CBS activity unavailable: '+$_.Exception.Message);$lastPhase='CBS unavailable'}}
            $remaining=[Math]::Max(0,$MaxSeconds-[int]$watch.Elapsed.TotalSeconds)
            $status=if($workers.Count){'Waiting on Windows | CBS last write '+$logAge+' ago | CPU since sample +'+('{0:N2}' -f $cpuDelta)+'s | timeout in '+$remaining+'s'}else{'No servicing processes | quiet '+[int]($watch.Elapsed.TotalSeconds-$quiet)+'/30s | timeout in '+$remaining+'s'}
            Write-Progress -Id 1 -Activity 'Precheck - our scan has NOT started' -Status $status
            $notice=$watch.Elapsed.TotalSeconds
        }
        Start-Sleep -Seconds 1
    }
    } finally {Write-Progress -Id 1 -Activity 'Precheck' -Completed}
    foreach($marker in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired',"$env:windir\WinSxS\pending.xml")) {
        if(Test-Path -LiteralPath $marker) {throw "Native servicing reboot marker present: $marker. Not bypassed."}
    }
    if(@(Get-Process dism,sfc,TiWorker,TrustedInstaller -ErrorAction SilentlyContinue).Count) {throw 'Servicing started during preflight.'}
    Write-Host 'PRECHECK PASSED: no native reboot marker; Windows servicing is quiet. Starting the requested check.'
}
function Invoke-Native([string]$Exe,[string]$Arguments,[string]$Label,[switch]$Unicode) {
    # An independent worker owns and drains native pipes even if this controller times out.
    # Never kill Windows servicing or restart an operation after an observation timeout.
    $worker=Join-Path $run 'native-worker.ps1'
    if(-not (Test-Path -LiteralPath $worker)) {
        @'
param([string]$Spec)
$ErrorActionPreference='Stop'
$s=Get-Content -Raw -LiteralPath $Spec | ConvertFrom-Json
$p=New-Object Diagnostics.Process
try {
 $p.StartInfo.FileName=$s.Exe;$p.StartInfo.Arguments=$s.Arguments
 $p.StartInfo.UseShellExecute=$false;$p.StartInfo.CreateNoWindow=$true
 $p.StartInfo.RedirectStandardOutput=$true;$p.StartInfo.RedirectStandardError=$true
 if($s.Unicode){$p.StartInfo.StandardOutputEncoding=[Text.Encoding]::Unicode}
 $null=$p.Start()
 @{PID=$p.Id;StartedUtc=[datetime]::UtcNow.ToString('o')} | ConvertTo-Json | Set-Content -LiteralPath $s.State -Encoding UTF8
 $outWriter=New-Object IO.StreamWriter($s.Stdout,$false,[Text.Encoding]::UTF8)
 $errWriter=New-Object IO.StreamWriter($s.Stderr,$false,[Text.Encoding]::UTF8)
 $ob=New-Object char[] 1024;$eb=New-Object char[] 1024
 $ot=$p.StandardOutput.ReadAsync($ob,0,$ob.Length);$et=$p.StandardError.ReadAsync($eb,0,$eb.Length)
 $od=$false;$ed=$false
 while(-not ($od -and $ed -and $p.HasExited)) {
  if(-not $od -and $ot.IsCompleted){$n=$ot.GetAwaiter().GetResult();if($n -eq 0){$od=$true}else{$outWriter.Write($ob,0,$n);$outWriter.Flush();$ot=$p.StandardOutput.ReadAsync($ob,0,$ob.Length)}}
  if(-not $ed -and $et.IsCompleted){$n=$et.GetAwaiter().GetResult();if($n -eq 0){$ed=$true}else{$errWriter.Write($eb,0,$n);$errWriter.Flush();$et=$p.StandardError.ReadAsync($eb,0,$eb.Length)}}
  Start-Sleep -Milliseconds 50
 }
 $p.WaitForExit();$outWriter.Dispose();$errWriter.Dispose()
 @{Exe=$s.Exe;Arguments=$s.Arguments;ExitCode=$p.ExitCode;Output=[IO.File]::ReadAllText($s.Stdout);ErrorOutput=[IO.File]::ReadAllText($s.Stderr)} | ConvertTo-Json | Set-Content -LiteralPath ($s.Receipt+'.tmp') -Encoding UTF8
 Move-Item -LiteralPath ($s.Receipt+'.tmp') -Destination $s.Receipt
} catch {
 @{WorkerError=$_.Exception.Message;ExitCode=-1} | ConvertTo-Json | Set-Content -LiteralPath ($s.Receipt+'.tmp') -Encoding UTF8
 Move-Item -LiteralPath ($s.Receipt+'.tmp') -Destination $s.Receipt
} finally {if($outWriter){$outWriter.Dispose()};if($errWriter){$errWriter.Dispose()};$p.Dispose()}
'@ | Set-Content -LiteralPath $worker -Encoding UTF8
    }
    $spec=[ordered]@{Exe=$Exe;Arguments=$Arguments;Unicode=$Unicode.IsPresent;State=(Join-Path $run ($Label+'-pid.json'));Stdout=(Join-Path $run ($Label+'-stdout.txt'));Stderr=(Join-Path $run ($Label+'-stderr.txt'));Receipt=(Join-Path $run ($Label+'.json'))}
    $specPath=Join-Path $run ($Label+'-spec.json')
    $spec | ConvertTo-Json | Set-Content -LiteralPath $specPath -Encoding UTF8
    $args='-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$worker+'" -Spec "'+$specPath+'"'
    $owner=Start-Process -FilePath "$env:windir\System32\WindowsPowerShell\v1.0\powershell.exe" -ArgumentList $args -WindowStyle Hidden -PassThru
    $watch=[Diagnostics.Stopwatch]::StartNew();$notice=-5;$offsets=@(0,0);$lastOutput=0
    Write-Host ('[{0:HH:mm:ss}] Starting {1}; monitor PID={2}' -f (Get-Date),$Label,$owner.Id)
    while($true) {
        $streams=@($spec.Stdout,$spec.Stderr)
        for($i=0;$i -lt 2;$i++) {
            if(Test-Path -LiteralPath $streams[$i]) {
                $handle=[IO.File]::Open($streams[$i],[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
                $reader=New-Object IO.StreamReader($handle)
                try {$text=$reader.ReadToEnd()} finally {$reader.Dispose()}
                if($text.Length -gt $offsets[$i]) {Write-Host -NoNewline $text.Substring($offsets[$i]);$offsets[$i]=$text.Length;$lastOutput=$watch.Elapsed.TotalSeconds}
            }
        }
        if(Test-Path -LiteralPath $spec.Receipt) {break}
        if($owner.HasExited) {throw "Native monitor exited without a receipt: $Label. Inspect $run; do not restart blindly."}
        if($watch.Elapsed.TotalSeconds-$notice -ge 5) {
            Write-Progress -Id 2 -Activity ('Running '+$Label) -Status ('Elapsed {0:N0}s | last native output {1:N0}s ago | timeout in {2:N0}s | live stdout/stderr shown below' -f $watch.Elapsed.TotalSeconds,($watch.Elapsed.TotalSeconds-$lastOutput),[Math]::Max(0,$NativeTimeoutSeconds-$watch.Elapsed.TotalSeconds))
            $notice=$watch.Elapsed.TotalSeconds
        }
        if($watch.Elapsed.TotalSeconds -ge $NativeTimeoutSeconds) {
            Write-Progress -Id 2 -Activity $Label -Completed
            throw "Observation timeout for $Label. Independent monitor PID=$($owner.Id) and native servicing may still be running. Not killed or retried. Watch $($spec.Stdout) and final receipt $($spec.Receipt)."
        }
        Start-Sleep -Milliseconds 200
    }
    $receipt=Get-Content -Raw -LiteralPath $spec.Receipt | ConvertFrom-Json
    Write-Progress -Id 2 -Activity $Label -Completed
    if($receipt.PSObject.Properties['WorkerError']) {throw $receipt.WorkerError}
    if($receipt.Output.Length -gt $offsets[0]) {Write-Host -NoNewline $receipt.Output.Substring($offsets[0])}
    if($receipt.ErrorOutput.Length -gt $offsets[1]) {Write-Host -NoNewline $receipt.ErrorOutput.Substring($offsets[1])}
    Write-Host ('[{0:HH:mm:ss}] Finished {1}; exit={2}' -f (Get-Date),$Label,$receipt.ExitCode)
    return $receipt
}
function Test-Clean($Receipt) {return ($Receipt.ExitCode -eq 0 -and $Receipt.Output -match 'Windows Resource Protection did not find any integrity violations\.')}
try {
    Write-Host ('Evidence: '+$run)
    Wait-Servicing
    $scanStart=Get-Date
    $initial=Invoke-Native "$env:windir\System32\sfc.exe" '/verifyonly' 'initial-sfc' -Unicode
    if(Test-Clean $initial) {$result.Outcome='VerifiedClean'}
    elseif($CheckOnly) {throw 'Full SFC is not explicitly clean; CheckOnly made no repairs.'}
    else {
        if($initial.ExitCode -ne 0 -or $initial.Output -notmatch 'Windows Resource Protection found') {throw 'SFC did not complete a recognized corruption scan. Inspect captured output.'}
        # Select only records from this scan, never historical corruption lines.
        Write-Host ('[{0:HH:mm:ss}] Reading fresh CBS findings' -f (Get-Date))
        $fresh=@(Get-Content -LiteralPath "$env:windir\Logs\CBS\CBS.log" | Where-Object {
            $stamp=[datetime]::MinValue
            $_.Length -ge 19 -and [datetime]::TryParseExact($_.Substring(0,19),'yyyy-MM-dd HH:mm:ss',[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::None,[ref]$stamp) -and $stamp -ge $scanStart.AddSeconds(-1)
        })
        $fresh | Set-Content -LiteralPath (Join-Path $run 'fresh-CBS.txt') -Encoding UTF8
        $files=@($fresh | ForEach-Object {if($_ -match 'DEPLOY \[Pnp\] Corrupt file: (.+)$') {$Matches[1].Trim()}} | Sort-Object -Unique)
        $sbat=Join-Path $env:windir 'System32\catroot\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}\SbatLevel.cat'
        if($files.Count) {
            $tool=Join-Path $PSScriptRoot 'Tools\signtool.exe'
            if(-not (Test-Path -LiteralPath $tool)) {$tool='C:\Program Files (x86)\Windows Kits\10\Tools\bin\i386\signtool.exe'}
            if(-not (Test-Path -LiteralPath $tool)) {throw 'Windows SDK x86 SignTool is required for exact catalog validation; no files downloaded.'}
            Add-Type -TypeDefinition @'
using System; using System.IO; using System.Collections.Generic; using System.ComponentModel; using System.Runtime.InteropServices;
public static class StandaloneCatalogEvidence {
 [DllImport("wintrust.dll",CharSet=CharSet.Unicode,ExactSpelling=true,SetLastError=true)] static extern bool CryptCATAdminAcquireContext2(out IntPtr c,IntPtr s,string a,IntPtr p,uint f);
 [DllImport("wintrust.dll",ExactSpelling=true,SetLastError=true)] static extern bool CryptCATAdminCalcHashFromFileHandle2(IntPtr c,IntPtr h,ref uint n,byte[] b,uint f);
 [DllImport("wintrust.dll",ExactSpelling=true)] static extern bool CryptCATAdminReleaseContext(IntPtr c,uint f);
 [DllImport("wintrust.dll",CharSet=CharSet.Unicode,ExactSpelling=true,SetLastError=true)] static extern IntPtr CryptCATOpen(string p,uint f,IntPtr h,uint v,uint e);
 [DllImport("wintrust.dll",ExactSpelling=true)] static extern IntPtr CryptCATEnumerateMember(IntPtr c,IntPtr p);
 [DllImport("wintrust.dll",ExactSpelling=true)] static extern bool CryptCATClose(IntPtr c);
 [StructLayout(LayoutKind.Sequential)] struct Head {public uint Size;public IntPtr Tag;public IntPtr Name;}
 public static string Hash(string p) {IntPtr c;if(!CryptCATAdminAcquireContext2(out c,IntPtr.Zero,"SHA256",IntPtr.Zero,0))throw new Win32Exception();try {using(var s=new FileStream(p,FileMode.Open,FileAccess.Read,FileShare.ReadWrite|FileShare.Delete)){uint n=0;CryptCATAdminCalcHashFromFileHandle2(c,s.SafeFileHandle.DangerousGetHandle(),ref n,null,0);if(n==0||n>128)throw new Exception("Hash size");byte[] b=new byte[n];s.Position=0;if(!CryptCATAdminCalcHashFromFileHandle2(c,s.SafeFileHandle.DangerousGetHandle(),ref n,b,0))throw new Win32Exception();return BitConverter.ToString(b).Replace("-","");}}finally{CryptCATAdminReleaseContext(c,0);}}
 public static string[] Matches(string p,string[] hashes) {var wanted=new HashSet<string>(hashes,StringComparer.OrdinalIgnoreCase);var found=new List<string>();IntPtr c=CryptCATOpen(p,0,IntPtr.Zero,0x200,0);if(c==IntPtr.Zero||c==new IntPtr(-1))throw new Win32Exception();try{IntPtr m=IntPtr.Zero;while((m=CryptCATEnumerateMember(c,m))!=IntPtr.Zero){var h=(Head)Marshal.PtrToStructure(m,typeof(Head));string t=Marshal.PtrToStringUni(h.Tag);if(t!=null&&wanted.Contains(t))found.Add(t);}}finally{CryptCATClose(c);}return found.ToArray();}
}
'@
            $root=[IO.Path]::GetFullPath("$env:windir\System32\")
            $hashes=@{}; $beforeHashes=@{}; $candidates=@{}
            $fileNumber=0
            foreach($file in $files) {
                $fileNumber++;Write-Host ('Hashing installed file {0}/{1}: {2}' -f $fileNumber,$files.Count,$file)
                $full=[IO.Path]::GetFullPath($file)
                if(-not $full.StartsWith($root,[StringComparison]::OrdinalIgnoreCase) -or -not (Test-Path -LiteralPath $full -PathType Leaf)) {throw "Unexpected or missing PnP target: $full"}
                $hashes[$file]=[StandaloneCatalogEvidence]::Hash($full)
                $beforeHashes[$file]=(Get-FileHash -LiteralPath $full -Algorithm SHA256).Hash
                $candidates[$file]=@()
            }
            $catalogs=@(Get-ChildItem -LiteralPath "$env:windir\WinSxS\Catalogs" -File -Filter *.cat);$catalogNumber=0
            foreach($cat in $catalogs) {
                $catalogNumber++;if($catalogNumber % 50 -eq 1 -or $catalogNumber -eq $catalogs.Count){Write-Host ('Indexing catalog {0}/{1}' -f $catalogNumber,$catalogs.Count)}
                $hits=@([StandaloneCatalogEvidence]::Matches($cat.FullName,[string[]]@($hashes.Values)))
                foreach($file in $files) {if($hashes[$file] -in $hits) {$candidates[$file]+=$cat.FullName}}
            }
            $plan=@();$counter=0
            foreach($file in $files) {
                $target='"'+(Join-Path $env:windir ('Sysnative\'+$file.Substring($root.Length)))+'"'
                $selected=$null
                foreach($cat in $candidates[$file]) {
                    $sig=Get-AuthenticodeSignature -LiteralPath $cat
                    if($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'CN=Microsoft Windows,') {continue}
                    $counter++
                    $proof=Invoke-Native $tool ('verify /kp /hash SHA256 /v /c "'+$cat+'" '+$target) ('catalog-proof-'+$counter)
                    if($proof.ExitCode -eq 0) {$selected=$cat;break}
                }
                if(-not $selected) {throw "No independently verified Microsoft catalog for $file; no registrations made."}
                $plan += [pscustomobject]@{File=$file;ToolTarget=$target;Catalog=$selected;CatalogHash=(Get-FileHash -LiteralPath $selected -Algorithm SHA256).Hash}
            }
            $plan | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $run 'validated-plan.json') -Encoding UTF8
            foreach($item in $plan) {if((Get-FileHash -LiteralPath $item.File -Algorithm SHA256).Hash -ne $beforeHashes[$item.File]) {throw 'Target changed during preflight.'}}
            $counter=0
            foreach($group in @($plan | Group-Object Catalog)) {
                $counter++;$cat=$group.Name
                if((Get-FileHash -LiteralPath $cat -Algorithm SHA256).Hash -ne $group.Group[0].CatalogHash) {throw 'Catalog changed after validation.'}
                $existing=Invoke-Native $tool ('verify /a /kp /hash SHA256 '+(($group.Group.ToolTarget) -join ' ')) ('automatic-before-'+$counter)
                if($existing.ExitCode -ne 0) {
                    $add=Invoke-Native $tool ('catdb /u /v "'+$cat+'"') ('register-'+$counter)
                    if($add.ExitCode -ne 0) {throw 'Catalog registration failed; inspect receipts.'}
                    $result.CatalogsAdded+= $cat
                }
            }
            $counter=0
            foreach($item in $plan) {
                $counter++
                $verify=Invoke-Native $tool ('verify /a /kp /hash SHA256 '+$item.ToolTarget) ('automatic-after-'+$counter)
                if($verify.ExitCode -ne 0 -or (Get-FileHash -LiteralPath $item.File -Algorithm SHA256).Hash -ne $beforeHashes[$item.File]) {throw 'Automatic catalog verification or unchanged-file check failed.'}
            }
        }
        if(-not (Test-Path -LiteralPath $sbat) -or @($fresh | Where-Object {$_ -match 'SbatLevel\.cat'}).Count) {
            Wait-Servicing
            $result.SbatRepairAttempted=$true
            $repair=Invoke-Native "$env:windir\System32\sfc.exe" ('/scanfile='+$sbat) 'sbat-repair' -Unicode
            if($repair.ExitCode -ne 0) {throw 'Targeted Sbat repair failed.'}
        }
        Wait-Servicing
        $final=Invoke-Native "$env:windir\System32\sfc.exe" '/verifyonly' 'final-sfc' -Unicode
        if(-not (Test-Clean $final)) {throw 'Full SFC remains unverified or corrupt. Other failure types require diagnosis; no forced reboot bypass.'}
        $result.Outcome='VerifiedClean'
    }
} catch {$result.Error=$_.Exception.Message;Write-Warning $result.Error}
finally {
    $result.QueueAfter=@((Get-ItemProperty -LiteralPath $key).PendingFileRenameOperations)
    $result.QueueUnchanged=[string]::Join([char]0,[string[]]$queueBefore) -ceq [string]::Join([char]0,[string[]]$result.QueueAfter)
    $result.CompletedUtc=[datetime]::UtcNow.ToString('o')
    $result | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $run 'result.json') -Encoding UTF8
    Write-Host ($result.Outcome+'; evidence='+$run)
}
if($result.Outcome -ne 'VerifiedClean') {exit 3}
