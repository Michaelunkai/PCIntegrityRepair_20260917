# Embedded into the delivered repair script by Build-RepairPackage.ps1.
function Ensure-CrashCapturePrerequisites {
    $computer=Get-CimInstance Win32_ComputerSystem -OperationTimeoutSec 20
    $paging=@((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management').PagingFiles | Where-Object {$_})
    if(-not $computer.AutomaticManagedPagefile -and -not $paging.Count){
        [ordered]@{CapturedUtc=[datetime]::UtcNow.ToString('o');AutomaticManagedPagefile=$computer.AutomaticManagedPagefile;PagingFiles=$paging;Change='User-authorized restoration of system-managed paging when no pagefile is configured.'} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $run 'paging-before.json') -Encoding UTF8
        Write-Host 'CRASH CAPTURE: restoring system-managed paging. Activation may require reboot; no reboot will be initiated.'
        $null=Set-CimInstance -InputObject $computer -Property @{AutomaticManagedPagefile=$true} -OperationTimeoutSec 20
        $after=Get-CimInstance Win32_ComputerSystem -OperationTimeoutSec 20
        if(-not $after.AutomaticManagedPagefile){throw 'System-managed paging setting did not persist.'}
        [ordered]@{AutomaticManagedPagefile=$after.AutomaticManagedPagefile;PagingFiles=@((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management').PagingFiles);ActivePagefiles=@(Get-CimInstance Win32_PageFileUsage -OperationTimeoutSec 20 | Select-Object Name,AllocatedBaseSize);RebootPerformed=$false} | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $run 'paging-after.json') -Encoding UTF8
        Write-Host 'System-managed paging configuration verified. Active crash-dump capacity must be checked after the next boot.'
    }
}
function Get-RebootGateOutcome([int]$IssueCount,[bool]$InventoryComplete,[bool]$NativeChecksPassed) {
    if($IssueCount -gt 0 -or -not $InventoryComplete -or -not $NativeChecksPassed){return 'NeedsAttention'}
    return 'ChecksPassed_NotBootTested'
}
function Invoke-RebootReadiness {
    Write-Host 'REBOOT READINESS: checking storage, boot configuration, drivers, services, pending operations, recovery, and crash evidence. No automatic reboot.'
    $worker=Join-Path $run 'reboot-inventory.ps1'
    @'
param([string]$OutputDirectory)
$ErrorActionPreference='Stop'
$report=[ordered]@{CapturedUtc=[datetime]::UtcNow.ToString('o');Complete=$false;Checks=@();Issues=@();Data=[ordered]@{};Limitations=@('No actual reboot tested.','No offline RAM/firmware or exhaustive hardware test.','A clean scan does not establish the cause of a previous CRITICAL_PROCESS_DIED crash.')}
function Save { $report | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath (Join-Path $OutputDirectory 'reboot-inventory.json') -Encoding UTF8 }
function Issue($Check,$Detail){$report.Issues+= [pscustomobject]@{Check=$Check;Detail=$Detail};Write-Host "ATTENTION [$Check]: $Detail"}
function Check($Name,[scriptblock]$Action){Write-Host "CHECK: $Name";try{& $Action;$report.Checks+=@{Name=$Name;Completed=$true}}catch{Issue $Name ('Check unavailable: '+$_.Exception.Message);$report.Checks+=@{Name=$Name;Completed=$false}};Save}
function Events($Filter,[int]$Maximum=1000){try{return @(Get-WinEvent -FilterHashtable $Filter -MaxEvents $Maximum -ErrorAction Stop)}catch{if($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*'){return @()};throw}}
function DisplayPath([string]$Value){$p=$Value -replace '^\*[12]','' -replace '^!','';if($p.StartsWith('\??\')){$p=$p.Substring(4)};if($p -notmatch '^[A-Za-z]:\\'){return $null};return [IO.Path]::GetFullPath($p)}
$os=Get-CimInstance Win32_OperatingSystem -OperationTimeoutSec 20
$report.Data.LastBootUpTime=$os.LastBootUpTime
$since=(Get-Date).AddDays(-7)
Check 'Storage health and free space' {
 $disks=@(Get-Disk | Select-Object Number,FriendlyName,BusType,HealthStatus,OperationalStatus,IsBoot,IsSystem)
 $report.Data.Disks=$disks
 foreach($d in $disks){if([string]$d.HealthStatus -ne 'Healthy' -or [string]$d.OperationalStatus -ne 'Online'){Issue 'Storage' ("Disk $($d.Number): $($d.HealthStatus), $($d.OperationalStatus)")}}
 $vol=Get-Volume -DriveLetter $env:SystemDrive.Substring(0,1)
 $report.Data.SystemVolume=$vol | Select-Object DriveLetter,HealthStatus,Size,SizeRemaining
 if([string]$vol.HealthStatus -ne 'Healthy' -or $vol.SizeRemaining -lt 10GB){Issue 'System volume' 'Unhealthy status or less than 10 GB free.'}
 $report.Data.ProjectVolumeDisk=Get-Partition -DriveLetter ([IO.Path]::GetPathRoot($OutputDirectory).Substring(0,1)) | Get-Disk | Select-Object Number,FriendlyName,BusType
}
Check 'Recent crashes, hardware errors, storage retries, and service failures' {
 $queries=@(
 @{LogName='System';ProviderName='Microsoft-Windows-WER-SystemErrorReporting';Id=1001;StartTime=$since},
 @{LogName='System';ProviderName='Microsoft-Windows-Kernel-Power';Id=41;StartTime=$since},
 @{LogName='System';ProviderName='disk';Id=7,11,51,153,157;StartTime=$since},
 @{LogName='System';ProviderName='Microsoft-Windows-Ntfs';Id=55,98,140;Level=1,2,3;StartTime=$since},
 @{LogName='System';ProviderName='Microsoft-Windows-WHEA-Logger';Level=1,2;StartTime=$since},
 @{LogName='System';ProviderName='Service Control Manager';Id=7000,7001,7023,7024,7026,7031,7034;StartTime=$os.LastBootUpTime}
 )
 $events=@();foreach($q in $queries){$events+=@(Events $q)}
 # Storage provider names vary by controller; filter matching IDs by provider, not ID alone.
 $events+=@(Events @{LogName='System';Id=129;StartTime=$since} | Where-Object ProviderName -match 'stor|nvme|ahci|iaStor')
 $report.Data.Events=@($events | Sort-Object TimeCreated | Select-Object TimeCreated,ProviderName,Id,Message)
 foreach($g in @($events | Group-Object ProviderName,Id)){Issue 'Event history' ("$($g.Count) event(s): $($g.Name); latest $((($g.Group | Sort-Object TimeCreated -Descending)[0]).TimeCreated). See full report; historical events are not automatically proof of an ongoing fault.")}
 $oldest=Get-WinEvent -LogName System -Oldest -MaxEvents 1
 $report.Data.SystemLogOldest=$oldest.TimeCreated
 if($oldest.TimeCreated -gt $since){Issue 'Crash history coverage' ('System event history starts '+$oldest.TimeCreated+'; less than seven days are available. Absence of crashes is not proof of no prior crash.')}
 $dumps=@(Get-Item "$env:windir\MEMORY.DMP" -ErrorAction SilentlyContinue | Select-Object FullName,Length,LastWriteTime)
 if(Test-Path "$env:windir\Minidump"){$dumps+=@(Get-ChildItem "$env:windir\Minidump" -File | Select-Object FullName,Length,LastWriteTime)}
 $report.Data.Dumps=$dumps
 if($dumps.Count){Issue 'Crash dumps' 'Crash dumps exist; this script does not infer their cause or silently mark them resolved.'}
}
Check 'Boot and system driver files' {
 $drivers=@(Get-CimInstance Win32_SystemDriver -OperationTimeoutSec 20 | Where-Object {$_.StartMode -in 'Boot','System' -or $_.State -eq 'Running'})
 $rows=@();$n=0
 foreach($d in $drivers){$n++;Write-Host "Driver $n/$($drivers.Count): $($d.Name)";$p=[Environment]::ExpandEnvironmentVariables([string]$d.PathName).Trim('"');if($p.StartsWith('\??\')){$p=$p.Substring(4)};if($p.StartsWith('\SystemRoot\',[StringComparison]::OrdinalIgnoreCase)){$p=Join-Path $env:windir $p.Substring(12)};if($p.StartsWith('System32\',[StringComparison]::OrdinalIgnoreCase)){$p=Join-Path $env:windir $p};$exists=$p -and (Test-Path -LiteralPath $p -PathType Leaf);$cfg=Get-ItemProperty -LiteralPath ('HKLM:\SYSTEM\CurrentControlSet\Services\'+$d.Name);$rows+=[pscustomobject]@{Name=$d.Name;StartMode=$d.StartMode;State=$d.State;ExitCode=$d.ExitCode;ErrorControl=$cfg.ErrorControl;Path=$p;Exists=[bool]$exists};if(-not $exists){Issue 'Driver file' ("Missing/unresolved $($d.Name): $p")};if($d.ExitCode -ne 0 -and ($d.State -eq 'Running' -or $cfg.ErrorControl -eq 3)){Issue 'Driver status' ("$($d.Name) reports exit $($d.ExitCode); running or configured boot-critical")}}
 $report.Data.Drivers=$rows
}
Check 'Essential services and present devices' {
 $services=@(Get-Service RpcSs,DcomLaunch,EventLog,PlugPlay,Power,Winmgmt,CryptSvc,BFE,MpsSvc | Select-Object Name,Status)
 $report.Data.Services=$services
 foreach($s in $services){if([string]$s.Status -ne 'Running'){Issue 'Essential service' ("$($s.Name) is $($s.Status)")}}
 $devices=@(Get-CimInstance Win32_PnPEntity -Filter 'ConfigManagerErrorCode <> 0' -OperationTimeoutSec 20 | Where-Object Present -eq $true | Select-Object Name,PNPClass,ConfigManagerErrorCode)
 $report.Data.DeviceProblems=$devices
 foreach($d in $devices){Issue 'Device' ("$($d.Name): code $($d.ConfigManagerErrorCode)")}
}
Check 'Pending boot operations and servicing markers' {
 $raw=@((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager').PendingFileRenameOperations)
 if($raw.Count % 2){throw 'Malformed pending-operation pairs'}
 $rows=@();for($i=0;$i -lt $raw.Count;$i+=2){$src=DisplayPath $raw[$i];$dst=if($raw[$i+1]){DisplayPath $raw[$i+1]}else{$null};$rows+=@{Source=$src;Destination=$dst;RawSource=$raw[$i];RawDestination=$raw[$i+1]};if(-not $src -or ($raw[$i+1] -and -not $dst)){Issue 'Pending operation' 'Unrecognized path encoding; queue was preserved.';continue};$protected=$src.StartsWith($env:windir+'\System32\',[StringComparison]::OrdinalIgnoreCase) -or $src.StartsWith($env:windir+'\WinSxS\',[StringComparison]::OrdinalIgnoreCase);if((Test-Path -LiteralPath $src) -and ($protected -or ($dst -and $dst.StartsWith($env:windir+'\',[StringComparison]::OrdinalIgnoreCase)))){Issue 'Pending protected-file operation' ("$src -> $dst; requires review, not blindly cleared.")}}
 $report.Data.PendingOperations=$rows
 foreach($m in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired',"$env:windir\WinSxS\pending.xml")){if(Test-Path $m){Issue 'Pending servicing' $m}}
}
Check 'Crash capture and encryption recovery requirements' {
 $dump=Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl'
 $pages=@(Get-CimInstance Win32_PageFileUsage -OperationTimeoutSec 20 | Select-Object Name,AllocatedBaseSize)
 $automatic=(Get-CimInstance Win32_ComputerSystem -OperationTimeoutSec 20).AutomaticManagedPagefile
 $report.Data.CrashCapture=@{CrashDumpEnabled=$dump.CrashDumpEnabled;PageFiles=$pages;DedicatedDumpFile=$dump.DedicatedDumpFile;AutomaticManagedPagefile=$automatic}
 if(-not $dump.CrashDumpEnabled){Issue 'Crash capture' 'Memory dump capture is disabled.'}
 if(-not $pages.Count -and -not $dump.DedicatedDumpFile){Issue 'Crash capture' ("No active pagefile or dedicated dump file was reported. System-managed paging configured=$automatic; activation remains unverified until a later boot.")}
 $bl=@(Get-BitLockerVolume | Select-Object MountPoint,VolumeStatus,ProtectionStatus,LockStatus)
 $report.Data.Encryption=$bl
 if(@($bl | Where-Object { [string]$_.ProtectionStatus -eq 'On' }).Count){Issue 'Recovery prerequisite' 'Encrypted volume present. Verify an externally accessible recovery key before reboot; keys are not collected by this script.'}
}
$report.Complete=$true;Save
Write-Host ('Inventory complete: '+$report.Issues.Count+' item(s) require attention. No Windows settings changed by inventory.')
'@ | Set-Content -LiteralPath $worker -Encoding UTF8
    $inventory=Invoke-Native "$env:windir\System32\WindowsPowerShell\v1.0\powershell.exe" ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$worker+'" -OutputDirectory "'+$run+'"') 'reboot-inventory-worker'
    if($inventory.ExitCode -ne 0){throw 'Reboot inventory did not complete. Reboot readiness is unknown.'}
    $data=Get-Content -Raw -LiteralPath (Join-Path $run 'reboot-inventory.json') | ConvertFrom-Json
    $checks=@();$issues=@($data.Issues)
    function GateResult($Name,[bool]$Passed,$Detail){Write-Host ("READINESS [$Name]: "+$(if($Passed){'PASS'}else{'ATTENTION'})+" - $Detail");return [pscustomobject]@{Name=$Name;Passed=$Passed;Detail=$Detail}}
    Wait-Servicing
    $dism=Invoke-Native "$env:windir\System32\dism.exe" '/Online /Cleanup-Image /ScanHealth /English /NoRestart' 'readiness-component-store'
    $checks+=GateResult 'Component store' ($dism.ExitCode -eq 0 -and $dism.Output -match 'No component store corruption detected') 'Full DISM ScanHealth; a nonzero or unrecognized result is not accepted.'
    $disk=Invoke-Native "$env:windir\System32\chkdsk.exe" ($env:SystemDrive+' /scan') 'readiness-system-filesystem'
    $checks+=GateResult 'System filesystem' ($disk.ExitCode -eq 0 -and $disk.Output -match 'found no problems') 'Online CHKDSK scan; no offline repair or reboot was scheduled.'
    if($disk.ExitCode -ne 0){
        $scanWorker=Join-Path $run 'storage-scan.ps1'
        "`$ErrorActionPreference='Stop'; Repair-Volume -DriveLetter `$env:SystemDrive.Substring(0,1) -Scan -ErrorAction Stop" | Set-Content -LiteralPath $scanWorker -Encoding UTF8
        $alternative=Invoke-Native "$env:windir\System32\WindowsPowerShell\v1.0\powershell.exe" ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$scanWorker+'"') 'readiness-alternate-filesystem'
        $checks+=GateResult 'Alternative storage scan' ($alternative.ExitCode -eq 0 -and $alternative.Output -match 'NoErrorsFound') 'Windows Repair-Volume online scan. An alternative pass does not erase a contradictory CHKDSK failure.'
    }
    $bcd=Invoke-Native "$env:windir\System32\bcdedit.exe" '/enum {current}' 'readiness-loader'
    $boot=Invoke-Native "$env:windir\System32\bcdedit.exe" '/enum {bootmgr}' 'readiness-bootmgr'
    $checks+=GateResult 'Boot configuration' ($bcd.ExitCode -eq 0 -and $boot.ExitCode -eq 0 -and $bcd.Output -match '\\Windows\\system32\\winload\.efi' -and $bcd.Output -notmatch '(?im)^\s*(testsigning|nointegritychecks)\s+Yes|^\s*safeboot\s' -and $boot.Output -match '\\EFI\\Microsoft\\Boot\\bootmgfw\.efi') 'Readable UEFI loader/manager entries; no test-signing, integrity bypass, or forced Safe Mode. This does not exercise firmware boot.'
    $re=Invoke-Native "$env:windir\System32\reagentc.exe" '/info' 'readiness-recovery'
    $checks+=GateResult 'Recovery environment' ($re.ExitCode -eq 0 -and $re.Output -match 'Windows RE status:\s+Enabled') 'Windows RE is registered and enabled; actual recovery boot not tested.'
    $targets=@($data.Data.Drivers | Where-Object Exists -eq $true | Select-Object -ExpandProperty Path -Unique)
    $targets+=@(Get-CriticalWindowsFiles)
    if($boot.Output -match 'partition=(\\Device\\HarddiskVolume\d+)'){$targets+=('\\?\GLOBALROOT'+$Matches[1]+'\EFI\Microsoft\Boot\bootmgfw.efi')}else{$checks+=GateResult 'EFI boot file location' $false 'Could not resolve the configured EFI volume; boot-file trust is unverified.'}
    $n=0;foreach($path in $targets){$n++;Write-Host "Verifying boot/system file $n/$($targets.Count): $path";$nativePath=$path -replace '(?i)\\system32\\','\Sysnative\';if($path.EndsWith('.sys',[StringComparison]::OrdinalIgnoreCase)){$r=Invoke-DriverTrust $nativePath ('readiness-trust-'+$n)}else{$r=Invoke-Native $tool ('verify /a /pa /hash SHA256 "'+$nativePath+'"') ('readiness-trust-'+$n)};$checks+=GateResult ('Trust '+[IO.Path]::GetFileName($path)) ($r.ExitCode -eq 0) $path}
    # Recheck after DISM and all other work; do not reuse an earlier clean result.
    Wait-Servicing
    $lastSfc=Invoke-Native "$env:windir\System32\sfc.exe" '/verifyonly' 'readiness-final-sfc' -Unicode
    $checks+=GateResult 'Final protected-file scan' (Test-Clean $lastSfc) 'Fresh full SFC result after all native checks.'
    $lastInventory=Invoke-Native "$env:windir\System32\WindowsPowerShell\v1.0\powershell.exe" ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$worker+'" -OutputDirectory "'+$run+'"') 'readiness-final-inventory'
    if($lastInventory.ExitCode -ne 0){throw 'Final reboot inventory failed; earlier results are not an all-clear.'}
    $data=Get-Content -Raw -LiteralPath (Join-Path $run 'reboot-inventory.json') | ConvertFrom-Json
    $issues=@($data.Issues)
    $nativePassed=@($checks | Where-Object Passed -eq $false).Count -eq 0
    $state=Get-RebootGateOutcome $issues.Count $data.Complete $nativePassed
    $report=[ordered]@{CompletedUtc=[datetime]::UtcNow.ToString('o');Status=$state;InventoryComplete=$data.Complete;Issues=$issues;NativeChecks=$checks;RebootPerformed=$false;Guarantee=$false;Limitations=$data.Limitations}
    $report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $run 'reboot-readiness.json') -Encoding UTF8
    Write-Host ('REBOOT READINESS: '+$state+'. See reboot-readiness.json and reboot-inventory.json. No reboot performed; no universal safety guarantee.')
    return $state
}
