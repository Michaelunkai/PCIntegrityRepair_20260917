$ErrorActionPreference='Stop'
$out=Join-Path $PSScriptRoot ('evidence\reboot-inspection-'+(Get-Date -Format 'yyyyMMdd-HHmmss'))
$null=New-Item -ItemType Directory -Path $out
function Record($Name,[scriptblock]$Action){Write-Host "Inspecting $Name";try{$v=& $Action;$v | ConvertTo-Json -Depth 8 | Set-Content (Join-Path $out ($Name+'.json')) -Encoding UTF8;$v | Format-List | Out-String -Width 180 | Write-Output}catch{Write-Output ($Name+': '+$_.Exception.Message)}}
Record 'boot' {Get-CimInstance Win32_OperatingSystem | Select-Object LastBootUpTime,Caption,Version}
Record 'crashes' {Get-WinEvent -FilterHashtable @{LogName='System';Id=41,1001,6008,7,51,55,129,153,161;StartTime=(Get-Date).AddDays(-14)} -MaxEvents 40 -ErrorAction Stop | Select-Object TimeCreated,Id,ProviderName,Message}
Record 'dumps' {Get-Item "$env:windir\MEMORY.DMP" -ErrorAction SilentlyContinue;Get-ChildItem "$env:windir\Minidump" -File -ErrorAction SilentlyContinue | Select-Object FullName,Length,LastWriteTime}
Record 'disks' {Get-Disk | Select-Object Number,FriendlyName,BusType,HealthStatus,OperationalStatus,IsBoot,IsSystem,Size}
Record 'volumes' {Get-Volume | Select-Object DriveLetter,FileSystem,HealthStatus,Size,SizeRemaining}
Record 'boot-drivers' {Get-CimInstance Win32_SystemDriver | Where-Object StartMode -in Boot,System | Select-Object Name,State,StartMode,PathName,ExitCode}
Record 'services' {Get-Service RpcSs,DcomLaunch,EventLog,PlugPlay,Power,Winmgmt,CryptSvc,BFE,MpsSvc | Select-Object Name,Status}
Record 'dump-config' {Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl' | Select-Object CrashDumpEnabled,DumpFile,MinidumpDir,LogEvent,AutoReboot;Get-CimInstance Win32_PageFileUsage | Select-Object Name,AllocatedBaseSize,CurrentUsage}
Record 'bcd-current' {& bcdedit.exe /enum '{current}';if($LASTEXITCODE){throw 'BCD read failed'}}
Record 'bcd-bootmgr' {& bcdedit.exe /enum '{bootmgr}';if($LASTEXITCODE){throw 'BCD read failed'}}
Record 'recovery' {& reagentc.exe /info}
Record 'bitlocker' {Get-BitLockerVolume | Select-Object MountPoint,VolumeStatus,ProtectionStatus,LockStatus}
Write-Output "Evidence=$out"
