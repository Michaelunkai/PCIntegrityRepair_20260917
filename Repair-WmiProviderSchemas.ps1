#requires -Version 5.1
#requires -RunAsAdministrator
[CmdletBinding()]
param(
    [switch]$Apply,
    [ValidateSet('WfASCim.mof','StorageWMI.mof','StorageWMI_passthru.mof','mispace.mof','NetAdapterCim.mof','NetTCPIP.mof','ProtectionManagement.mof','nlmcim.mof','win32_encryptablevolume.mof')]
    [string[]]$ProviderMof = @('WfASCim.mof','StorageWMI.mof','StorageWMI_passthru.mof','mispace.mof')
)
$ErrorActionPreference = 'Stop'
$run = Join-Path $PSScriptRoot ('evidence\wmi-schema-' + (Get-Date -Format 'yyyyMMdd-HHmmss-fff'))
$null = New-Item -ItemType Directory -Path $run
$wbem = Join-Path $env:windir 'System32\wbem'
$mofs = $ProviderMof
$mofPaths = @{}
foreach ($mof in $mofs) {
    if ($mof -eq 'ProtectionManagement.mof') {
        $servicePath = (Get-CimInstance Win32_Service -Filter "Name='WinDefend'").PathName
        if ($servicePath -notmatch '^"(?<exe>[^"]+\\MsMpEng\.exe)"') { throw 'Cannot identify the active Defender platform path.' }
        $mofPaths[$mof] = Join-Path (Split-Path -Parent $Matches.exe) $mof
    } else { $mofPaths[$mof] = Join-Path $wbem $mof }
}
function Get-ProviderProbe {
    $result = [ordered]@{}
    foreach ($name in @('FirewallClass','FirewallProfiles','Disks','PhysicalDisks','NetworkAdapters','IPAddresses','DefenderStatus','NetworkProfiles','BitLockerVolumes')) {
        try {
            $data = switch ($name) {
                'FirewallClass' { Get-CimClass -Namespace root/StandardCimv2 -ClassName MSFT_NetFirewallProfile -ErrorAction Stop | Select-Object CimClassName }
                'FirewallProfiles' { Get-NetFirewallProfile -ErrorAction Stop | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction }
                'Disks' { Get-Disk -ErrorAction Stop | Select-Object Number,FriendlyName,BusType,HealthStatus,OperationalStatus,Size }
                'PhysicalDisks' { Get-PhysicalDisk -ErrorAction Stop | Select-Object FriendlyName,BusType,HealthStatus,OperationalStatus,Size }
                'NetworkAdapters' { Get-NetAdapter -ErrorAction Stop | Select-Object Name,Status,InterfaceDescription }
                'IPAddresses' { Get-NetIPAddress -ErrorAction Stop | Select-Object InterfaceIndex,AddressFamily,AddressState }
                'DefenderStatus' { Get-MpComputerStatus -ErrorAction Stop | Select-Object AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,NISEnabled,AMRunningMode,AntivirusSignatureLastUpdated }
                'NetworkProfiles' { Get-NetConnectionProfile -ErrorAction Stop | Select-Object InterfaceIndex,NetworkCategory,IPv4Connectivity,IPv6Connectivity }
                'BitLockerVolumes' { Get-BitLockerVolume -ErrorAction Stop | Select-Object MountPoint,VolumeStatus,ProtectionStatus }
            }
            $result[$name] = @{ Success=(@($data).Count -gt 0); Count=@($data).Count; Data=@($data); EmptyResult=(@($data).Count -eq 0) }
        } catch { $result[$name] = @{ Success=$false; Error=$_.Exception.Message; ErrorId=$_.FullyQualifiedErrorId } }
    }
    return $result
}
$before = Get-ProviderProbe
$before | ConvertTo-Json -Depth 8 | Set-Content (Join-Path $run 'before.json') -Encoding UTF8
foreach ($mof in $mofs) {
    $file = $mofPaths[$mof]
    $output = & (Join-Path $wbem 'mofcomp.exe') -check $file 2>&1
    $code = $LASTEXITCODE
    $output | Set-Content (Join-Path $run ($mof + '.syntax.txt')) -Encoding UTF8
    if ($code -ne 0) { throw ('MOF syntax check failed: ' + $mof) }
    Get-FileHash -LiteralPath $file | ConvertTo-Json | Set-Content (Join-Path $run ($mof + '.hash.json')) -Encoding UTF8
}
if (-not $Apply) { Write-Output ('Preflight complete: ' + $run); return }
$backup = Join-Path $run 'wmi-repository-before.bak'
$output = & (Join-Path $wbem 'winmgmt.exe') /backup $backup 2>&1
$code = $LASTEXITCODE
$output | Set-Content (Join-Path $run 'backup.txt') -Encoding UTF8
if ($code -ne 0 -or -not (Test-Path -LiteralPath $backup) -or (Get-Item -LiteralPath $backup).Length -eq 0) { throw 'WMI backup did not succeed; no schema change attempted.' }
foreach ($mof in $mofs) {
    $output = & (Join-Path $wbem 'mofcomp.exe') $mofPaths[$mof] 2>&1
    $code = $LASTEXITCODE
    $output | Set-Content (Join-Path $run ($mof + '.compile.txt')) -Encoding UTF8
    Write-Output ($mof + ': exit=' + $code)
    if ($code -ne 0) { throw ('Compilation failed; inspect saved evidence before further changes: ' + $run) }
}
if ($mofs -contains 'mispace.mof') {
    $service = Get-Service -Name smphost
    if (@($service.DependentServices | Where-Object Status -eq Running).Count) { throw 'Storage provider has running dependents; inspect before restarting.' }
    Restart-Service -Name smphost -ErrorAction Stop
    (Get-Service smphost | Select-Object Name,Status) | ConvertTo-Json | Set-Content (Join-Path $run 'provider-service.json') -Encoding UTF8
}
$after = Get-ProviderProbe
$after | ConvertTo-Json -Depth 8 | Set-Content (Join-Path $run 'after.json') -Encoding UTF8
Write-Output ('Evidence: ' + $run)
$after | ConvertTo-Json -Depth 8 | Write-Output
