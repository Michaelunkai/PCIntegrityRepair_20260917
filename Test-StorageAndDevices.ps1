#requires -Version 5.1
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$run = Join-Path $PSScriptRoot ('evidence\storage-devices-' + (Get-Date -Format 'yyyyMMdd-HHmmss-fff'))
$null = New-Item -ItemType Directory -Path $run
$disks = @(Get-Disk | Select-Object Number,FriendlyName,BusType,HealthStatus,OperationalStatus,Size)
$volumes = @(Get-Volume | Select-Object DriveLetter,FileSystem,HealthStatus,OperationalStatus,Size,SizeRemaining)
$reliability = @()
foreach ($disk in @(Get-PhysicalDisk)) {
    try {
        $counter = $disk | Get-StorageReliabilityCounter -ErrorAction Stop
        $reliability += [pscustomobject]@{DeviceId=$disk.DeviceId; Model=$disk.FriendlyName; Counter=($counter | Select-Object Temperature,TemperatureMax,Wear,PowerOnHours,ReadErrorsTotal,ReadErrorsUncorrected,WriteErrorsTotal,WriteErrorsUncorrected,ReadLatencyMax,WriteLatencyMax,FlushLatencyMax); Error=$null}
    } catch { $reliability += [pscustomobject]@{DeviceId=$disk.DeviceId; Model=$disk.FriendlyName; Error=$_.Exception.Message} }
}
$dirty = @()
foreach ($volume in $volumes) {
    if ($volume.FileSystem -ne 'NTFS' -or -not $volume.DriveLetter) { continue }
    $target = [string]$volume.DriveLetter + ':'
    $output = & "$env:windir\System32\fsutil.exe" dirty query $target 2>&1
    $dirty += [pscustomobject]@{Target=$target; ExitCode=$LASTEXITCODE; Output=($output -join "`n")}
}
$devices = @(Get-PnpDevice -PresentOnly | Where-Object Status -ne 'OK' | Select-Object Class,FriendlyName,Status,InstanceId)
$usbNumbers = @($disks | Where-Object BusType -eq 'USB' | ForEach-Object Number)
$usbDisks = @(Get-CimInstance Win32_DiskDrive | Where-Object { $usbNumbers -contains $_.Index } | Select-Object Index,Model,PNPDeviceID,Status,FirmwareRevision)
$usbChains = @()
foreach ($disk in $usbDisks) {
    $instance = $disk.PNPDeviceID
    $chain = @()
    $seen = @{}
    for ($depth=0; $depth -lt 10 -and $instance -and -not $seen.ContainsKey($instance); $depth++) {
        $seen[$instance] = $true
        try {
            $device = Get-PnpDevice -InstanceId $instance -ErrorAction Stop
            $properties = @(Get-PnpDeviceProperty -InstanceId $instance -ErrorAction Stop | Where-Object KeyName -in @('DEVPKEY_Device_Parent','DEVPKEY_Device_Service','DEVPKEY_Device_DriverVersion','DEVPKEY_Device_DriverProvider','DEVPKEY_Device_ProblemCode','DEVPKEY_Device_LocationInfo'))
            $chain += [pscustomobject]@{Name=$device.FriendlyName; Class=$device.Class; Status=$device.Status; InstanceId=$instance; Properties=@($properties | Select-Object KeyName,Data)}
            $instance = ($properties | Where-Object KeyName -eq 'DEVPKEY_Device_Parent').Data
        } catch { $chain += [pscustomobject]@{InstanceId=$instance; Error=$_.Exception.Message}; break }
    }
    $usbChains += [pscustomobject]@{DiskNumber=$disk.Index; Chain=$chain}
}
$report = [ordered]@{CapturedUtc=[datetime]::UtcNow.ToString('o'); Disks=$disks; Volumes=$volumes; Reliability=$reliability; DirtyQueries=$dirty; PresentDeviceProblems=$devices; UsbDisks=$usbDisks; ChangesMade=$false; Caveat='Healthy status, an unset dirty flag, and empty device errors do not prove media integrity. Maximum latency counters may be historical; no stress test or filesystem repair was performed.'}
$report.UsbConnectionChains = $usbChains
$report | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $run 'report.json') -Encoding UTF8
Write-Output ('Report: '+(Join-Path $run 'report.json'))
$dirty | Format-Table -AutoSize
$reliability | ConvertTo-Json -Depth 5
Write-Output ('PresentDeviceProblems='+$devices.Count)
$usbDisks | Format-List
$usbChains.Chain | Select-Object Name,Class,Status,InstanceId | Format-Table -AutoSize
