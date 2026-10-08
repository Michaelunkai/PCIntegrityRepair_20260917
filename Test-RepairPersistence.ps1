[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$outDir = Join-Path $PSScriptRoot ('evidence\persistence-' + (Get-Date -Format 'yyyyMMdd-HHmmss-fff'))
$null = New-Item -ItemType Directory -Path $outDir
$since = [datetime]'2026-09-17T22:52:57'
$runtime = 'C:\Users\Admin\.cache\codex-runtimes\codex-primary-runtime\dependencies\native\powershell'
$events = @()
foreach ($log in @('System','Microsoft-Windows-CodeIntegrity/Operational')) {
    try {
        $events += Get-WinEvent -FilterHashtable @{LogName=$log; StartTime=$since; Level=@(1,2,3)} -ErrorAction Stop |
            Select-Object TimeCreated,LogName,ProviderName,Id,Message
    } catch {
        if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { throw }
    }
}
$packages = @(Get-AppxPackage -Name '*PowerShell*' | Select-Object Name,Version,InstallLocation,Status)
$runtimeTests = @()
foreach ($package in $packages) {
    $executable = Join-Path $package.InstallLocation 'pwsh.exe'
    if (-not (Test-Path -LiteralPath $executable)) { continue }
    $probe = & $executable -NoProfile -NonInteractive -Command 'Import-Module Microsoft.PowerShell.Management,Microsoft.PowerShell.Utility -ErrorAction Stop; Get-Command Get-Content,Set-Alias,Join-Path | Select-Object Name,Source | ConvertTo-Json -Compress' 2>&1
    $runtimeTests += [pscustomobject]@{Executable=$executable; ExitCode=$LASTEXITCODE; Output=($probe -join "`n"); ProfileLoaded=$false}
}
$report = [ordered]@{
    CapturedUtc = [datetime]::UtcNow.ToString('o')
    SinceLocal = $since.ToString('o')
    Runtime = $runtime
    RuntimeModulesDirectoryExists = Test-Path -LiteralPath (Join-Path $runtime 'Modules')
    RuntimeFiles = @(Get-ChildItem -LiteralPath $runtime | Select-Object Name,Length)
    InstalledPowerShellPackages = $packages
    InstalledPowerShellModuleTests = $runtimeTests
    Services = @(Get-CimInstance Win32_Service -Filter "Name='MpsSvc' OR Name='WinDefend' OR Name='CryptSvc' OR Name='winmgmt'" | Select-Object Name,State,ExitCode)
    StoppedAutomaticServices = @(Get-CimInstance Win32_Service | Where-Object { $_.StartMode -eq 'Auto' -and $_.State -ne 'Running' } | Select-Object Name,State,ExitCode,DelayedAutoStart)
    DefenderStatus = Get-MpComputerStatus | Select-Object AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,AntivirusSignatureLastUpdated,QuickScanEndTime,FullScanEndTime,RebootRequired
    FirewallDriver = Get-CimInstance Win32_SystemDriver -Filter "Name='mpsdrv'" | Select-Object Name,State,ExitCode
    Events = $events
    ChangesMade = $false
}
$report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $outDir 'report.json') -Encoding UTF8
Write-Output ('Report: ' + (Join-Path $outDir 'report.json'))
$report.Services | Format-Table
$report.FirewallDriver | Format-Table
$packages | Format-List
$events | Format-List
