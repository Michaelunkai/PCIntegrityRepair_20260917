#requires -Version 5.1
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$run=Join-Path $PSScriptRoot ('evidence\service-triage-'+(Get-Date -Format 'yyyyMMdd-HHmmss-fff'))
$null=New-Item -ItemType Directory -Path $run
$services=@(Get-CimInstance Win32_Service | Where-Object {$_.StartMode -eq 'Auto' -and $_.State -ne 'Running'})
$details=@()
foreach($service in $services) {
    $controller=Get-Service -Name $service.Name -ErrorAction Stop
    $triggers=& "$env:windir\System32\sc.exe" qtriggerinfo $service.Name 2>&1
    $triggerExit=$LASTEXITCODE
    $binary=$null
    $exists=$null
    $signature=$null
    $binaryError=$null
    if ($service.PathName -match '^\s*"([^"]+)"') { $binary=$Matches[1] }
    elseif ($service.PathName -match '^\s*(.+?\.exe)(?:\s|$)') { $binary=$Matches[1] }
    if ($binary) {
        $binary=[Environment]::ExpandEnvironmentVariables($binary)
        try {
            $exists=Test-Path -LiteralPath $binary -PathType Leaf
            if ($exists) { $sig=Get-AuthenticodeSignature -LiteralPath $binary; $signature=[string]$sig.Status }
        } catch { $binaryError=$_.Exception.Message }
    }
    $details += [pscustomobject]@{
        Name=$service.Name; DisplayName=$service.DisplayName; State=$service.State; ExitCode=$service.ExitCode
        StartMode=$service.StartMode; DelayedAutoStart=$service.DelayedAutoStart; PathName=$service.PathName
        Dependencies=@($controller.ServicesDependedOn | Select-Object Name,Status)
        TriggerQueryExit=$triggerExit; Triggers=($triggers -join "`n")
        Executable=$binary; ExecutableExists=$exists; SignatureStatus=$signature; ExecutableCheckError=$binaryError
    }
}
$events=@()
try {
    $events=@(Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Service Control Manager'; StartTime=(Get-Date).AddDays(-1); Level=@(1,2,3)} -ErrorAction Stop | Select-Object TimeCreated,Id,Message)
} catch { if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') {throw} }
$report=[ordered]@{CapturedUtc=[datetime]::UtcNow.ToString('o'); StoppedAutomaticServices=$details; RetainedScmEvents=$events; HistoryCaveat='System log was cleared earlier today; absence of events is not complete history.'; ChangesMade=$false}
$report | ConvertTo-Json -Depth 7 | Set-Content -LiteralPath (Join-Path $run 'report.json') -Encoding UTF8
Write-Output ('Report: '+(Join-Path $run 'report.json'))
$details | Select-Object Name,ExitCode,ExecutableExists,SignatureStatus,ExecutableCheckError | Format-Table -AutoSize
Write-Output ('RetainedScmErrors='+$events.Count+'; newest='+($events | Select-Object -First 1 -ExpandProperty TimeCreated))
