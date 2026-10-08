# No real Windows repairs: exercise the exact launch gate with a harmless child,
# then run package wait scenarios using fake process/CBS observations and time.
$ErrorActionPreference='Stop'
$canonical='F:\study\repos\shells\powershell\fixfixfix.ps1'
. $canonical
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($canonical,[ref]$tokens,[ref]$errors)
if($errors.Count){throw ($errors | Out-String)}
$fn=$ast.Find({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Invoke-BoundedNative'},$true)
. ([scriptblock]::Create($fn.Extent.Text))
$OverallTimeoutSeconds=60;$NativeTimeoutSeconds=10;$InactivityTimeoutSeconds=10;$StatusIntervalSeconds=1;$ServicingWaitSeconds=3
$overallWatch=[Diagnostics.Stopwatch]::StartNew()
function Write-FixProgress {param($Stage,$Percent,$Detail)}
function Get-WindowsServicingState {
    $script:samples++
    $busy=$script:scenario -eq 'busy' -or ($script:scenario -eq 'transient' -and $script:samples -le 3)
    $pending=$script:scenario -eq 'reboot'
    $unknown=$script:scenario -eq 'unknown'
    [pscustomobject]@{Blocked=($busy -or $pending -or $unknown);PersistentRebootPending=$pending;ProbeHealthy=(-not $unknown);ProbeError=$(if($unknown){'Fixture probe denied'}else{$null});ActiveProcesses=@($(if($busy){'Dism#123'}));DirectRepairProcesses=@($(if($busy){'Dism#123'}));CBSRebootPending=$pending;WURebootRequired=$false;PendingXmlPresent=$false}
}
$exe=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$script:scenario='transient';$script:samples=0
$r=Invoke-BoundedNative $exe @('-NoProfile','-Command','"Write-Output resumed-after-contention"') 10 -OperationLabel 'contention-regression'
if($r.Code -ne 0 -or $r.Output -notmatch 'resumed-after-contention' -or $script:samples -lt 4){throw 'Transient contention skipped the native operation'}
foreach($case in @(@('busy',1618),@('reboot',3010),@('unknown',1618))){
    $script:scenario=$case[0];$script:samples=0;$ServicingWaitSeconds=1
    $r=Invoke-BoundedNative $exe @('-NoProfile','-Command','"throw ''must not launch''"') 10 -OperationLabel 'blocked-regression'
    if($r.Code -ne $case[1] -or -not $r.StartFailed){throw "Unsafe launch for $($case[0])"}
}
$OverallTimeoutSeconds=0;$script:scenario='busy'
$r=Invoke-BoundedNative $exe @('-NoProfile','-Command','"exit 0"') 10
if($r.Code -ne 1460 -or -not $r.StartFailed){throw 'Wait did not respect overall deadline'}
Write-Host 'PASS: fastff launch resumes after transient contention; busy timeout, reboot, unknown state and overall deadline block launch.'

& {
    $source=Join-Path $PSScriptRoot 'WindowsCatalogRepair-Package\Repair-WindowsCatalogCorruption.ps1'
    $ast=[Management.Automation.Language.Parser]::ParseFile($source,[ref]$tokens,[ref]$errors)
    if($errors.Count){throw ($errors | Out-String)}
    $fn=$ast.Find({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Wait-Servicing'},$true)
    # Only the source of elapsed time is substituted; execute the packaged logic.
    . ([scriptblock]::Create($fn.Extent.Text.Replace('[Diagnostics.Stopwatch]::StartNew()','$script:fixtureClock')))
    function Start-Sleep {param($Seconds);$script:fixtureClock.Elapsed=$script:fixtureClock.Elapsed.Add([TimeSpan]::FromSeconds($Seconds))}
    function Get-Process {
        param([string[]]$Name,$ErrorAction)
        $elapsed=$script:fixtureClock.Elapsed.TotalSeconds
        if($script:scenario -eq 'busy' -or ($script:scenario -eq 'churn' -and $elapsed -lt 3)){return [pscustomobject]@{Name='dism';Id=(100+[int]$elapsed);CPU=0}}
        if('TrustedInstaller' -in $Name){[pscustomobject]@{Name='TrustedInstaller';Id=222;CPU=$(if($script:scenario -eq 'cpu'){[double]$elapsed}else{0.0})}}
    }
    function Get-Item {param($LiteralPath,$ErrorAction);if($script:scenario -eq 'unreadable'){throw 'Fixture CBS inaccessible'};$stamp=[datetime]'2026-01-01';if($script:scenario -eq 'cbs'){$stamp=$stamp.AddSeconds($script:fixtureClock.Elapsed.TotalSeconds)};[pscustomobject]@{LastWriteTimeUtc=$stamp;LastWriteTime=$stamp}}
    function Get-Content {param($LiteralPath,$Tail,$ErrorAction);'Fixture CBS record'}
    function Test-Path {param($LiteralPath);return ($script:scenario -eq 'reboot')}
    function Write-Progress {param($Id,$Activity,$Status,[switch]$Completed)}
    function Stop-Process {throw 'Must never stop another process'}
    foreach($scenario in @('idle','churn','busy','cpu','cbs','unreadable','reboot')){
        $script:scenario=$scenario;$script:fixtureClock=[pscustomobject]@{Elapsed=[TimeSpan]::Zero}
        $failed=$false
        try{Wait-Servicing -MaxSeconds 40}catch{$failed=$true}
        if($scenario -in @('idle','churn')){if($failed){throw "$scenario should become quiet despite the resident service"}}elseif(-not $failed){throw "$scenario should remain blocked"}
    }
    Write-Host 'PASS: fff4 packaged wait resumes after PID churn, permits idle resident services, rejects active CPU/CBS, timeout, unreadable evidence and reboot markers.'
}
