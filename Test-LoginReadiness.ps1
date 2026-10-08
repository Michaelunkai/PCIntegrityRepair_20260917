# Safe behavioral tests: service mutations are mocked; no real service is changed.
$ErrorActionPreference='Stop'
$source=Join-Path $PSScriptRoot 'WindowsCatalogRepair-Package\Repair-WindowsCatalogCorruption.ps1'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($source,[ref]$tokens,[ref]$errors)
if($errors.Count){throw ($errors | Out-String)}
foreach($name in @('Get-LoginServiceAction','Invoke-LoginReadiness','Get-RebootGateOutcome','Get-FinalRepairOutcome')){
    $fn=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name},$true)
    if(-not $fn){throw "Missing embedded function: $name"}
    . ([scriptblock]::Create($fn.Extent.Text))
}
foreach($case in @(
    @('ProfSvc','Disabled','Stopped',$false,'Observe'),
    @('ProfSvc','Disabled','Stopped',$true,'EnableAndStart'),
    @('UserManager','Auto','Stopped',$true,'Start'),
    @('SamSs','Auto','Running',$true,'Observe'),
    @('NgcSvc','Disabled','Stopped',$true,'Observe'),
    @('VaultSvc','Manual','Stopped',$true,'Observe'),
    @('OtherService','Disabled','Stopped',$true,'Observe')
)){
    if((Get-LoginServiceAction $case[0] $case[1] $case[2] $case[3]) -ne $case[4]){throw 'Service repair boundary regression'}
}
$run=Join-Path $PSScriptRoot ('evidence\login-fixtures-'+(Get-Date -Format 'yyyyMMdd-HHmmss-fff'))
$null=New-Item -ItemType Directory -Path $run
# Force an isolated disabled ProfSvc fixture. Other inventory calls are denied,
# proving unavailable checks cannot turn into an all-clear.
function Get-CimInstance {
    param($ClassName,$Filter,$OperationTimeoutSec)
    if($ClassName -eq 'Win32_UserProfile' -and $script:profileFixture){return [pscustomobject]@{SID=$script:profileSid;LocalPath=$env:USERPROFILE;Loaded=$true;Special=$false;Status=9;HealthStatus=3}}
    if($ClassName -ne 'Win32_Service'){throw 'Fixture inventory unavailable'}
    $name=$Filter.Replace("Name='",'').TrimEnd("'")
    if($name -eq 'ProfSvc'){return [pscustomobject]@{Name=$name;StartMode=$script:fixtureMode;State=$script:fixtureState;PathName='fixture';StartName='LocalSystem'}}
    return [pscustomobject]@{Name=$name;StartMode='Auto';State='Running';PathName='fixture';StartName='LocalSystem'}
}
function Set-Service {param($Name,$StartupType);if($Name -ne 'ProfSvc' -or $StartupType -ne 'Automatic'){throw 'Unexpected service mutation'};$script:mutations++;$script:fixtureMode='Auto'}
function Invoke-CimMethod {param($InputObject,$MethodName,$OperationTimeoutSec);if($InputObject.Name -ne 'ProfSvc' -or $MethodName -ne 'StartService'){throw 'Unexpected service method'};$script:mutations++;if($script:failStart){return @{ReturnValue=2}};$script:fixtureState='Running';return @{ReturnValue=0}}
function Get-ItemProperty {
    param($LiteralPath)
    if($script:profileFixture -and $LiteralPath -eq 'fixture-profile-key'){return @{ProfileImagePath=$env:USERPROFILE;State=0;RefCount=1}}
    if($script:profileFixture -and $LiteralPath -like '*\ProfileList'){return @{Default=(Join-Path (Split-Path $env:USERPROFILE -Parent) 'Default')}}
    throw 'Fixture registry unavailable'
}
function Get-ChildItem {param($LiteralPath);if($script:profileFixture -and $LiteralPath -like '*\ProfileList'){return [pscustomobject]@{PSPath='fixture-profile-key';PSChildName=($script:profileSid+'.bak')}};throw 'Fixture enumeration unavailable'}
function Get-LocalUser {throw 'Fixture accounts unavailable'}
function Get-WinEvent {throw 'Fixture event log unavailable'}
function Get-Tpm {throw 'Fixture TPM unavailable'}
$script:mutations=0;$script:fixtureMode='Disabled';$script:fixtureState='Stopped';$script:failStart=$false
$r=Invoke-LoginReadiness -Phase 'check-only-fixture'
if($script:mutations -ne 0 -or $r.Status -ne 'NeedsAttention' -or $r.Complete){throw 'Check-only/unavailable inventory failed closed incorrectly'}
$r=Invoke-LoginReadiness -Repair -Phase 'repair-fixture'
if($script:mutations -ne 2 -or $r.Changes.Count -ne 1 -or -not $r.Changes[0].Verified){throw 'Disabled-service repair was not verified'}
if($r.Changes[0].Before.StartMode -ne 'Disabled'){throw 'Before snapshot lost'}
$script:fixtureMode='Disabled';$script:fixtureState='Stopped';$script:failStart=$true
$r=Invoke-LoginReadiness -Repair -Phase 'failure-fixture'
if($r.Status -ne 'NeedsAttention' -or $r.Changes[0].Verified -or $r.Complete){throw 'Failed repair incorrectly passed'}
$state=Get-RebootGateOutcome $r.Issues.Count $r.Complete $true
if((Get-FinalRepairOutcome $true $state) -ne 'NeedsAttention'){throw 'Login risk did not block a clean-integrity result'}
$script:profileFixture=$true;$script:profileSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$r=Invoke-LoginReadiness -Phase 'profile-fixture'
foreach($expected in @('Temporary profile','Corrupted profile','Profile mapping')){if(-not @($r.Issues | Where-Object Check -eq $expected).Count){throw "Failed to detect $expected"}}
if($r.Changes.Count){throw 'Profile diagnostic unexpectedly attempted a repair'}
$text=[IO.File]::ReadAllText($source)
if($text.Contains('__LOGIN_')){throw 'Unexpanded login packaging marker'}
if(-not (Test-Path (Join-Path $run 'LOGIN-RECOVERY.txt'))){throw 'Standalone recovery guide was not generated'}
$readiness=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Invoke-RebootReadiness'},$true).Extent.Text
if(-not $readiness.Contains('Invoke-LoginReadiness -Phase ''final''') -or -not $readiness.Contains('@($loginFinal.Issues)')){throw 'Final login gate disconnected'}
Write-Host 'PASS: packaged login checks, check-only mutation boundary, narrow service repair, before/after evidence, repair failure and incomplete checks blocking success, temporary/corrupt profile and .bak detection, standalone guide, final gate wiring.'
