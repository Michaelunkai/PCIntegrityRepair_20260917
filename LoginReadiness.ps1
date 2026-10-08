# Embedded into the delivered PS1. No credential, SAM, SECURITY or NGC export.
function Get-LoginServiceAction([string]$Name,[string]$StartMode,[string]$State,[bool]$Repair) {
    if(-not $Repair -or $Name -notin @('ProfSvc','UserManager','SamSs')){return 'Observe'}
    if($StartMode -eq 'Disabled'){return 'EnableAndStart'}
    if($State -eq 'Stopped'){return 'Start'}
    return 'Observe'
}
function Invoke-LoginReadiness([switch]$Repair,[string]$Phase='final') {
    $login=[ordered]@{CapturedUtc=[datetime]::UtcNow.ToString('o');Phase=$Phase;Complete=$false;Status='Incomplete';Checks=@();Issues=@();Changes=@();Data=[ordered]@{};LoginTested=$false;Limitations=@('No password, PIN, biometric or next-logon test was performed.','Profile metadata and file presence do not prove a registry hive is internally healthy or its effective permissions are correct.','No backup account is proven usable until its owner successfully signs in.','Hardware, firmware, network identity providers and later changes can still prevent sign-in.')}
    $loginPath=Join-Path $run ('login-readiness-'+$Phase+'.json')
    # The guide is embedded as well, so copying the delivered PS1 alone still works.
    $guide=@'
__LOGIN_RECOVERY_GUIDE__
'@
    $guide | Set-Content -LiteralPath (Join-Path $run 'LOGIN-RECOVERY.txt') -Encoding UTF8
    function Save-Login {$login | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $loginPath -Encoding UTF8}
    function Login-Issue($Name,$Detail){$login.Issues+=@{Check=$Name;Detail=$Detail};Write-Host "LOGIN ATTENTION [$Name]: $Detail"}
    function Login-Check($Name,[scriptblock]$Action){try{& $Action;$login.Checks+=@{Name=$Name;Completed=$true}}catch{Login-Issue $Name ('Check/repair unavailable: '+$_.Exception.Message);$login.Checks+=@{Name=$Name;Completed=$false}};Save-Login}
    Write-Host "LOGIN READINESS ($Phase): checking profiles, services, accounts and sign-in evidence. No sign-out or reboot."
    Save-Login
    Login-Check 'Login services' {
        $login.Data.Services=@()
        foreach($name in @('ProfSvc','UserManager','SamSs','VaultSvc','NgcSvc','NgcCtnrSvc')){
            $svc=Get-CimInstance Win32_Service -Filter "Name='$name'" -OperationTimeoutSec 20
            if(-not $svc){Login-Issue 'Login services' "$name is missing; service registration will not be invented.";continue}
            $before=$svc | Select-Object Name,StartMode,State,PathName,StartName
            $login.Data.Services+=$before
            $action=Get-LoginServiceAction $name $svc.StartMode $svc.State $Repair.IsPresent
            if($action -ne 'Observe'){
                # Persist the prior state BEFORE changing only the three core services.
                $change=[ordered]@{Name=$name;Before=$before;Action=$action;Verified=$false}
                $login.Changes+=$change;Save-Login
                if($action -eq 'EnableAndStart'){Set-Service -Name $name -StartupType Automatic}
                # CIM service methods return promptly; do not wait indefinitely on a hung service.
                $started=Invoke-CimMethod -InputObject $svc -MethodName StartService -OperationTimeoutSec 20
                if($started.ReturnValue -notin 0,10){throw "$name start failed: $($started.ReturnValue)"}
                $after=Get-CimInstance Win32_Service -Filter "Name='$name'" -OperationTimeoutSec 20
                $change.After=$after | Select-Object Name,StartMode,State
                $change.Verified=$after.State -eq 'Running' -and $after.StartMode -ne 'Disabled'
                Save-Login
                if(-not $change.Verified){Login-Issue 'Login services' "$name has not reached Running; inspect the service failure before reboot."}
                $svc=$after
            }
            if($svc.StartMode -eq 'Disabled'){Login-Issue 'Login services' "$name is disabled."}
            if($name -in @('ProfSvc','UserManager','SamSs') -and $svc.StartMode -ne 'Auto'){Login-Issue 'Login services' "$name startup mode is $($svc.StartMode); automatic startup is not confirmed."}
            if($name -in @('ProfSvc','UserManager','SamSs') -and $svc.State -ne 'Running'){Login-Issue 'Login services' "$name is $($svc.State)."}
            # Manual/trigger-start Hello and Vault services may legitimately be stopped.
        }
    }
    Login-Check 'Profile mappings and hives' {
        $base='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
        $profiles=@(Get-CimInstance Win32_UserProfile -OperationTimeoutSec 20 | Where-Object {-not $_.Special})
        $login.Data.Profiles=@($profiles | Select-Object SID,LocalPath,Loaded,Status,HealthStatus)
        $mappings=@(Get-ChildItem -LiteralPath $base | ForEach-Object {$v=Get-ItemProperty -LiteralPath $_.PSPath;[pscustomobject]@{SID=$_.PSChildName;Path=[Environment]::ExpandEnvironmentVariables([string]$v.ProfileImagePath);State=$v.State;RefCount=$v.RefCount}})
        $login.Data.ProfileMappings=$mappings
        foreach($m in $mappings){if($m.SID -match '\.bak$'){Login-Issue 'Profile mapping' "Backup SID mapping $($m.SID) requires diagnosis; never blindly rename/delete it."}}
        foreach($p in $profiles){
            if(($p.Status -band 1) -ne 0){Login-Issue 'Temporary profile' "Temporary profile: $($p.LocalPath). Save new files elsewhere before signing out."}
            if(($p.Status -band 8) -ne 0){Login-Issue 'Corrupted profile' "Windows reports a corrupted profile: $($p.LocalPath)."}
            $mapped=@($mappings | Where-Object SID -eq $p.SID)
            if($mapped.Count -ne 1 -or $mapped[0].Path.TrimEnd('\') -ine ([string]$p.LocalPath).TrimEnd('\')){Login-Issue 'Profile mapping' "Missing or inconsistent mapping for $($p.SID)."}
            foreach($path in @($p.LocalPath,(Join-Path $p.LocalPath 'NTUSER.DAT'),(Join-Path $p.LocalPath 'AppData\Local\Microsoft\Windows\UsrClass.dat'))){
                try{
                    $item=Get-Item -LiteralPath $path -Force -ErrorAction Stop
                    if(-not $item.PSIsContainer -and $item.Length -eq 0){Login-Issue 'Profile hive' "Empty hive: $path"}
                    # Use Desktop .NET directly: inherited PSModulePath can point
                    # Get-Acl at an incompatible PowerShell Core security module.
                    $acl=$item.GetAccessControl()
                    $denies=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]) | Where-Object { $_.AccessControlType -eq 'Deny' -and $_.IdentityReference.Value -in @($p.SID,'S-1-5-18','S-1-1-0','S-1-5-11') })
                    if($denies.Count){Login-Issue 'Profile permissions' "Potentially blocking deny rule on $path; effective access needs review."}
                }catch{Login-Issue 'Profile hive/access' ("Cannot inspect $path : "+$_.Exception.Message)}
            }
        }
        $currentSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        $login.Data.InspectedProcessSID=$currentSid
        if(-not @($profiles | Where-Object {$_.SID -eq $currentSid -and $_.Loaded}).Count){Login-Issue 'Profile coverage' 'The process account has no loaded ordinary profile; interactive user coverage is unverified.'}
        $defaultPath=Join-Path ([Environment]::ExpandEnvironmentVariables([string](Get-ItemProperty -LiteralPath $base).Default)) 'NTUSER.DAT'
        $defaultHive=Get-Item -LiteralPath $defaultPath -Force
        if($defaultHive.Length -eq 0){Login-Issue 'Default profile' 'Default profile hive is empty; new-account sign-in may fail.'}
    }
    Login-Check 'Winlogon configuration' {
        $v=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
        # Select only non-secret values; never serialize the whole Winlogon key.
        $login.Data.Winlogon=$v | Select-Object Shell,Userinit
        if(([string]$v.Shell).Trim() -ine 'explorer.exe'){Login-Issue 'Winlogon' 'Nonstandard shell requires review; custom kiosk shells are not overwritten.'}
        $expected=Join-Path $env:windir 'system32\userinit.exe'
        if(([Environment]::ExpandEnvironmentVariables([string]$v.Userinit)).Trim().TrimEnd(',') -ine $expected){Login-Issue 'Winlogon' 'Nonstandard Userinit requires review; it was not overwritten.'}
        $userKey='HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
        if(Test-Path $userKey){$u=Get-ItemProperty $userKey;if($u.Shell -or $u.Userinit){Login-Issue 'Winlogon' 'Per-user shell/Userinit override requires review.'}}
    }
    Login-Check 'Accounts and alternate administrator' {
        $users=@(Get-LocalUser)
        $members=@(Get-LocalGroupMember -SID 'S-1-5-32-544')
        $accounts=@(Get-CimInstance Win32_UserAccount -Filter 'LocalAccount=True' -OperationTimeoutSec 20)
        $login.Data.Accounts=@($users | Select-Object Name,SID,Enabled,AccountExpires,PasswordExpires,LastLogon)
        $admins=@($users | Where-Object {$_.Enabled -and $_.SID.Value -in @($members | ForEach-Object {$_.SID.Value})})
        $login.Data.EnabledLocalAdministrators=@($admins | Select-Object Name,SID)
        if($admins.Count -lt 2){Login-Issue 'Recovery prerequisite' 'Fewer than two enabled local administrators. Create a separate recovery administrator in Settings and verify its sign-in before relying on it.'}
        foreach($u in @($users | Where-Object {$_.SID.Value -in @($login.Data.Profiles.SID) -or $_.SID.Value -in @($admins | ForEach-Object {$_.SID.Value})})){
            if(-not $u.Enabled){Login-Issue 'Disabled account' "$($u.Name): the account associated with a profile is disabled."}
            if($u.AccountExpires -and $u.AccountExpires -le (Get-Date).AddDays(7)){Login-Issue 'Account expiry' "$($u.Name): account expires within seven days or has expired."}
            if($u.PasswordExpires -and $u.PasswordExpires -le (Get-Date).AddDays(7)){Login-Issue 'Password expiry' "$($u.Name): password expires within seven days or has expired. Change it through Windows; no password reset is performed."}
            if(@($accounts | Where-Object {$_.SID -eq $u.SID.Value -and $_.Lockout}).Count){Login-Issue 'Account lockout' "$($u.Name) is locked out; determine the source of failed attempts."}
        }
    }
    Login-Check 'Profile and authentication event history' {
        $since=(Get-Date).AddDays(-30)
        $queries=@(@{LogName='Application';ProviderName='Microsoft-Windows-User Profiles Service';StartTime=$since;Level=1,2,3})
        foreach($channel in @('Microsoft-Windows-User Profile Service/Operational','Microsoft-Windows-HelloForBusiness/Operational','Microsoft-Windows-AAD/Operational')){
            $log=Get-WinEvent -ListLog $channel -ErrorAction Stop
            if($log.IsEnabled){$queries+=@{LogName=$channel;StartTime=$since;Level=1,2,3}}else{Login-Issue 'Event coverage' "$channel is disabled; its absence of errors cannot be verified."}
        }
        $events=@()
        foreach($q in $queries){try{$events+=@(Get-WinEvent -FilterHashtable $q -MaxEvents 200 -ErrorAction Stop)}catch{if($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*'){throw}}}
        $login.Data.Events=@($events | Select-Object TimeCreated,ProviderName,Id,Message)
        foreach($group in @($events | Group-Object ProviderName,Id)){Login-Issue 'Sign-in history' "$($group.Count) event(s): $($group.Name). Historical evidence requires review; it does not prove a current failure."}
        $oldest=Get-WinEvent -LogName Application -Oldest -MaxEvents 1
        $login.Data.ApplicationLogOldest=$oldest.TimeCreated
        if($oldest.TimeCreated -gt $since){Login-Issue 'Event coverage' 'Less than 30 days of Application history are retained; the recurring failure may not be represented.'}
    }
    Login-Check 'TPM and password sign-in availability' {
        $tpm=Get-Tpm
        $login.Data.Tpm=$tpm | Select-Object TpmPresent,TpmReady,TpmEnabled,LockedOut
        if($tpm.TpmPresent -and (-not $tpm.TpmReady -or $tpm.LockedOut)){Login-Issue 'Windows Hello' 'TPM is not ready or is locked out; PIN/biometric sign-in may fail. TPM/NGC will not be cleared.'}
        $passwordProvider='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{60B78E88-EAD8-445C-9CFD-0B87F74EA6CD}'
        if(-not (Test-Path $passwordProvider)){Login-Issue 'Password provider' 'Password credential provider registration missing.'}elseif((Get-ItemProperty $passwordProvider).Disabled -eq 1){Login-Issue 'Password provider' 'Password credential provider is disabled.'}
        $filters='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Provider Filters'
        if(Test-Path $filters){$login.Data.CredentialProviderFilters=@(Get-ChildItem $filters | Select-Object PSChildName);if($login.Data.CredentialProviderFilters.Count){Login-Issue 'Credential filters' 'Credential provider filters are installed; their effect on sign-in requires verification.'}}
        $passwordless='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PasswordLess\Device'
        if(Test-Path $passwordless){$login.Data.DevicePasswordLessBuildVersion=(Get-ItemProperty $passwordless).DevicePasswordLessBuildVersion;if($login.Data.DevicePasswordLessBuildVersion -eq 2){Login-Issue 'Password fallback' 'Hello-only sign-in preference is enabled; verify a usable recovery method in Sign-in options.'}}
    }
    $login.Complete=@($login.Checks | Where-Object {-not $_.Completed}).Count -eq 0
    $login.Status=if($login.Complete -and $login.Issues.Count -eq 0){'ChecksPassed_LoginNotTested'}else{'NeedsAttention'}
    Save-Login
    Write-Host "LOGIN READINESS: $($login.Status); $loginPath. Review LOGIN-RECOVERY.txt before reboot."
    return [pscustomobject]$login
}
