#requires -Version 5.1
#requires -RunAsAdministrator
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$tool = 'C:\Program Files (x86)\Windows Kits\10\Tools\bin\i386\signtool.exe'
$catalog = Join-Path $env:windir 'WinSxS\Catalogs\fbc943848826f205637944ff56d4d65876b1aab914759cd14474c4e311965286.cat'
$driver = Join-Path $env:windir 'System32\drivers\mpsdrv.sys'
$toolDriver = Join-Path $env:windir 'Sysnative\drivers\mpsdrv.sys'
$run = Join-Path $PSScriptRoot ('evidence\firewall-catalog-repair-' + (Get-Date -Format 'yyyyMMdd-HHmmss-fff'))
$null = New-Item -ItemType Directory -Path $run
function Invoke-SignTool([string]$Arguments,[string]$Label) {
    $p = New-Object Diagnostics.Process
    $p.StartInfo.FileName = $tool
    $p.StartInfo.Arguments = $Arguments
    $p.StartInfo.UseShellExecute = $false
    $p.StartInfo.CreateNoWindow = $true
    $p.StartInfo.RedirectStandardOutput = $true
    $p.StartInfo.RedirectStandardError = $true
    $null = $p.Start()
    $o = $p.StandardOutput.ReadToEndAsync()
    $e = $p.StandardError.ReadToEndAsync()
    $p.WaitForExit()
    $code = $p.ExitCode
    [IO.File]::WriteAllText((Join-Path $run ($Label + '.txt')), $o.Result + $e.Result, [Text.Encoding]::UTF8)
    $p.Dispose()
    return $code
}
$beforeHash = (Get-FileHash -LiteralPath $driver).Hash
Get-FileHash -LiteralPath $catalog,$driver | ConvertTo-Json | Set-Content (Join-Path $run 'hashes-before.json') -Encoding UTF8
$signer = Get-AuthenticodeSignature -LiteralPath $catalog
if ($signer.Status -ne 'Valid' -or $signer.SignerCertificate.Subject -notmatch 'CN=Microsoft Windows,') { throw 'Catalog must have a valid Microsoft Windows signature.' }
$verify = 'verify /kp /hash SHA256 /v /c "' + $catalog + '" "' + $toolDriver + '"'
if ((Invoke-SignTool $verify 'explicit-catalog-verification') -ne 0) { throw 'Catalog does not validate the installed driver.' }
$automatic = 'verify /a /kp /hash SHA256 /v "' + $toolDriver + '"'
$before = Invoke-SignTool $automatic 'automatic-before'
$registered = $false
if ($before -ne 0) {
    if ((Invoke-SignTool ('catdb /u /v "' + $catalog + '"') 'catalog-registration') -ne 0) { throw 'Catalog registration failed; see evidence.' }
    $registered = $true
}
$after = Invoke-SignTool $automatic 'automatic-after'
if ($after -ne 0) { throw 'Automatic kernel-signature verification still fails; service start skipped.' }
$serviceError = $null
try { Start-Service -Name MpsSvc -ErrorAction Stop } catch { $serviceError = $_.Exception.Message }
$profileError = $null
$profiles = @()
try { $profiles = @(Get-NetFirewallProfile -ErrorAction Stop | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction) } catch { $profileError = $_.Exception.Message }
$result = [ordered]@{ CompletedUtc=[DateTime]::UtcNow.ToString('o'); Catalog=$catalog; Registered=$registered; AutomaticVerificationBefore=$before; AutomaticVerificationAfter=$after; DriverHashUnchanged=($beforeHash -ceq (Get-FileHash -LiteralPath $driver).Hash); FirewallService=(Get-Service MpsSvc).Status.ToString(); ServiceError=$serviceError; ProfileError=$profileError; Profiles=$profiles }
$result | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $run 'result.json') -Encoding UTF8
Write-Output ('Evidence: ' + $run)
$result | ConvertTo-Json -Depth 5 | Write-Output
