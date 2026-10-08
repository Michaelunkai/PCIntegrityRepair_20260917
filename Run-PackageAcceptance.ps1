$ErrorActionPreference='Stop'
$script=Join-Path $PSScriptRoot 'WindowsCatalogRepair-Package\Repair-WindowsCatalogCorruption.ps1'
$before=(Get-FileHash -LiteralPath $script -Algorithm SHA256).Hash
& "$env:windir\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $script
$code=$LASTEXITCODE
if((Get-FileHash -LiteralPath $script -Algorithm SHA256).Hash -ne $before){throw 'Package changed during acceptance run'}
[ordered]@{CompletedUtc=[datetime]::UtcNow.ToString('o');Script=$script;SHA256=$before;NativeExitCode=$code;Meaning=$(if($code -eq 0){'Configured checks passed; no boot test'}elseif($code -eq 4){'Checks completed; unresolved reboot-readiness items'}else{'Execution or repair incomplete'})} | ConvertTo-Json | Set-Content (Join-Path $PSScriptRoot 'package-acceptance.json') -Encoding UTF8
Write-Host "PACKAGE_NATIVE_EXIT_CODE=$code"
exit $code
