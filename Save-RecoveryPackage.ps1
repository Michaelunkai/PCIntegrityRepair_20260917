$ErrorActionPreference='Stop'
$source=Join-Path $PSScriptRoot 'WindowsCatalogRepair-Package.zip'
$recoveryRoot=Join-Path $env:ProgramData 'PCIntegrityRepair\Recovery'
$null=New-Item -ItemType Directory -Path $recoveryRoot -Force
$destination=Join-Path $recoveryRoot 'WindowsCatalogRepair-Package.zip'
$hash=(Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash
Copy-Item -LiteralPath $source -Destination $destination -Force
if((Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash -ne $hash){throw 'Recovery copy hash mismatch'}
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'LOGIN-RECOVERY.txt') -Destination $recoveryRoot -Force
[ordered]@{CapturedUtc=[datetime]::UtcNow.ToString('o');ActiveProject=$PSScriptRoot;RecoveryPackage=$destination;SHA256=$hash;Reason='Retain the repair tools on the Windows volume as well as F:. This is not a backup of Windows, profiles or personal files.'} | ConvertTo-Json | Set-Content (Join-Path $PSScriptRoot 'recovery-copy.json') -Encoding UTF8
Write-Host 'Updated package recovery copy on C: matches the active package SHA256.'
