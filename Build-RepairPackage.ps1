param([switch]$Update)
$ErrorActionPreference='Stop'
$destination=Join-Path $PSScriptRoot 'WindowsCatalogRepair-Package'
$zip=Join-Path $PSScriptRoot 'WindowsCatalogRepair-Package.zip'
if(((Test-Path -LiteralPath $destination) -or (Test-Path -LiteralPath $zip)) -and -not $Update){throw 'Package already exists; use -Update for a backed-up refresh.'}
$backup=Join-Path $PSScriptRoot ('package-backup-'+(Get-Date -Format 'yyyyMMdd-HHmmss-fff'))
if($Update){$null=New-Item -ItemType Directory -Path $backup}
$null=New-Item -ItemType Directory -Path (Join-Path $destination 'Tools') -Force
foreach($name in @('Repair-WindowsCatalogCorruption.ps1','Run-Repair.cmd','PACKAGE-README.txt','LOGIN-RECOVERY.txt','Test-StandaloneCatalogRepair.ps1','Test-LiveCatalogProgress.ps1')) {
    $target=Join-Path $destination $name
    if($Update -and (Test-Path -LiteralPath $target)){Copy-Item -LiteralPath $target -Destination (Join-Path $backup $name)}
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot $name) -Destination $target -Force
}
$source='C:\Program Files (x86)\Windows Kits\10\Tools\bin\i386\signtool.exe'
if((Get-AuthenticodeSignature -LiteralPath $source).Status -ne 'Valid'){throw 'Installed SignTool signature is not valid.'}
$scriptTarget=Join-Path $destination 'Repair-WindowsCatalogCorruption.ps1'
$scriptText=[IO.File]::ReadAllText($scriptTarget)
$embedded=[Convert]::ToBase64String([IO.File]::ReadAllBytes($source))
$sourceHash=(Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash
if(-not $scriptText.Contains('__EMBEDDED_SIGNTOOL_BASE64__')){throw 'Missing embedded-resource marker.'}
# Mechanical packaging substitution; development source remains readable.
$scriptText=$scriptText.Replace('__EMBEDDED_SIGNTOOL_BASE64__',$embedded).Replace('__EMBEDDED_SIGNTOOL_SHA256__',$sourceHash)
$scriptText=$scriptText.Replace('# __REBOOT_READINESS_FUNCTIONS__',[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'RebootReadiness.ps1')))
$scriptText=$scriptText.Replace('# __LOGIN_READINESS_FUNCTIONS__',[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'LoginReadiness.ps1')))
$scriptText=$scriptText.Replace('__LOGIN_RECOVERY_GUIDE__',[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'LOGIN-RECOVERY.txt')))
[IO.File]::WriteAllText($scriptTarget,$scriptText,[Text.Encoding]::UTF8)
$tool=Join-Path $destination 'Tools\signtool.exe'
Copy-Item -LiteralPath $source -Destination $tool
# Exercise the packaged binary, not merely its file existence.
& $tool verify /kp /hash SHA256 /c "$env:windir\WinSxS\Catalogs\fbc943848826f205637944ff56d4d65876b1aab914759cd14474c4e311965286.cat" "$env:windir\Sysnative\drivers\mpsdrv.sys"
if($LASTEXITCODE -ne 0){throw 'Packaged SignTool could not verify the reference driver against its exact catalog.'}
$packageFiles=@('Repair-WindowsCatalogCorruption.ps1','Run-Repair.cmd','PACKAGE-README.txt','LOGIN-RECOVERY.txt','Test-StandaloneCatalogRepair.ps1','Test-LiveCatalogProgress.ps1','Tools\signtool.exe')
$manifest=@($packageFiles | ForEach-Object {Get-Item -LiteralPath (Join-Path $destination $_)} | ForEach-Object {
    [pscustomobject]@{RelativePath=$_.FullName.Substring($destination.Length+1);SHA256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash;Bytes=$_.Length}
})
$manifest | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $destination 'SHA256.json') -Encoding UTF8
$staging=Join-Path $PSScriptRoot ('package-staging-'+[guid]::NewGuid().ToString('N'))
$stagedPackage=Join-Path $staging 'WindowsCatalogRepair-Package'
$null=New-Item -ItemType Directory -Path (Join-Path $stagedPackage 'Tools')
foreach($relative in ($packageFiles+@('SHA256.json'))){Copy-Item -LiteralPath (Join-Path $destination $relative) -Destination (Join-Path $stagedPackage $relative)}
$stagedZip=Join-Path $staging 'WindowsCatalogRepair-Package.zip'
Compress-Archive -LiteralPath $stagedPackage -DestinationPath $stagedZip
if(Test-Path -LiteralPath $zip){Copy-Item -LiteralPath $zip -Destination (Join-Path $backup 'WindowsCatalogRepair-Package.zip')}
Copy-Item -LiteralPath $stagedZip -Destination $zip -Force
Write-Output ('Package='+$zip)
Write-Output ('Launcher='+ (Join-Path $destination 'Run-Repair.cmd'))
