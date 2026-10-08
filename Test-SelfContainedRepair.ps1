$ErrorActionPreference='Stop'
$packageScript=Join-Path $PSScriptRoot 'WindowsCatalogRepair-Package\Repair-WindowsCatalogCorruption.ps1'
$isolation=Join-Path $PSScriptRoot ('evidence\self-contained-'+(Get-Date -Format 'yyyyMMdd-HHmmss-fff'))
$null=New-Item -ItemType Directory -Path $isolation
$standalone=Join-Path $isolation 'Repair-WindowsCatalogCorruption.ps1'
Copy-Item -LiteralPath $packageScript -Destination $standalone
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($standalone,[ref]$tokens,[ref]$errors)
if($errors.Count){throw ($errors.Message -join "`n")}
$definition=$ast.Find({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Get-VerifiedSignTool'},$true)
. ([scriptblock]::Create($definition.Extent.Text))
$run=Join-Path $isolation 'generated'
$null=New-Item -ItemType Directory -Path $run
$tool=Get-VerifiedSignTool
$hash=(Get-FileHash -LiteralPath $tool -Algorithm SHA256).Hash
& $tool verify /kp /hash SHA256 /c "$env:windir\WinSxS\Catalogs\fbc943848826f205637944ff56d4d65876b1aab914759cd14474c4e311965286.cat" "$env:windir\Sysnative\drivers\mpsdrv.sys"
if($LASTEXITCODE -ne 0){throw 'Reconstructed utility failed exact-file verification.'}
# Corrupt only this test-created copy, not a Windows or installed-tool file.
[IO.File]::WriteAllBytes($tool,[byte[]]@(0,1,2,3))
$recreated=Get-VerifiedSignTool
if((Get-FileHash -LiteralPath $recreated -Algorithm SHA256).Hash -cne $hash){throw 'Reconstruction failed.'}
$tampered=$definition.Extent.Text -replace '\$expected=''[0-9A-F]{64}''',('$expected='''+('0'*64)+'''')
. ([scriptblock]::Create($tampered))
$rejected=$false
try{$null=Get-VerifiedSignTool}catch{if($_.Exception.Message -match 'hash mismatch'){$rejected=$true}else{throw}}
if(-not $rejected){throw 'Tampered embedded resource was accepted.'}
[ordered]@{StandaloneScript=$standalone;ExtractedToolHash=$hash;ExactFileVerification=$true;CorruptedTestCopyRecreated=$true;TamperedPayloadRejected=$true;UsedInstalledSDK=$false} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $isolation 'result.json') -Encoding UTF8
Write-Output ('PASS: single-file extraction, valid signature, real verification, damaged-copy reconstruction, tamper rejection. Evidence='+$isolation)
