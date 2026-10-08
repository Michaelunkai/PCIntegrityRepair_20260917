# Read-only volume-header inspection. Never writes a disk sector.
$ErrorActionPreference='Stop'
foreach($drive in @('C:','F:')){
 $stream=[IO.File]::Open(('\\.\'+$drive),[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
 try{
  $sector=New-Object byte[] 512;$count=$stream.Read($sector,0,512)
  $oem=[Text.Encoding]::ASCII.GetString($sector,3,8)
  $bps=[BitConverter]::ToUInt16($sector,11);$sectors=[BitConverter]::ToInt64($sector,40)
  [pscustomobject]@{Drive=$drive;ReadBytes=$count;OEM=$oem;BytesPerSector=$bps;SectorsField=$sectors;EndMarker=('{0:X2}{1:X2}' -f $sector[510],$sector[511])} | ConvertTo-Json
  if($bps -eq 512 -and $sectors -gt 1 -and $sectors -lt 20000000000){
   $null=$stream.Seek($sectors*$bps,[IO.SeekOrigin]::Begin);$backup=New-Object byte[] 512;$n=$stream.Read($backup,0,512)
   [pscustomobject]@{Drive=$drive;BackupOffset=$sectors*$bps;ReadBytes=$n;OEM=[Text.Encoding]::ASCII.GetString($backup,3,8);SameHeader=([Convert]::ToBase64String($sector) -eq [Convert]::ToBase64String($backup))} | ConvertTo-Json
  }
 }finally{$stream.Dispose()}
}
