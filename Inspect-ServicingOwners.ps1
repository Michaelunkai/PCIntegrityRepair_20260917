$ErrorActionPreference='Stop'
$processes=@(Get-CimInstance Win32_Process)
foreach($native in @($processes | Where-Object Name -in 'sfc.exe','dism.exe')){
 $current=$native;$seen=@{}
 for($level=0;$level -lt 5 -and $current -and -not $seen.ContainsKey($current.ProcessId);$level++){
  $seen[$current.ProcessId]=$true
  [pscustomobject]@{Level=$level;Name=$current.Name;PID=$current.ProcessId;Parent=$current.ParentProcessId;Started=$current.CreationDate;CommandLine=$current.CommandLine} | ConvertTo-Json
  $parent=$current.ParentProcessId;$current=$processes | Where-Object ProcessId -eq $parent | Select-Object -First 1
 }
}
