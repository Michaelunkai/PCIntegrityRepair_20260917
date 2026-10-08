$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.IO.Compression.FileSystem
$zipPath=Join-Path $PSScriptRoot 'WindowsCatalogRepair-Package.zip'
$archive=[IO.Compression.ZipFile]::OpenRead($zipPath)
try {
    $manifestEntry=@($archive.Entries | Where-Object FullName -Match '[/\\]SHA256\.json$')
    if($manifestEntry.Count -ne 1){throw 'Missing or ambiguous manifest.'}
    $reader=New-Object IO.StreamReader($manifestEntry[0].Open())
    try{$manifest=$reader.ReadToEnd() | ConvertFrom-Json}finally{$reader.Dispose()}
    foreach($item in $manifest) {
        $expected=('WindowsCatalogRepair-Package/'+$item.RelativePath.Replace('\','/'))
        $entry=@($archive.Entries | Where-Object {$_.FullName.Replace('\','/') -ceq $expected})
        if($entry.Count -ne 1){throw ('Missing or duplicate archive member: '+$expected)}
        $stream=$entry[0].Open();$sha=[Security.Cryptography.SHA256]::Create()
        try{$hash=[BitConverter]::ToString($sha.ComputeHash($stream)).Replace('-','')}finally{$stream.Dispose();$sha.Dispose()}
        if($hash -cne $item.SHA256 -or $entry[0].Length -ne $item.Bytes){throw ('Archive mismatch: '+$expected)}
    }
    if(@($archive.Entries | Where-Object FullName -Match '[/\\]evidence[/\\]').Count){throw 'Personal evidence accidentally packaged.'}
    Write-Output ('PASS: '+@($manifest).Count+' packaged file hashes/sizes; no evidence logs in ZIP.')
}finally{$archive.Dispose()}
