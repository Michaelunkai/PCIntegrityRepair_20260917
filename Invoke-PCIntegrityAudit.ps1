#requires -Version 5.1
[CmdletBinding()]
param(
    [string]$OutputRoot,
    [switch]$RepairWindowsFiles,
    [switch]$ConfirmRepair,
    [switch]$SelfTest,
    [ValidateRange(60, 21600)]
    [int]$NativeTimeoutSeconds = 7200,
    [ValidateRange(60, 1800)]
    [int]$ServicingSettleSeconds = 300,
    [ValidateRange(5, 120)]
    [int]$ServicingQuietSeconds = 30
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:Checks = [System.Collections.Generic.List[object]]::new()
$script:RunStartedLocal = [DateTime]::Now
$script:RunId = $script:RunStartedLocal.ToString('yyyyMMdd-HHmmss-fff')
$script:Mode = if ($RepairWindowsFiles) { 'Repair' } else { 'Audit' }
$script:WindowsPowerShellExecutable = [System.IO.Path]::Combine($env:windir, 'System32\WindowsPowerShell\v1.0\powershell.exe')
if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
    $sysnativePowerShell = [System.IO.Path]::Combine($env:windir, 'Sysnative\WindowsPowerShell\v1.0\powershell.exe')
    if ([System.IO.File]::Exists($sysnativePowerShell)) { $script:WindowsPowerShellExecutable = $sysnativePowerShell }
}
$script:ServicingSettleSeconds = $ServicingSettleSeconds
$script:ServicingQuietSeconds = $ServicingQuietSeconds
if ($ServicingQuietSeconds -ge $ServicingSettleSeconds) {
    [Console]::Error.WriteLine('ServicingSettleSeconds must exceed ServicingQuietSeconds.')
    exit 12
}

if ([string]::IsNullOrWhiteSpace($OutputRoot)) {
    $OutputRoot = [System.IO.Path]::Combine($PSScriptRoot, 'evidence')
}
$script:RunDirectory = [System.IO.Path]::Combine($OutputRoot, $script:RunId)
$script:ReportPath = [System.IO.Path]::Combine($script:RunDirectory, 'report.json')

function Add-PCCheck {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][ValidateSet('pass', 'warn', 'fail', 'blocked', 'unknown')][string]$Status,
        [Parameter(Mandatory = $true)][string]$Summary,
        [object]$Evidence = $null
    )
    $script:Checks.Add([pscustomobject][ordered]@{
        Name = $Name
        Status = $Status
        Summary = $Summary
        Evidence = $Evidence
    })
}

function Get-PCStorageEventVerdict {
    param(
        [Parameter(Mandatory = $true)][string]$ProviderName,
        [Parameter(Mandatory = $true)][int]$EventId,
        [string]$Message = ''
    )
    if ($ProviderName -match '(^Ntfs$|Microsoft-Windows-Ntfs)' -and $EventId -eq 98 -and $Message -match '(?i)\bis healthy\.\s*No action is needed\.') {
        return [pscustomobject]@{ Status = 'pass'; Summary = 'NTFS Event 98 explicitly reports the volume is healthy; no action is needed.' }
    }
    if ($ProviderName -ieq 'disk' -and $EventId -eq 153) {
        return [pscustomobject]@{ Status = 'warn'; Summary = 'Disk Event 153 records a retried I/O operation; correlate the disk and investigate the storage path.' }
    }
    return [pscustomobject]@{ Status = 'warn'; Summary = 'A recent storage event requires device and time-context review.' }
}

function Get-PCStorageEventsHistoryVerdict {
    param(
        [int]$EventCount = 0,
        [int]$WarningEventCount = 0,
        [string]$EventQueryError = '',
        [bool]$EvidenceWritten = $true,
        [string]$EvidenceWriteError = '',
        [Parameter(Mandatory = $true)][object]$HistoryState
    )
    if ($WarningEventCount -gt 0) {
        $status = 'warn'
        $summary = '{0} storage-related events captured; {1} require investigation. Explicit healthy NTFS Event 98 records are informational.' -f $EventCount, $WarningEventCount
    }
    elseif (-not [string]::IsNullOrWhiteSpace($EventQueryError)) {
        $status = 'unknown'
        $summary = 'Could not query the last 30 days of storage-related System events: ' + $EventQueryError
    }
    elseif (-not [bool]$HistoryState.HistoryComplete) {
        $status = 'unknown'
        if ($EventCount -eq 0) {
            $summary = 'No matching storage-related events were found in the retained System records; the requested 30-day history is incomplete.'
        }
        else {
            $summary = '{0} storage-related event(s) were captured in retained System records, but the requested 30-day history is incomplete.' -f $EventCount
        }
    }
    elseif (-not $EvidenceWritten) {
        $status = 'unknown'
        $summary = 'Storage-event evidence could not be persisted, so the result cannot be verified.'
    }
    elseif ($EventCount -eq 0) {
        $status = 'pass'
        $summary = 'No matching storage-related System events were found in the last 30 days.'
    }
    else {
        $status = 'pass'
        $summary = '{0} storage-related event(s) captured, all explicitly classified as healthy NTFS Event 98 information.' -f $EventCount
    }
    if (-not [bool]$HistoryState.HistoryComplete -and -not [string]::IsNullOrWhiteSpace([string]$HistoryState.Summary)) {
        $summary += ' ' + [string]$HistoryState.Summary
    }
    if (-not $EvidenceWritten -and -not [string]::IsNullOrWhiteSpace($EvidenceWriteError)) {
        $summary += ' Evidence file could not be written: ' + $EvidenceWriteError
    }
    return [pscustomobject]@{ Status = $status; Summary = $summary }
}

function Get-PCDiskNumberFromStorageEvent {
    param(
        [string]$Message = '',
        [object[]]$Properties = @()
    )
    $messageMatch = [System.Text.RegularExpressions.Regex]::Match($Message, '(?i)\bDisk\s+(?<number>\d+)\b')
    if ($messageMatch.Success) { return [int]$messageMatch.Groups['number'].Value }
    foreach ($property in @($Properties)) {
        if ($null -eq $property) { continue }
        $value = if ($property.PSObject.Properties['Value']) { [string]$property.Value } else { [string]$property }
        $deviceMatch = [System.Text.RegularExpressions.Regex]::Match($value, '(?i)\\Harddisk(?<number>\d+)\\DR\d+')
        if ($deviceMatch.Success) { return [int]$deviceMatch.Groups['number'].Value }
    }
    return $null
}

function Get-PCStorageDriveLettersFromEvent {
    param(
        [string]$Message = '',
        [object[]]$Properties = @()
    )
    $textParts = [System.Collections.Generic.List[string]]::new()
    if (-not [string]::IsNullOrWhiteSpace($Message)) { $textParts.Add($Message) }
    foreach ($property in @($Properties)) {
        if ($null -eq $property) { continue }
        $value = if ($property.PSObject.Properties['Value']) { [string]$property.Value } else { [string]$property }
        if (-not [string]::IsNullOrWhiteSpace($value)) { $textParts.Add($value) }
    }
    $letters = [System.Collections.Generic.List[string]]::new()
    $matches = [System.Text.RegularExpressions.Regex]::Matches(($textParts -join ' '), '(?i)(?<![A-Z0-9])(?<letter>[A-Z]):(?=\\|[^A-Z0-9]|$)')
    foreach ($match in $matches) {
        $letter = $match.Groups['letter'].Value.ToUpperInvariant() + ':'
        if (-not $letters.Contains($letter)) { $letters.Add($letter) }
    }
    return @($letters.ToArray() | Sort-Object)
}

function Get-PCStorageDiskMap {
    param(
        [object[]]$DiskDrives = @(),
        [object[]]$PartitionAssociations = @(),
        [object[]]$LogicalDisks = @()
    )
    $diskMap = @{}
    foreach ($drive in @($DiskDrives)) {
        $number = [int]$drive.Index
        $sizeGiB = if ($null -ne $drive.Size) { [Math]::Round(([double]$drive.Size / 1GB), 1) } else { $null }
        $diskMap[$number] = [pscustomobject][ordered]@{
            Number = $number
            DeviceId = [string]$drive.DeviceID
            Model = [string]$drive.Model
            SizeGiB = $sizeGiB
            Status = [string]$drive.Status
            DriveLetters = @()
            Volumes = @()
        }
    }

    foreach ($association in @($PartitionAssociations)) {
        if ($null -eq $association.Antecedent -or $null -eq $association.Dependent) { continue }
        $antecedent = $association.Antecedent
        $partitionText = if ($antecedent -is [string]) { $antecedent } elseif ($antecedent.PSObject.Properties['DeviceID']) { [string]$antecedent.DeviceID } else { [string]$antecedent }
        $diskMatch = [System.Text.RegularExpressions.Regex]::Match($partitionText, '(?i)Disk\s*#?\s*(?<number>\d+),')
        if (-not $diskMatch.Success) { continue }
        $diskNumber = [int]$diskMatch.Groups['number'].Value

        $dependent = $association.Dependent
        $driveLetter = if ($dependent -is [string]) {
            $letterMatch = [System.Text.RegularExpressions.Regex]::Match($dependent, '(?i)DeviceID\s*=\s*"(?<letter>[A-Z]:)"')
            if ($letterMatch.Success) { $letterMatch.Groups['letter'].Value.ToUpperInvariant() } else { '' }
        }
        elseif ($dependent.PSObject.Properties['DeviceID']) { ([string]$dependent.DeviceID).ToUpperInvariant() }
        else { '' }
        if ($driveLetter -notmatch '^[A-Z]:$' -or -not $diskMap.ContainsKey($diskNumber)) { continue }
        $entry = $diskMap[$diskNumber]
        $entry.DriveLetters = @(@($entry.DriveLetters) + $driveLetter | Sort-Object -Unique)
    }

    $volumeByLetter = @{}
    foreach ($logical in @($LogicalDisks)) {
        if ($null -eq $logical.DeviceID) { continue }
        $letter = ([string]$logical.DeviceID).ToUpperInvariant()
        $volumeByLetter[$letter] = [pscustomobject]@{ DriveLetter = $letter; FileSystem = [string]$logical.FileSystem }
    }
    foreach ($entry in @($diskMap.Values)) {
        $volumes = [System.Collections.Generic.List[object]]::new()
        foreach ($letter in @($entry.DriveLetters | Sort-Object -Unique)) {
            if ($volumeByLetter.ContainsKey($letter)) { $volumes.Add($volumeByLetter[$letter]) }
            else { $volumes.Add([pscustomobject]@{ DriveLetter = $letter; FileSystem = $null }) }
        }
        $entry.DriveLetters = @($entry.DriveLetters | Sort-Object -Unique)
        $entry.Volumes = @($volumes.ToArray())
    }
    return @($diskMap.Values | Sort-Object Number)
}

function Get-PCOverallStatus {
    param([Parameter(Mandatory = $true)][object[]]$Checks)
    $checkArray = @($Checks)
    if (@($checkArray | Where-Object { $_.Status -eq 'fail' }).Count -gt 0) { return 'Failed' }
    if (@($checkArray | Where-Object { $_.Status -eq 'blocked' -or $_.Status -eq 'unknown' }).Count -gt 0) { return 'Incomplete' }
    if (@($checkArray | Where-Object { $_.Status -eq 'warn' }).Count -gt 0) { return 'NeedsReview' }
    return 'Completed'
}

function Get-PCStorageReliabilityVerdict {
    param(
        [string]$HealthStatus,
        [string[]]$OperationalStatus = @(),
        [object]$Counters = $null
    )
    $warningReasons = [System.Collections.Generic.List[string]]::new()
    $missingFields = [System.Collections.Generic.List[string]]::new()
    if ([string]::IsNullOrWhiteSpace($HealthStatus)) { $missingFields.Add('HealthStatus') }
    elseif ($HealthStatus -ne 'Healthy') { $warningReasons.Add('Windows storage HealthStatus is ' + $HealthStatus + '.') }
    $operational = @($OperationalStatus | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
    if ($operational.Count -eq 0) { $missingFields.Add('OperationalStatus') }
    elseif ($operational -notcontains 'Online') { $warningReasons.Add('Disk is not reported Online.') }

    $counterFields = @(
        'ReadErrorsTotal', 'ReadErrorsUncorrected', 'WriteErrorsTotal', 'WriteErrorsUncorrected',
        'ReadLatencyMax', 'WriteLatencyMax', 'FlushLatencyMax', 'Temperature', 'Wear'
    )
    $counterValues = [ordered]@{}
    if ($null -eq $Counters) {
        foreach ($field in $counterFields) { $counterValues[$field] = $null }
        $missingFields.Add('StorageReliabilityCounter')
    }
    else {
        foreach ($field in $counterFields) {
            $property = $Counters.PSObject.Properties[$field]
            $value = if ($null -ne $property) { $property.Value } else { $null }
            $counterValues[$field] = $value
            if ($null -eq $value -or [string]::IsNullOrWhiteSpace([string]$value)) {
                $missingFields.Add($field)
                continue
            }
            if ($field -match 'Errors' -and [double]$value -gt 0) { $warningReasons.Add($field + ' is ' + $value + '.') }
            if ($field -match 'LatencyMax' -and [double]$value -gt 10000) { $warningReasons.Add($field + ' is ' + $value + ' ms; values above 10000 ms warrant review.') }
        }
    }

    $status = if ($warningReasons.Count -gt 0) { 'warn' } elseif ($missingFields.Count -gt 0) { 'unknown' } else { 'pass' }
    $summary = if ($warningReasons.Count -gt 0) {
        $warningReasons -join ' '
    }
    elseif ($missingFields.Count -gt 0) {
        'Some storage health or reliability fields were unavailable: ' + ($missingFields -join ', ') + '.'
    }
    else {
        'Windows reports the disk online/healthy and the exposed reliability counters show no threshold breach.'
    }
    return [pscustomobject]@{
        Status = $status
        Summary = $summary
        CounterValues = [pscustomobject]$counterValues
        WarningReasons = @($warningReasons.ToArray())
        MissingFields = @($missingFields.ToArray())
    }
}

function Get-PCStorageCounterSnapshot {
    param([object]$Counters)
    if ($null -eq $Counters) { return $null }
    $fields = @(
        'DeviceId', 'PowerOnHours', 'LoadUnloadCycleCount', 'LoadUnloadCycleCountMax',
        'StartStopCycleCount', 'StartStopCycleCountMax', 'ReadErrorsCorrected', 'ReadErrorsTotal',
        'ReadErrorsUncorrected', 'ReadLatencyMax', 'WriteErrorsCorrected', 'WriteErrorsTotal',
        'WriteErrorsUncorrected', 'WriteLatencyMax', 'FlushLatencyMax', 'Temperature',
        'TemperatureMax', 'Wear', 'ManufactureDate'
    )
    $snapshot = [ordered]@{}
    foreach ($field in $fields) {
        $property = $Counters.PSObject.Properties[$field]
        $snapshot[$field] = if ($null -ne $property) { $property.Value } else { $null }
    }
    return [pscustomobject]$snapshot
}

function Get-PCErrorSummary {
    param([Parameter(Mandatory = $true)][System.Management.Automation.ErrorRecord]$ErrorRecord)
    $message = [string]$ErrorRecord.Exception.Message
    $errorId = [string]$ErrorRecord.FullyQualifiedErrorId
    if (-not [string]::IsNullOrWhiteSpace($errorId)) {
        if ([string]::IsNullOrWhiteSpace($message)) { return $errorId }
        return $message + ' [' + $errorId + ']'
    }
    return $message
}

function Get-PCEventLogClearAudit {
    param([Parameter(Mandatory = $true)][datetime]$SinceLocal)

    $records = @()
    $queryErrors = [System.Collections.Generic.List[string]]::new()
    try {
        $records = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Eventlog'; Id = 104; StartTime = $SinceLocal } -ErrorAction Stop)
    }
    catch {
        $isNoMatchingEvents = ($_.FullyQualifiedErrorId -match 'NoMatchingEventsFound') -or ($_.Exception.Message -match '(?i)no events were found|no events found')
        if (-not $isNoMatchingEvents) { $queryErrors.Add('System Event ID 104 query: ' + (Get-PCErrorSummary -ErrorRecord $_)) }
    }

    $clearEvents = [System.Collections.Generic.List[object]]::new()
    foreach ($record in @($records)) {
        try {
            $xml = [xml]$record.ToXml()
            $clearData = $xml.SelectSingleNode("//*[local-name()='LogFileCleared']")
            if ($null -eq $clearData) { throw 'Event ID 104 had no LogFileCleared data.' }
            $channelNode = $clearData.SelectSingleNode("*[local-name()='Channel']")
            if ($null -eq $channelNode -or [string]::IsNullOrWhiteSpace([string]$channelNode.InnerText)) { throw 'Event ID 104 did not identify the cleared channel.' }
            $userNode = $clearData.SelectSingleNode("*[local-name()='SubjectUserName']")
            $domainNode = $clearData.SelectSingleNode("*[local-name()='SubjectDomainName']")
            $processNode = $clearData.SelectSingleNode("*[local-name()='ClientProcessId']")
            $clearEvents.Add([pscustomobject][ordered]@{
                Channel = [string]$channelNode.InnerText
                TimeCreatedLocal = $record.TimeCreated.ToString('o')
                TimeCreatedUtc = $record.TimeCreated.ToUniversalTime().ToString('o')
                EventRecordId = [long]$record.RecordId
                SubjectUserName = if ($null -ne $userNode) { [string]$userNode.InnerText } else { '' }
                SubjectDomainName = if ($null -ne $domainNode) { [string]$domainNode.InnerText } else { '' }
                ClientProcessId = if ($null -ne $processNode -and [string]$processNode.InnerText -match '^\d+$') { [int]$processNode.InnerText } else { $null }
            })
        }
        catch {
            $queryErrors.Add(('Could not parse System Event ID 104 record {0}: {1}' -f $record.RecordId, $_.Exception.Message))
        }
    }

    $securityRecords = @()
    $securityQueryErrors = [System.Collections.Generic.List[string]]::new()
    try {
        $securityRecords = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 1102; StartTime = $SinceLocal } -ErrorAction Stop)
    }
    catch {
        $isNoMatchingEvents = ($_.FullyQualifiedErrorId -match 'NoMatchingEventsFound') -or ($_.Exception.Message -match '(?i)no events were found|no events found')
        if (-not $isNoMatchingEvents) { $securityQueryErrors.Add('Security Event ID 1102 query: ' + (Get-PCErrorSummary -ErrorRecord $_)) }
    }
    $securityClearEvents = [System.Collections.Generic.List[object]]::new()
    foreach ($record in @($securityRecords)) {
        try {
            $xml = [xml]$record.ToXml()
            $clearData = $xml.SelectSingleNode("//*[local-name()='LogFileCleared']")
            if ($null -eq $clearData) { throw 'Event ID 1102 had no LogFileCleared data.' }
            $userNode = $clearData.SelectSingleNode("*[local-name()='SubjectUserName']")
            $domainNode = $clearData.SelectSingleNode("*[local-name()='SubjectDomainName']")
            $logonNode = $clearData.SelectSingleNode("*[local-name()='SubjectLogonId']")
            $processNode = $clearData.SelectSingleNode("*[local-name()='ClientProcessId']")
            $securityClearEvents.Add([pscustomobject][ordered]@{
                Channel = 'Security'
                TimeCreatedLocal = $record.TimeCreated.ToString('o')
                TimeCreatedUtc = $record.TimeCreated.ToUniversalTime().ToString('o')
                EventRecordId = [long]$record.RecordId
                SubjectUserName = if ($null -ne $userNode) { [string]$userNode.InnerText } else { '' }
                SubjectDomainName = if ($null -ne $domainNode) { [string]$domainNode.InnerText } else { '' }
                SubjectLogonId = if ($null -ne $logonNode) { [string]$logonNode.InnerText } else { '' }
                ClientProcessId = if ($null -ne $processNode -and [string]$processNode.InnerText -match '^\d+$') { [int]$processNode.InnerText } else { $null }
            })
        }
        catch {
            $securityQueryErrors.Add(('Could not parse Security Event ID 1102 record {0}: {1}' -f $record.RecordId, $_.Exception.Message))
        }
    }

    return [pscustomobject]@{
        WindowStartLocal = $SinceLocal.ToString('o')
        EventCount = $clearEvents.Count
        QueryError = $queryErrors -join ' | '
        Events = $clearEvents.ToArray()
        SecurityClearEventCount = $securityClearEvents.Count
        SecurityQueryError = $securityQueryErrors -join ' | '
        SecurityClearEvents = $securityClearEvents.ToArray()
    }
}

function Get-PCEventLogClearState {
    param(
        [Parameter(Mandatory = $true)][object]$Audit,
        [Parameter(Mandatory = $true)][string]$LogName,
        [Parameter(Mandatory = $true)][datetime]$WindowStartLocal,
        [object]$LogMetadata = $null
    )

    $matchingClears = [System.Collections.Generic.List[object]]::new()
    $stateErrors = [System.Collections.Generic.List[string]]::new()
    $coverageNotes = [System.Collections.Generic.List[string]]::new()
    if (-not [string]::IsNullOrWhiteSpace([string]$Audit.QueryError)) { $stateErrors.Add([string]$Audit.QueryError) }
    foreach ($event in @($Audit.Events)) {
        if ([string]$event.Channel -ine $LogName) { continue }
        try {
            $clearTime = [DateTimeOffset]::Parse([string]$event.TimeCreatedLocal).LocalDateTime
            if ($clearTime -ge $WindowStartLocal) { $matchingClears.Add($event) }
        }
        catch {
            $stateErrors.Add(('Could not evaluate clear time for {0} Event ID 104 record {1}: {2}' -f $LogName, $event.EventRecordId, $_.Exception.Message))
        }
    }

    if ($null -eq $LogMetadata) {
        $metadataEnabled = $null
        $metadataRecordCount = $null
        $oldestRecordTimeLocal = $null
        $metadataQueryError = $null
        try {
            $logInfo = Get-WinEvent -ListLog $LogName -ErrorAction Stop
            $enabledProperty = $logInfo.PSObject.Properties['IsEnabled']
            if ($null -ne $enabledProperty) { $metadataEnabled = [bool]$enabledProperty.Value }
            $recordCountProperty = $logInfo.PSObject.Properties['RecordCount']
            if ($null -ne $recordCountProperty -and $null -ne $recordCountProperty.Value) { $metadataRecordCount = [long]$recordCountProperty.Value }
            else { $metadataRecordCount = 0 }
            if (-not $metadataEnabled) {
                $metadataQueryError = 'The channel is disabled; its requested history cannot be verified.'
            }
            elseif ($metadataRecordCount -le 0) {
                $metadataQueryError = 'The channel has no retained events from which to establish the requested history window.'
            }
            else {
                $oldestRecord = Get-WinEvent -LogName $LogName -Oldest -MaxEvents 1 -ErrorAction Stop
                if ($null -eq $oldestRecord -or $null -eq $oldestRecord.TimeCreated) {
                    $metadataQueryError = 'The oldest retained event time could not be determined.'
                }
                else {
                    $oldestRecordTimeLocal = $oldestRecord.TimeCreated.ToString('o')
                }
            }
        }
        catch {
            $metadataQueryError = Get-PCErrorSummary -ErrorRecord $_
        }
        $LogMetadata = [pscustomobject]@{
            IsEnabled = $metadataEnabled
            RecordCount = $metadataRecordCount
            OldestRecordTimeLocal = $oldestRecordTimeLocal
            QueryError = $metadataQueryError
        }
    }
    if (-not [string]::IsNullOrWhiteSpace([string]$LogMetadata.QueryError)) { $stateErrors.Add('Log coverage metadata: ' + [string]$LogMetadata.QueryError) }
    elseif ($null -eq $LogMetadata.OldestRecordTimeLocal) { $stateErrors.Add('Log coverage metadata did not contain the oldest retained event time.') }
    else {
        try {
            $oldestRecordTime = [DateTimeOffset]::Parse([string]$LogMetadata.OldestRecordTimeLocal).LocalDateTime
            if ($oldestRecordTime -gt $WindowStartLocal) {
                $coverageNotes.Add(('The oldest retained event in {0} is {1}, later than the requested window start {2}; earlier history is unavailable.' -f $LogName, $LogMetadata.OldestRecordTimeLocal, $WindowStartLocal.ToString('o')))
            }
        }
        catch {
            $stateErrors.Add(('Could not evaluate the oldest retained event time for {0}: {1}' -f $LogName, $_.Exception.Message))
        }
    }

    $latestClear = $null
    if ($matchingClears.Count -gt 0) { $latestClear = $matchingClears | Sort-Object TimeCreatedUtc -Descending | Select-Object -First 1 }
    $queryError = $stateErrors -join ' | '
    $historyStatus = if (-not [string]::IsNullOrWhiteSpace($queryError)) { 'unknown' } elseif ($matchingClears.Count -gt 0 -or $coverageNotes.Count -gt 0) { 'partial' } else { 'complete' }
    $summary = ''
    if ($historyStatus -eq 'partial') {
        if ($null -ne $latestClear) { $summary = ('Historical coverage for {0} is partial: it was cleared at {1} (System Event ID 104 record {2}); earlier records in this window are unavailable.' -f $LogName, $latestClear.TimeCreatedLocal, $latestClear.EventRecordId) }
        foreach ($coverageNote in $coverageNotes) {
            if (-not [string]::IsNullOrWhiteSpace($summary)) { $summary += ' ' }
            $summary += $coverageNote
        }
    }
    elseif ($historyStatus -eq 'unknown') {
        $summary = 'Could not verify ' + $LogName + ' log-clear history: ' + $queryError
        if ($null -ne $latestClear) { $summary += ' A clear was also recorded at ' + $latestClear.TimeCreatedLocal + '.' }
    }

    return [pscustomobject]@{
        LogName = $LogName
        WindowStartLocal = $WindowStartLocal.ToString('o')
        HistoryStatus = $historyStatus
        HistoryComplete = ($historyStatus -eq 'complete')
        ClearCount = $matchingClears.Count
        LatestClear = $latestClear
        Clears = $matchingClears.ToArray()
        LogMetadata = $LogMetadata
        QueryError = $queryError
        Summary = $summary
    }
}

function Get-PCFirewallStateVerdict {
    param(
        [string]$FirewallServiceState,
        [string]$FirewallStartMode,
        [string]$BaseFilteringEngineState,
        [string]$NetworkStoreInterfaceState,
        [int]$MpsdrvIntegrityFailureCount = 0,
        [string]$MpsdrvIntegrityQueryError = '',
        [bool]$MpsdrvIntegrityHistoryComplete = $true,
        [string]$MpsdrvIntegrityHistoryNote = '',
        [object[]]$EffectiveProfiles = @(),
        [string]$ProfileQueryError = '',
        [string]$ServiceQueryError = ''
    )
    $warnings = [System.Collections.Generic.List[string]]::new()
    $missing = [System.Collections.Generic.List[string]]::new()
    if (-not [string]::IsNullOrWhiteSpace($ServiceQueryError)) { $missing.Add('firewall dependency service query') }
    if ([string]::IsNullOrWhiteSpace($FirewallServiceState)) { $missing.Add('MpsSvc state') }
    elseif ($FirewallServiceState -ne 'Running') { $warnings.Add('Windows Defender Firewall service (MpsSvc) is ' + $FirewallServiceState + '.') }
    if (-not [string]::IsNullOrWhiteSpace($FirewallServiceState) -and $FirewallStartMode -eq 'Disabled') { $warnings.Add('MpsSvc startup mode is Disabled.') }
    if ([string]::IsNullOrWhiteSpace($BaseFilteringEngineState)) { $missing.Add('BFE state') }
    elseif ($BaseFilteringEngineState -ne 'Running') { $warnings.Add('Base Filtering Engine (BFE) is ' + $BaseFilteringEngineState + '.') }
    if ([string]::IsNullOrWhiteSpace($NetworkStoreInterfaceState)) { $missing.Add('NSI state') }
    elseif ($NetworkStoreInterfaceState -ne 'Running') { $warnings.Add('Network Store Interface (NSI) service is ' + $NetworkStoreInterfaceState + '.') }
    if ($MpsdrvIntegrityFailureCount -gt 0) { $warnings.Add('Windows Code Integrity logged ' + $MpsdrvIntegrityFailureCount + ' image-integrity failure event(s) for mpsdrv.sys.') }
    if (-not [string]::IsNullOrWhiteSpace($MpsdrvIntegrityQueryError)) { $missing.Add('mpsdrv Code Integrity event query') }
    if (-not $MpsdrvIntegrityHistoryComplete -and $MpsdrvIntegrityFailureCount -eq 0 -and [string]::IsNullOrWhiteSpace($MpsdrvIntegrityQueryError)) { $missing.Add('complete mpsdrv Code Integrity event history') }
    $profiles = @($EffectiveProfiles)
    if ($profiles.Count -eq 0) {
        if ([string]::IsNullOrWhiteSpace($ProfileQueryError)) { $missing.Add('effective firewall profiles') }
    }
    else {
        $disabledProfiles = @($profiles | Where-Object { -not [bool]$_.Enabled })
        if ($disabledProfiles.Count -gt 0) { $warnings.Add('Firewall profiles reported disabled: ' + (@($disabledProfiles | ForEach-Object { [string]$_.Name }) -join ', ') + '.') }
        if ($profiles.Count -lt 3) { $missing.Add('one or more effective firewall profiles') }
    }
    if (-not [string]::IsNullOrWhiteSpace($ProfileQueryError) -and $warnings.Count -eq 0) { $missing.Add('effective profile query failed') }
    $status = if ($warnings.Count -gt 0) { 'warn' } elseif ($missing.Count -gt 0) { 'unknown' } else { 'pass' }
    $summary = if ($warnings.Count -gt 0) { $warnings -join ' ' } elseif ($missing.Count -gt 0) { 'Firewall state could not be fully verified: ' + ($missing -join ', ') + '.' } else { 'MpsSvc, BFE, and NSI are running and all three effective firewall profiles are enabled.' }
    if (-not [string]::IsNullOrWhiteSpace($ProfileQueryError)) { $summary += ' Profile query error: ' + $ProfileQueryError }
    if (-not [string]::IsNullOrWhiteSpace($MpsdrvIntegrityQueryError)) { $summary += ' mpsdrv Code Integrity query error: ' + $MpsdrvIntegrityQueryError }
    if (-not $MpsdrvIntegrityHistoryComplete) {
        if (-not [string]::IsNullOrWhiteSpace($MpsdrvIntegrityHistoryNote)) { $summary += ' ' + $MpsdrvIntegrityHistoryNote }
        else { $summary += ' Historical mpsdrv Code Integrity coverage is incomplete.' }
    }
    return [pscustomobject]@{ Status = $status; Summary = $summary; WarningReasons = @($warnings.ToArray()); MissingFields = @($missing.ToArray()) }
}

function Get-PCBitsAuditVerdict {
    param(
        [object[]]$Jobs = @(),
        [int]$Event61Count = 0,
        [string[]]$QueryErrors = @(),
        [bool]$EventHistoryComplete = $true,
        [string]$EventHistoryNote = ''
    )
    $failedJobs = @($Jobs | Where-Object { [string]$_.JobState -in @('Error', 'TransientError') })
    $errors = @($QueryErrors | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
    if ($failedJobs.Count -gt 0 -or $Event61Count -gt 0) {
        $status = 'warn'
        $summary = '{0} BITS job(s) are in Error/TransientError; {1} Event 61 record(s) were found in the last five hours.' -f $failedJobs.Count, $Event61Count
        if ($errors.Count -gt 0) { $summary += ' Some queries also failed: ' + ($errors -join ' | ') }
        if (-not $EventHistoryComplete) {
            if (-not [string]::IsNullOrWhiteSpace($EventHistoryNote)) { $summary += ' ' + $EventHistoryNote }
            else { $summary += ' BITS Event 61 history is incomplete.' }
        }
    }
    elseif ($errors.Count -gt 0 -or -not $EventHistoryComplete) {
        $status = 'unknown'
        $unknownReasons = [System.Collections.Generic.List[string]]::new()
        foreach ($errorText in $errors) { $unknownReasons.Add([string]$errorText) }
        if (-not $EventHistoryComplete) {
            if (-not [string]::IsNullOrWhiteSpace($EventHistoryNote)) { $unknownReasons.Add($EventHistoryNote) }
            else { $unknownReasons.Add('BITS Event 61 history is incomplete.') }
        }
        $summary = 'BITS job/event state could not be fully verified: ' + ($unknownReasons -join ' | ')
    }
    else {
        $status = 'pass'
        $summary = 'No BITS jobs are in Error/TransientError and no Event 61 records were found in the last five hours.'
    }
    return [pscustomobject]@{ Status = $status; Summary = $summary; FailedJobCount = $failedJobs.Count; Event61Count = $Event61Count; QueryErrors = $errors; EventHistoryComplete = $EventHistoryComplete }
}

function Get-PCServiceStabilityVerdict {
    param(
        [string]$ServiceName,
        [string]$ServiceState,
        [string]$StartMode,
        [int]$UnexpectedExitCount = 0,
        [string]$QueryError = '',
        [bool]$EventHistoryComplete = $true,
        [string]$EventHistoryNote = ''
    )
    if ($UnexpectedExitCount -gt 0) {
        $summary = '{0} unexpected service-exit event(s) mention {1} in the last 30 days.' -f $UnexpectedExitCount, $ServiceName
        if (-not [string]::IsNullOrWhiteSpace($ServiceState)) { $summary += ' Current state=' + $ServiceState + '; start mode=' + $StartMode + '.' }
        if (-not [string]::IsNullOrWhiteSpace($QueryError)) { $summary += ' A related query failed: ' + $QueryError }
        if (-not $EventHistoryComplete) {
            if (-not [string]::IsNullOrWhiteSpace($EventHistoryNote)) { $summary += ' ' + $EventHistoryNote }
            else { $summary += ' Service-exit event history is incomplete.' }
        }
        return [pscustomobject]@{ Status = 'warn'; Summary = $summary }
    }
    if (-not [string]::IsNullOrWhiteSpace($QueryError)) {
        $summary = 'Could not complete the ' + $ServiceName + ' stability query: ' + $QueryError
        if (-not $EventHistoryComplete -and -not [string]::IsNullOrWhiteSpace($EventHistoryNote)) { $summary += ' ' + $EventHistoryNote }
        return [pscustomobject]@{ Status = 'unknown'; Summary = $summary }
    }
    if ([string]::IsNullOrWhiteSpace($ServiceState)) {
        $summary = 'Could not determine the current ' + $ServiceName + ' service state.'
        if (-not $EventHistoryComplete -and -not [string]::IsNullOrWhiteSpace($EventHistoryNote)) { $summary += ' ' + $EventHistoryNote }
        return [pscustomobject]@{ Status = 'unknown'; Summary = $summary }
    }
    if ($ServiceState -ne 'Running' -and $StartMode -match '^(?i:Auto|Automatic)$') {
        $summary = $ServiceName + ' is configured to start automatically but is currently ' + $ServiceState + '.'
        if (-not $EventHistoryComplete -and -not [string]::IsNullOrWhiteSpace($EventHistoryNote)) { $summary += ' ' + $EventHistoryNote }
        return [pscustomobject]@{ Status = 'warn'; Summary = $summary }
    }
    if (-not $EventHistoryComplete) {
        $summary = $ServiceName + ' has no matching unexpected-exit events in retained records; its 30-day stability history cannot be verified. Current state=' + $ServiceState + '; start mode=' + $StartMode + '.'
        if (-not [string]::IsNullOrWhiteSpace($EventHistoryNote)) { $summary += ' ' + $EventHistoryNote }
        return [pscustomobject]@{ Status = 'unknown'; Summary = $summary }
    }
    return [pscustomobject]@{ Status = 'pass'; Summary = $ServiceName + ' has no unexpected service-exit events and its current state is ' + $ServiceState + '.' }
}

function Invoke-PCKnownServiceAudit {
    param([Parameter(Mandatory = $true)][string]$RunDirectory)

    $serviceNames = @('BFE', 'MpsSvc', 'nsi', 'BITS', 'Everything')
    $serviceFilter = ($serviceNames | ForEach-Object { "Name='$_'" }) -join ' OR '
    $services = @()
    $serviceQueryError = $null
    try { $services = @(Get-CimInstance -ClassName Win32_Service -Filter $serviceFilter -ErrorAction Stop) }
    catch { $serviceQueryError = $_.Exception.Message }
    $serviceMap = @{}
    foreach ($service in @($services)) { $serviceMap[[string]$service.Name] = $service }
    $serviceSnapshots = @($services | Sort-Object Name | ForEach-Object {
        [pscustomobject]@{ Name = $_.Name; State = $_.State; StartMode = $_.StartMode; ExitCode = $_.ExitCode; ServiceSpecificExitCode = $_.ServiceSpecificExitCode; ProcessId = $_.ProcessId }
    })
    $mpsdrvEvidence = @()
    $mpsdrvQueryError = $null
    try {
        $mpsdrvEvidence = @(Get-CimInstance -ClassName Win32_SystemDriver -Filter "Name='mpsdrv'" -ErrorAction Stop | Select-Object Name, PathName, State, StartMode, Status, ExitCode)
    }
    catch { $mpsdrvQueryError = $_.Exception.Message }
    $mpsdrvIntegrityWindowStart = (Get-Date).AddDays(-30)
    $mpsdrvIntegrityHistory = Get-PCEventLogClearState -Audit $script:EventLogClearAudit -LogName 'Microsoft-Windows-CodeIntegrity/Operational' -WindowStartLocal $mpsdrvIntegrityWindowStart
    $mpsdrvIntegrityEvents = @()
    $mpsdrvIntegrityQueryError = $null
    try {
        $codeIntegrityCandidates = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-CodeIntegrity/Operational'; Id = 3004; StartTime = $mpsdrvIntegrityWindowStart } -ErrorAction Stop)
        $mpsdrvIntegrityEvents = @($codeIntegrityCandidates | Where-Object { [string]$_.Message -match '(?i)mpsdrv\.sys' })
    }
    catch {
        $isNoMatchingEvents = ($_.FullyQualifiedErrorId -match 'NoMatchingEventsFound') -or ($_.Exception.Message -match '(?i)no events were found|no events found')
        if (-not $isNoMatchingEvents) { $mpsdrvIntegrityQueryError = Get-PCErrorSummary -ErrorRecord $_ }
    }
    $mpsdrvIntegritySamples = @($mpsdrvIntegrityEvents | Sort-Object TimeCreated -Descending | Select-Object -First 10 | ForEach-Object {
        $message = [string]$_.Message
        if ($message.Length -gt 800) { $message = $message.Substring(0, 800) }
        [pscustomobject]@{ TimeCreatedLocal = $_.TimeCreated.ToString('o'); EventId = $_.Id; Level = $_.LevelDisplayName; MessageExcerpt = $message }
    })

    $configuredFirewallProfiles = [System.Collections.Generic.List[object]]::new()
    $firewallRegistryErrors = [System.Collections.Generic.List[string]]::new()
    foreach ($profile in @('DomainProfile', 'StandardProfile', 'PublicProfile')) {
        $registryPath = 'SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\' + $profile
        $key = $null
        try {
            $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($registryPath, $false)
            if ($null -eq $key) {
                $firewallRegistryErrors.Add($profile + ' registry key is missing.')
                $configuredFirewallProfiles.Add([pscustomobject]@{ Name = $profile; EnableFirewall = $null; DefaultInboundAction = $null; DefaultOutboundAction = $null })
            }
            else {
                $configuredFirewallProfiles.Add([pscustomobject]@{
                    Name = $profile
                    EnableFirewall = $key.GetValue('EnableFirewall', $null)
                    DefaultInboundAction = $key.GetValue('DefaultInboundAction', $null)
                    DefaultOutboundAction = $key.GetValue('DefaultOutboundAction', $null)
                })
            }
        }
        catch { $firewallRegistryErrors.Add($profile + ': ' + $_.Exception.Message) }
        finally { if ($null -ne $key) { $key.Dispose() } }
    }
    $effectiveFirewallProfiles = @()
    $profileQueryError = $null
    try { $effectiveFirewallProfiles = @(Get-NetFirewallProfile -ErrorAction Stop | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction) }
    catch { $profileQueryError = Get-PCErrorSummary -ErrorRecord $_ }
    $firewallService = $serviceMap['MpsSvc']
    $baseFilteringService = $serviceMap['BFE']
    $networkStoreInterfaceService = $serviceMap['nsi']
    $firewallServiceState = if ($null -ne $firewallService) { [string]$firewallService.State } else { '' }
    $firewallStartMode = if ($null -ne $firewallService) { [string]$firewallService.StartMode } else { '' }
    $baseFilteringEngineState = if ($null -ne $baseFilteringService) { [string]$baseFilteringService.State } else { '' }
    $networkStoreInterfaceState = if ($null -ne $networkStoreInterfaceService) { [string]$networkStoreInterfaceService.State } else { '' }
    $firewallVerdict = Get-PCFirewallStateVerdict -FirewallServiceState $firewallServiceState -FirewallStartMode $firewallStartMode -BaseFilteringEngineState $baseFilteringEngineState -NetworkStoreInterfaceState $networkStoreInterfaceState -MpsdrvIntegrityFailureCount $mpsdrvIntegrityEvents.Count -MpsdrvIntegrityQueryError $mpsdrvIntegrityQueryError -MpsdrvIntegrityHistoryComplete $mpsdrvIntegrityHistory.HistoryComplete -MpsdrvIntegrityHistoryNote $mpsdrvIntegrityHistory.Summary -EffectiveProfiles $effectiveFirewallProfiles -ProfileQueryError $profileQueryError -ServiceQueryError $serviceQueryError
    if ($firewallRegistryErrors.Count -gt 0) { $firewallVerdict.Summary += ' Firewall registry query issues: ' + ($firewallRegistryErrors -join ' | ') }

    $bitsJobs = [System.Collections.Generic.List[object]]::new()
    $bitsQueryErrors = [System.Collections.Generic.List[string]]::new()
    try {
        foreach ($job in @(Get-BitsTransfer -AllUsers -ErrorAction Stop)) {
            $internalErrorCode = $null
            $internalErrorHex = $null
            try {
                $internalErrorCode = [int]$job.InternalErrorCode
                $internalErrorUnsigned = [BitConverter]::ToUInt32([BitConverter]::GetBytes($internalErrorCode), 0)
                $internalErrorHex = '0x' + $internalErrorUnsigned.ToString('X8')
            }
            catch { }
            $bitsJobs.Add([pscustomobject]@{
                JobId = [string]$job.JobId
                JobState = [string]$job.JobState
                OwnerAccount = [string]$job.OwnerAccount
                TransferType = [string]$job.TransferType
                TransientErrorCount = $job.TransientErrorCount
                InternalErrorCode = $internalErrorCode
                InternalErrorCodeHex = $internalErrorHex
                ErrorDescription = [string]$job.ErrorDescription
            })
        }
    }
    catch { $bitsQueryErrors.Add('Get-BitsTransfer: ' + $_.Exception.Message) }

    $bitsWindowStart = (Get-Date).AddHours(-5)
    $bitsHistory = Get-PCEventLogClearState -Audit $script:EventLogClearAudit -LogName 'Microsoft-Windows-Bits-Client/Operational' -WindowStartLocal $bitsWindowStart
    $bitsEvents = @()
    $bitsEventQueryError = $null
    try { $bitsEvents = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Bits-Client/Operational'; Id = 61; StartTime = $bitsWindowStart } -ErrorAction Stop) }
    catch {
        $isNoMatchingEvents = ($_.FullyQualifiedErrorId -match 'NoMatchingEventsFound') -or ($_.Exception.Message -match '(?i)no events were found|no events found')
        if (-not $isNoMatchingEvents) { $bitsEventQueryError = $_.Exception.Message; $bitsQueryErrors.Add('BITS Event 61 query: ' + $_.Exception.Message) }
    }
    $bitsEventSamples = @($bitsEvents | Sort-Object TimeCreated -Descending | Select-Object -First 10 | ForEach-Object {
        $message = [string]$_.Message
        if ($message.Length -gt 600) { $message = $message.Substring(0, 600) }
        [pscustomobject]@{ TimeCreatedLocal = $_.TimeCreated.ToString('o'); EventId = $_.Id; Level = $_.LevelDisplayName; MessageExcerpt = $message }
    })
    $bitsVerdict = Get-PCBitsAuditVerdict -Jobs $bitsJobs.ToArray() -Event61Count $bitsEvents.Count -QueryErrors $bitsQueryErrors.ToArray() -EventHistoryComplete $bitsHistory.HistoryComplete -EventHistoryNote $bitsHistory.Summary

    $everythingExitEvents = @()
    $everythingQueryError = $null
    $everythingWindowStart = (Get-Date).AddDays(-30)
    $everythingHistory = Get-PCEventLogClearState -Audit $script:EventLogClearAudit -LogName 'System' -WindowStartLocal $everythingWindowStart
    try {
        $serviceExitEvents = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Service Control Manager'; Id = @(7031, 7034); StartTime = $everythingWindowStart } -ErrorAction Stop)
        $everythingExitEvents = @($serviceExitEvents | Where-Object { $_.Message -match '(?i)\bEverything\b' } | ForEach-Object {
            $message = [string]$_.Message
            if ($message.Length -gt 1200) { $message = $message.Substring(0, 1200) }
            [pscustomobject]@{ TimeCreatedLocal = $_.TimeCreated.ToString('o'); EventId = $_.Id; MessageExcerpt = $message }
        })
    }
    catch {
        $isNoMatchingEvents = ($_.FullyQualifiedErrorId -match 'NoMatchingEventsFound') -or ($_.Exception.Message -match '(?i)no events were found|no events found')
        if (-not $isNoMatchingEvents) { $everythingQueryError = $_.Exception.Message }
    }
    $everythingService = $serviceMap['Everything']
    $everythingState = if ($null -ne $everythingService) { [string]$everythingService.State } else { '' }
    $everythingStartMode = if ($null -ne $everythingService) { [string]$everythingService.StartMode } else { '' }
    $everythingVerdict = Get-PCServiceStabilityVerdict -ServiceName 'Everything' -ServiceState $everythingState -StartMode $everythingStartMode -UnexpectedExitCount $everythingExitEvents.Count -QueryError $everythingQueryError -EventHistoryComplete $everythingHistory.HistoryComplete -EventHistoryNote $everythingHistory.Summary

    $evidencePath = [System.IO.Path]::Combine($RunDirectory, 'service-reliability-current.txt')
    $evidenceLines = [System.Collections.Generic.List[string]]::new()
    $evidenceLines.Add('CapturedLocal=' + (Get-Date).ToString('o'))
    $evidenceLines.Add('ServiceQueryError=' + [string]$serviceQueryError)
    foreach ($item in $serviceSnapshots) { $evidenceLines.Add('Service=' + (ConvertTo-Json -InputObject $item -Compress)) }
    $evidenceLines.Add('MpsdrvSystemDriver=' + (ConvertTo-Json -InputObject $mpsdrvEvidence -Compress))
    $evidenceLines.Add('MpsdrvQueryError=' + [string]$mpsdrvQueryError)
    $evidenceLines.Add('MpsdrvCodeIntegrityWindowStartLocal=' + $mpsdrvIntegrityWindowStart.ToString('o'))
    $evidenceLines.Add('MpsdrvCodeIntegrityEventCount=' + $mpsdrvIntegrityEvents.Count)
    $evidenceLines.Add('MpsdrvCodeIntegrityQueryError=' + [string]$mpsdrvIntegrityQueryError)
    $evidenceLines.Add('MpsdrvCodeIntegrityHistory=' + (ConvertTo-Json -InputObject $mpsdrvIntegrityHistory -Depth 6 -Compress))
    foreach ($event in $mpsdrvIntegritySamples) { $evidenceLines.Add('MpsdrvCodeIntegrityEvent=' + (ConvertTo-Json -InputObject $event -Compress)) }
    $evidenceLines.Add('FirewallRegistryProfiles=' + (ConvertTo-Json -InputObject $configuredFirewallProfiles.ToArray() -Compress))
    $evidenceLines.Add('FirewallProfileQueryError=' + [string]$profileQueryError)
    $evidenceLines.Add('FirewallRegistryErrors=' + ($firewallRegistryErrors -join ' | '))
    $evidenceLines.Add('EffectiveFirewallProfiles=' + (ConvertTo-Json -InputObject $effectiveFirewallProfiles -Compress))
    foreach ($job in $bitsJobs) { $evidenceLines.Add('BITSJob=' + (ConvertTo-Json -InputObject $job -Compress)) }
    $evidenceLines.Add('BITSJobQueryErrors=' + ($bitsQueryErrors -join ' | '))
    $evidenceLines.Add('BITS61WindowStartLocal=' + $bitsWindowStart.ToString('o'))
    $evidenceLines.Add('BITS61EventCount=' + $bitsEvents.Count)
    $evidenceLines.Add('BITS61QueryError=' + [string]$bitsEventQueryError)
    $evidenceLines.Add('BITS61History=' + (ConvertTo-Json -InputObject $bitsHistory -Depth 6 -Compress))
    foreach ($sample in $bitsEventSamples) { $evidenceLines.Add('BITS61Sample=' + (ConvertTo-Json -InputObject $sample -Compress)) }
    $evidenceLines.Add('EverythingUnexpectedExitCount=' + $everythingExitEvents.Count)
    $evidenceLines.Add('EverythingExitQueryError=' + [string]$everythingQueryError)
    $evidenceLines.Add('EverythingHistory=' + (ConvertTo-Json -InputObject $everythingHistory -Depth 6 -Compress))
    foreach ($event in $everythingExitEvents) { $evidenceLines.Add('EverythingExit=' + (ConvertTo-Json -InputObject $event -Compress)) }
    $evidenceWritten = $true
    $evidenceWriteError = $null
    try { [System.IO.File]::WriteAllLines($evidencePath, $evidenceLines.ToArray(), [System.Text.UTF8Encoding]::new($true)) }
    catch { $evidenceWritten = $false; $evidenceWriteError = $_.Exception.Message }

    $firewallEvidence = [pscustomobject]@{
        Services = $serviceSnapshots | Where-Object { $_.Name -in @('BFE', 'MpsSvc', 'nsi') }
        MpsdrvDriver = $mpsdrvEvidence
        MpsdrvQueryError = $mpsdrvQueryError
        MpsdrvIntegrityWindowStartLocal = $mpsdrvIntegrityWindowStart.ToString('o')
        MpsdrvIntegrityFailureCount = $mpsdrvIntegrityEvents.Count
        MpsdrvIntegrityEvents = $mpsdrvIntegritySamples
        MpsdrvIntegrityQueryError = $mpsdrvIntegrityQueryError
        MpsdrvIntegrityHistory = $mpsdrvIntegrityHistory
        ConfiguredProfiles = $configuredFirewallProfiles.ToArray()
        EffectiveProfiles = $effectiveFirewallProfiles
        ProfileQueryError = $profileQueryError
        RegistryErrors = $firewallRegistryErrors.ToArray()
        ServiceQueryError = $serviceQueryError
        EvidenceFile = $evidencePath
    }
    $bitsEvidence = [pscustomobject]@{
        JobCount = $bitsJobs.Count
        FailedJobs = @($bitsJobs.ToArray() | Where-Object { $_.JobState -in @('Error', 'TransientError') })
        Jobs = $bitsJobs.ToArray()
        Event61WindowStartLocal = $bitsWindowStart.ToString('o')
        Event61Count = $bitsEvents.Count
        Event61Samples = $bitsEventSamples
        QueryErrors = $bitsQueryErrors.ToArray()
        EventHistory = $bitsHistory
        EvidenceFile = $evidencePath
    }
    $everythingEvidence = [pscustomobject]@{
        Service = $serviceSnapshots | Where-Object { $_.Name -eq 'Everything' }
        UnexpectedExitCount = $everythingExitEvents.Count
        Events = $everythingExitEvents
        QueryError = $everythingQueryError
        EventHistory = $everythingHistory
        EvidenceFile = $evidencePath
    }
    if (-not $evidenceWritten) {
        if ($firewallVerdict.Status -eq 'pass') { $firewallVerdict.Status = 'unknown' }
        if ($bitsVerdict.Status -eq 'pass') { $bitsVerdict.Status = 'unknown' }
        if ($everythingVerdict.Status -eq 'pass') { $everythingVerdict.Status = 'unknown' }
        $firewallVerdict.Summary += ' Evidence file could not be written: ' + $evidenceWriteError
        $bitsVerdict.Summary += ' Evidence file could not be written: ' + $evidenceWriteError
        $everythingVerdict.Summary += ' Evidence file could not be written: ' + $evidenceWriteError
    }
    Add-PCCheck -Name 'FirewallAvailability' -Status $firewallVerdict.Status -Summary $firewallVerdict.Summary -Evidence $firewallEvidence
    Add-PCCheck -Name 'BITSJobsAndEvents5h' -Status $bitsVerdict.Status -Summary $bitsVerdict.Summary -Evidence $bitsEvidence
    Add-PCCheck -Name 'EverythingStability30d' -Status $everythingVerdict.Status -Summary $everythingVerdict.Summary -Evidence $everythingEvidence
}

function Invoke-PCStorageAudit {
    param([Parameter(Mandatory = $true)][string]$RunDirectory)

    $windowEnd = Get-Date
    $windowStart = $windowEnd.AddDays(-30)
    $systemEventHistory = Get-PCEventLogClearState -Audit $script:EventLogClearAudit -LogName 'System' -WindowStartLocal $windowStart
    $eventIds = @(7, 11, 15, 51, 55, 98, 129, 140, 153, 154, 157)
    $providerNames = @('disk', 'Ntfs', 'Microsoft-Windows-Ntfs', 'stor*', 'Microsoft-Windows-Stor*', 'Microsoft-Windows-Storage*', 'partmgr', 'volmgr', 'volsnap')
    $eventRecords = @()
    $eventQueryError = $null
    try {
        $eventRecords = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = $providerNames; Id = $eventIds; StartTime = $windowStart } -ErrorAction Stop)
    }
    catch {
        $isNoMatchingEvents = ($_.FullyQualifiedErrorId -match 'NoMatchingEventsFound') -or ($_.Exception.Message -match '(?i)no events were found|no events found')
        if (-not $isNoMatchingEvents) { $eventQueryError = $_.Exception.Message }
    }

    $diskMap = @()
    $mappingError = $null
    try {
        $diskDrives = @(Get-CimInstance -ClassName Win32_DiskDrive -ErrorAction Stop)
        $partitionAssociations = @(Get-CimInstance -ClassName Win32_LogicalDiskToPartition -ErrorAction Stop)
        $logicalDisks = @(Get-CimInstance -ClassName Win32_LogicalDisk -ErrorAction Stop)
        $diskMap = @(Get-PCStorageDiskMap -DiskDrives $diskDrives -PartitionAssociations $partitionAssociations -LogicalDisks $logicalDisks)
        if ($diskMap.Count -eq 0) { $mappingError = 'Win32_DiskDrive returned no devices.' }
    }
    catch {
        $mappingError = $_.Exception.Message
        $diskMap = @()
    }

    $diskMapByNumber = @{}
    $letterToDiskNumbers = @{}
    $volumeByLetter = @{}
    foreach ($mappedDisk in @($diskMap)) {
        $diskMapByNumber[[int]$mappedDisk.Number] = $mappedDisk
        foreach ($volume in @($mappedDisk.Volumes)) {
            if ($null -ne $volume.DriveLetter) { $volumeByLetter[[string]$volume.DriveLetter] = $volume }
        }
        foreach ($letter in @($mappedDisk.DriveLetters)) {
            if (-not $letterToDiskNumbers.ContainsKey([string]$letter)) { $letterToDiskNumbers[[string]$letter] = [System.Collections.Generic.List[int]]::new() }
            if (-not $letterToDiskNumbers[[string]$letter].Contains([int]$mappedDisk.Number)) { $letterToDiskNumbers[[string]$letter].Add([int]$mappedDisk.Number) }
        }
    }

    $evidencePath = [System.IO.Path]::Combine($RunDirectory, 'storage-events-30d.txt')
    $evidenceLines = [System.Collections.Generic.List[string]]::new()
    $evidenceLines.Add('WindowStartLocal=' + $windowStart.ToString('o'))
    $evidenceLines.Add('WindowEndLocal=' + $windowEnd.ToString('o'))
    $evidenceLines.Add('EventIds=' + ($eventIds -join ','))
    $evidenceLines.Add('ProviderFilters=' + ($providerNames -join ','))
    $evidenceLines.Add('EventQueryError=' + [string]$eventQueryError)
    $evidenceLines.Add('DeviceMappingError=' + [string]$mappingError)
    $evidenceLines.Add('=== Disk and volume mapping ===')
    foreach ($mappedDisk in @($diskMap)) {
        $volumeText = @($mappedDisk.Volumes | ForEach-Object { [string]$_.DriveLetter + ' (' + [string]$_.FileSystem + ')' }) -join ', '
        $evidenceLines.Add(('Disk={0}; Model={1}; DeviceID={2}; SizeGiB={3}; Status={4}; Volumes={5}' -f $mappedDisk.Number, $mappedDisk.Model, $mappedDisk.DeviceId, $mappedDisk.SizeGiB, $mappedDisk.Status, $volumeText))
    }

    $eventSummaries = [System.Collections.Generic.List[object]]::new()
    $warningEventCount = 0
    foreach ($eventRecord in @($eventRecords | Sort-Object TimeCreated)) {
        $providerName = [string]$eventRecord.ProviderName
        $eventId = [int]$eventRecord.Id
        $message = ''
        try { $message = [string]$eventRecord.Message } catch { $message = '[Event message could not be rendered: ' + $_.Exception.Message + ']' }
        $properties = @()
        try { $properties = @($eventRecord.Properties) } catch { }
        $verdict = Get-PCStorageEventVerdict -ProviderName $providerName -EventId $eventId -Message $message
        if ($verdict.Status -eq 'warn') { $warningEventCount++ }
        $diskNumber = Get-PCDiskNumberFromStorageEvent -Message $message -Properties $properties
        $mentionedLetters = @(Get-PCStorageDriveLettersFromEvent -Message $message -Properties $properties)
        $matchedDiskNumbers = [System.Collections.Generic.List[int]]::new()
        if ($null -ne $diskNumber -and $diskMapByNumber.ContainsKey([int]$diskNumber)) { $matchedDiskNumbers.Add([int]$diskNumber) }
        foreach ($letter in $mentionedLetters) {
            if ($letterToDiskNumbers.ContainsKey([string]$letter)) {
                foreach ($number in $letterToDiskNumbers[[string]$letter]) {
                    if (-not $matchedDiskNumbers.Contains([int]$number)) { $matchedDiskNumbers.Add([int]$number) }
                }
            }
        }
        $matchedDevices = @($matchedDiskNumbers | ForEach-Object {
            $mappedDisk = $diskMapByNumber[[int]$_]
            [pscustomobject]@{
                Number = $mappedDisk.Number
                Model = $mappedDisk.Model
                DeviceId = $mappedDisk.DeviceId
                SizeGiB = $mappedDisk.SizeGiB
                Status = $mappedDisk.Status
                DriveLetters = @($mappedDisk.DriveLetters)
                Volumes = @($mappedDisk.Volumes)
            }
        })
        $eventLetters = @($matchedDevices | ForEach-Object { $_.DriveLetters } | Sort-Object -Unique)
        if ($eventLetters.Count -eq 0) { $eventLetters = $mentionedLetters }
        $mappedVolumes = @($eventLetters | ForEach-Object {
            if ($volumeByLetter.ContainsKey([string]$_)) { $volumeByLetter[[string]$_] }
            else { [pscustomobject]@{ DriveLetter = [string]$_; FileSystem = $null } }
        })
        $messageExcerpt = $message
        if ($messageExcerpt.Length -gt 1200) { $messageExcerpt = $messageExcerpt.Substring(0, 1200) }
        $timeLocal = if ($null -ne $eventRecord.TimeCreated) { $eventRecord.TimeCreated.ToString('o') } else { $null }
        $timeUtc = if ($null -ne $eventRecord.TimeCreated) { $eventRecord.TimeCreated.ToUniversalTime().ToString('o') } else { $null }
        $summary = [pscustomobject]@{
            TimeCreatedLocal = $timeLocal
            TimeCreatedUtc = $timeUtc
            ProviderName = $providerName
            EventId = $eventId
            Level = [string]$eventRecord.LevelDisplayName
            Status = $verdict.Status
            Verdict = $verdict.Summary
            DiskNumberFromEvent = $diskNumber
            MatchedDisks = $matchedDevices
            MentionedDriveLetters = $mentionedLetters
            MappedVolumes = $mappedVolumes
            MessageExcerpt = $messageExcerpt
        }
        $eventSummaries.Add($summary)
        $evidenceLines.Add('=== Event ' + $eventId + ' provider=' + $providerName + ' status=' + $verdict.Status + ' time=' + [string]$timeLocal + ' disks=' + (@($matchedDiskNumbers) -join ',') + ' volumes=' + ($eventLetters -join ',') + ' ===')
        try { $evidenceLines.Add([string]$eventRecord.ToXml()) } catch { $evidenceLines.Add('EventXmlError=' + $_.Exception.Message) }
        $evidenceLines.Add('RenderedMessage:')
        $evidenceLines.Add($message)
    }

    $reliabilityRecords = [System.Collections.Generic.List[object]]::new()
    $diskQueryError = $null
    $storageDisks = @()
    try {
        $storageDisks = @(Get-Disk -ErrorAction Stop)
        if ($storageDisks.Count -eq 0) { $diskQueryError = 'Get-Disk returned no devices.' }
    }
    catch {
        $diskQueryError = Get-PCErrorSummary -ErrorRecord $_
    }
    $evidenceLines.Add('=== Storage reliability counters ===')
    $evidenceLines.Add('GetDiskQueryError=' + [string]$diskQueryError)
    foreach ($disk in @($storageDisks)) {
        $diskNumber = if ($null -ne $disk.Number) { [int]$disk.Number } else { -1 }
        $counter = $null
        $counterQueryError = $null
        try {
            $counterResults = @(Get-StorageReliabilityCounter -Disk $disk -ErrorAction Stop)
            if ($counterResults.Count -gt 0) { $counter = $counterResults[0] }
        }
        catch {
            $counterQueryError = $_.Exception.Message
        }
        $operationalStatus = @($disk.OperationalStatus | ForEach-Object { [string]$_ })
        $verdict = Get-PCStorageReliabilityVerdict -HealthStatus ([string]$disk.HealthStatus) -OperationalStatus $operationalStatus -Counters $counter
        $counterSnapshot = Get-PCStorageCounterSnapshot -Counters $counter
        $mappedDisk = if ($diskMapByNumber.ContainsKey($diskNumber)) { $diskMapByNumber[$diskNumber] } else { $null }
        $model = if ($null -ne $mappedDisk -and -not [string]::IsNullOrWhiteSpace([string]$mappedDisk.Model)) { [string]$mappedDisk.Model } else { [string]$disk.FriendlyName }
        $record = [pscustomobject]@{
            DiskNumber = $diskNumber
            Model = $model
            FriendlyName = [string]$disk.FriendlyName
            SizeBytes = $disk.Size
            BusType = [string]$disk.BusType
            HealthStatus = [string]$disk.HealthStatus
            OperationalStatus = $operationalStatus
            DriveLetters = if ($null -ne $mappedDisk) { @($mappedDisk.DriveLetters) } else { @() }
            Status = $verdict.Status
            Summary = $verdict.Summary
            CounterQueryError = $counterQueryError
            CounterValues = $verdict.CounterValues
            RawCounters = $counterSnapshot
        }
        $reliabilityRecords.Add($record)
        $evidenceLines.Add((ConvertTo-Json -InputObject $record -Depth 7 -Compress))
    }
    if ($diskQueryError) {
        $evidenceLines.Add('StorageReliabilityUnavailable=' + $diskQueryError)
        $reliabilityRecords.Add([pscustomobject]@{ DiskNumber = $null; Status = 'unknown'; Summary = 'Could not query Get-Disk or no disk devices were returned.'; Error = $diskQueryError })
    }

    $evidenceWritten = $true
    $evidenceWriteError = $null
    try {
        [System.IO.File]::WriteAllLines($evidencePath, $evidenceLines.ToArray(), [System.Text.UTF8Encoding]::new($true))
    }
    catch {
        $evidenceWritten = $false
        $evidenceWriteError = $_.Exception.Message
    }

    if ($mappingError) {
        Add-PCCheck -Name 'StorageDeviceMapping' -Status 'unknown' -Summary ('Could not map physical disks to mounted logical volumes: ' + $mappingError) -Evidence ([pscustomobject]@{ EvidenceFile = $evidencePath })
    }
    else {
        Add-PCCheck -Name 'StorageDeviceMapping' -Status 'pass' -Summary ('Mapped ' + $diskMap.Count + ' physical disk(s) to available drive-letter/filesystem associations.') -Evidence ([pscustomobject]@{ Disks = $diskMap; EvidenceFile = $evidencePath })
    }

    $eventGroups = @($eventSummaries | Group-Object -Property { '{0}/{1}/{2}' -f $_.ProviderName, $_.EventId, $_.Status } | Sort-Object Name | ForEach-Object {
        $first = $_.Group[0]
        [pscustomobject]@{ ProviderName = $first.ProviderName; EventId = $first.EventId; Status = $first.Status; Count = $_.Count }
    })
    $eventVerdict = Get-PCStorageEventsHistoryVerdict -EventCount $eventSummaries.Count -WarningEventCount $warningEventCount -EventQueryError ([string]$eventQueryError) -EvidenceWritten $evidenceWritten -EvidenceWriteError ([string]$evidenceWriteError) -HistoryState $systemEventHistory
    $eventStatus = $eventVerdict.Status
    $eventSummary = $eventVerdict.Summary
    $eventEvidence = [pscustomobject]@{
        WindowStartLocal = $windowStart.ToString('o')
        WindowEndLocal = $windowEnd.ToString('o')
        EventCount = $eventSummaries.Count
        WarningEventCount = $warningEventCount
        CountsByProviderEventIdStatus = $eventGroups
        Events = @($eventSummaries | Select-Object -First 250)
        EventsOmittedFromReport = [Math]::Max(0, $eventSummaries.Count - 250)
        EventHistory = $systemEventHistory
        QueryError = $eventQueryError
        EvidenceWriteError = $evidenceWriteError
        EvidenceFile = $evidencePath
    }
    Add-PCCheck -Name 'StorageEvents30d' -Status $eventStatus -Summary $eventSummary -Evidence $eventEvidence

    foreach ($record in @($reliabilityRecords)) {
        $status = [string]$record.Status
        $summary = [string]$record.Summary
        if ($record.PSObject.Properties['CounterQueryError'] -and $record.CounterQueryError) { $summary += ' Counter query error: ' + $record.CounterQueryError }
        if (-not $evidenceWritten -and $status -eq 'pass') { $status = 'unknown'; $summary += ' Counter evidence file could not be written.' }
        $checkName = if ($null -ne $record.DiskNumber) { 'StorageReliabilityDisk' + $record.DiskNumber } else { 'StorageReliability' }
        Add-PCCheck -Name $checkName -Status $status -Summary $summary -Evidence ([pscustomobject]@{ Disk = $record; EvidenceFile = $evidencePath })
    }
}

function Test-PCAdministrator {
    try {
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
        return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        return $false
    }
}

function Get-PCPendingRenameAssessment {
    param(
        [string[]]$Entries,
        [string[]]$TemporaryRoots
    )
    $entryArray = @($Entries)
    $unsafeReasons = [System.Collections.Generic.List[string]]::new()
    $outsideTempDeletionCount = 0
    $replacementOrMoveCount = 0
    $unreviewedPrefixCount = 0
    $invalidPathCount = 0
    $unmatchedOperationCount = 0
    if ($entryArray.Count -eq 0) {
        return [pscustomobject]@{
            EntryCount = 0
            PairCount = 0
            OutsideTempDeletionCount = 0
            ReplacementOrMoveCount = 0
            UnreviewedPrefixCount = 0
            InvalidPathCount = 0
            UnmatchedOperationCount = 0
            CleanupOnly = $false
            BlocksComponentServicing = $false
            UnsafeReasons = @()
        }
    }

    $separator = [string][System.IO.Path]::DirectorySeparatorChar
    $tempRoots = [System.Collections.Generic.List[string]]::new()
    foreach ($candidateRoot in @($TemporaryRoots)) {
        if ([string]::IsNullOrWhiteSpace($candidateRoot)) { continue }
        try {
            $fullRoot = [System.IO.Path]::GetFullPath($candidateRoot)
            if (-not $fullRoot.EndsWith($separator)) { $fullRoot += $separator }
            $tempRoots.Add($fullRoot)
        }
        catch {
            $unsafeReasons.Add('A current-user Temp root could not be normalized.')
        }
    }
    if ($tempRoots.Count -eq 0) { $unsafeReasons.Add('No current-user Temp root could be verified.') }

    for ($i = 0; $i -lt $entryArray.Count; $i += 2) {
        if (($i + 1) -ge $entryArray.Count) {
            $unmatchedOperationCount++
            $unsafeReasons.Add('An unmatched pending file operation was found.')
            break
        }
        $source = [string]$entryArray[$i]
        $destination = [string]$entryArray[$i + 1]
        $operationPrefix = 'none'
        $prefixMatch = [System.Text.RegularExpressions.Regex]::Match($source, '^\*(?<flag>\d+)')
        if ($prefixMatch.Success) {
            $operationPrefix = $prefixMatch.Groups['flag'].Value
            $source = $source.Substring($prefixMatch.Length)
            if ($operationPrefix -ne '1') {
                $unreviewedPrefixCount++
                $unsafeReasons.Add('A pending operation uses the unreviewed *' + $operationPrefix + ' prefix.')
            }
        }
        if ($source.StartsWith('\??\', [System.StringComparison]::OrdinalIgnoreCase)) { $source = $source.Substring(4) }
        $temporaryDeletion = $false
        $pathResolved = $false
        $underTempRoot = $false
        try {
            $fullSource = [System.IO.Path]::GetFullPath($source)
            $pathResolved = $true
            foreach ($tempRoot in $tempRoots) {
                if ($fullSource.StartsWith($tempRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
                    $underTempRoot = $true
                    break
                }
            }
        }
        catch {
            $pathResolved = $false
        }
        $destinationIsBlank = [string]::IsNullOrWhiteSpace($destination)
        if (-not $destinationIsBlank) {
            $replacementOrMoveCount++
            $unsafeReasons.Add('A pending operation is a replacement or move, not a deletion.')
        }
        elseif (-not $pathResolved) {
            $invalidPathCount++
            $unsafeReasons.Add('A pending deletion path could not be normalized.')
        }
        elseif (-not $underTempRoot) {
            $outsideTempDeletionCount++
            $unsafeReasons.Add('A pending deletion is outside verified current-user Temp roots.')
        }
        elseif ($operationPrefix -eq '1' -or $operationPrefix -eq 'none') {
            $temporaryDeletion = $true
        }
    }

    return [pscustomobject]@{
        EntryCount = $entryArray.Count
        PairCount = [int][Math]::Ceiling($entryArray.Count / 2.0)
        OutsideTempDeletionCount = $outsideTempDeletionCount
        ReplacementOrMoveCount = $replacementOrMoveCount
        UnreviewedPrefixCount = $unreviewedPrefixCount
        InvalidPathCount = $invalidPathCount
        UnmatchedOperationCount = $unmatchedOperationCount
        CleanupOnly = ($entryArray.Count -gt 0 -and $unsafeReasons.Count -eq 0)
        BlocksComponentServicing = ($unsafeReasons.Count -gt 0)
        UnsafeReasons = @($unsafeReasons.ToArray())
    }
}

function Get-PCRebootState {
    $markers = [System.Collections.Generic.List[string]]::new()
    $blockingMarkers = [System.Collections.Generic.List[string]]::new()
    $pendingRenameAssessment = $null
    $pendingRenameEntries = @()
    $keyPaths = @(
        'SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
        'SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootInProgress',
        'SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
    )
    foreach ($path in $keyPaths) {
        $key = $null
        try {
            $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($path, $false)
            if ($null -ne $key) {
                $markers.Add($path)
                $blockingMarkers.Add($path)
            }
        }
        finally {
            if ($null -ne $key) { $key.Dispose() }
        }
    }

    $sessionManager = $null
    try {
        $sessionManager = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SYSTEM\CurrentControlSet\Control\Session Manager', $false)
        if ($null -ne $sessionManager) {
            $pending = $sessionManager.GetValue('PendingFileRenameOperations', $null)
            if ($null -ne $pending -and @($pending).Count -gt 0) {
                $pendingRenameEntries = @($pending)
                $temporaryRoots = @([System.IO.Path]::GetTempPath())
                if (-not [string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
                    $temporaryRoots += [System.IO.Path]::Combine($env:LOCALAPPDATA, 'Temp')
                }
                $renameAssessment = Get-PCPendingRenameAssessment -Entries @($pending) -TemporaryRoots $temporaryRoots
                if ($renameAssessment.CleanupOnly) {
                    $markers.Add('PendingFileRenameOperations cleanup-only pairs=' + $renameAssessment.PairCount)
                }
                else {
                    $markers.Add(('PendingFileRenameOperations blocks servicing; entries={0}; pairs={1}; outsideTempDeletes={2}; movesOrReplacements={3}; unreviewedPrefixes={4}; invalidPaths={5}; unmatched={6}' -f $renameAssessment.EntryCount, $renameAssessment.PairCount, $renameAssessment.OutsideTempDeletionCount, $renameAssessment.ReplacementOrMoveCount, $renameAssessment.UnreviewedPrefixCount, $renameAssessment.InvalidPathCount, $renameAssessment.UnmatchedOperationCount))
                    $blockingMarkers.Add('PendingFileRenameOperations contains a non-Temp, replacement/move, invalid-path, unmatched, or unreviewed-prefix operation')
                }
                $pendingRenameAssessment = $renameAssessment
            }
        }
    }
    finally {
        if ($null -ne $sessionManager) { $sessionManager.Dispose() }
    }
    return [pscustomobject]@{
        Detected = ($markers.Count -gt 0)
        BlocksComponentServicing = ($blockingMarkers.Count -gt 0)
        Markers = @($markers.ToArray())
        BlockingReasons = @($blockingMarkers.ToArray())
        PendingFileRenameAssessment = $pendingRenameAssessment
        PendingFileRenameEntries = $pendingRenameEntries
    }
}

function Get-PCServicingProcesses {
    $knownNames = @('dism', 'sfc', 'tiworker', 'trustedinstaller')
    $found = [System.Collections.Generic.List[object]]::new()
    foreach ($process in [System.Diagnostics.Process]::GetProcesses()) {
        try {
            if ($knownNames -contains $process.ProcessName.ToLowerInvariant()) {
                $found.Add([pscustomobject]@{ Name = $process.ProcessName; Id = $process.Id })
            }
        }
        catch {
        }
        finally {
            $process.Dispose()
        }
    }
    return @($found.ToArray())
}

function Wait-PCServicingQuiet {
    param(
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds,
        [int]$RequiredQuietSeconds = $script:ServicingQuietSeconds
    )
    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    $current = @()
    $quietSince = $null
    while ($watch.Elapsed.TotalSeconds -lt $TimeoutSeconds) {
        $current = @(Get-PCServicingProcesses)
        if ($current.Count -eq 0) {
            if ($null -eq $quietSince) { $quietSince = $watch.Elapsed.TotalSeconds }
            if (($watch.Elapsed.TotalSeconds - $quietSince) -ge $RequiredQuietSeconds) {
                return [pscustomobject]@{ Quiet = $true; Processes = @(); WaitedSeconds = [int]$watch.Elapsed.TotalSeconds; QuietSeconds = $RequiredQuietSeconds }
            }
        }
        else {
            $quietSince = $null
        }
        if ($watch.Elapsed.TotalSeconds -ge $TimeoutSeconds) { break }
        Start-Sleep -Seconds 5
    }
    return [pscustomobject]@{
        Quiet = $false
        Processes = @($current)
        WaitedSeconds = [int]$watch.Elapsed.TotalSeconds
        QuietSeconds = 0
    }
}

function Get-PCCommandVerdict {
    param([string]$Kind, [string]$Text, [int]$ExitCode)
    switch ($Kind) {
        'DismCheckHealth' {
            if ($Text -match '(?i)No component store corruption detected|No component store corruption found') {
                if ($ExitCode -eq 0) { return [pscustomobject]@{ Status = 'pass'; Summary = 'DISM reports no component-store corruption.' } }
                return [pscustomobject]@{ Status = 'fail'; Summary = 'DISM printed a clean result but exited with code ' + $ExitCode + '.' }
            }
            if ($Text -match '(?i)component store is repairable|component store is not repairable') {
                return [pscustomobject]@{ Status = 'fail'; Summary = 'DISM reports component-store corruption.' }
            }
        }
        'DismScanHealth' {
            if ($Text -match '(?i)No component store corruption detected|No component store corruption found') {
                if ($ExitCode -eq 0) { return [pscustomobject]@{ Status = 'pass'; Summary = 'DISM scan reports no component-store corruption.' } }
                return [pscustomobject]@{ Status = 'fail'; Summary = 'DISM scan printed a clean result but exited with code ' + $ExitCode + '.' }
            }
            if ($Text -match '(?i)component store is repairable|component store is not repairable') {
                return [pscustomobject]@{ Status = 'fail'; Summary = 'DISM scan reports component-store corruption.' }
            }
        }
        'DismRestoreHealth' {
            if ($ExitCode -eq 0 -and $Text -match '(?i)The restore operation completed successfully') {
                return [pscustomobject]@{ Status = 'pass'; Summary = 'DISM RestoreHealth completed; a separate integrity check is still required.' }
            }
            return [pscustomobject]@{ Status = 'fail'; Summary = 'DISM RestoreHealth did not produce its expected success result.' }
        }
        'SfcVerifyOnly' {
            if ($Text -match '(?i)did not find any integrity violations') {
                if ($ExitCode -eq 0) { return [pscustomobject]@{ Status = 'pass'; Summary = 'SFC verify-only reports no protected-file integrity violations.' } }
                return [pscustomobject]@{ Status = 'fail'; Summary = 'SFC verify-only printed a clean result but exited with code ' + $ExitCode + '.' }
            }
            if ($Text -match '(?i)found integrity violations|unable to fix some|could not perform the requested operation') {
                return [pscustomobject]@{ Status = 'fail'; Summary = 'SFC verify-only reports a protected-file integrity problem.' }
            }
        }
        'SfcScanNow' {
            if ($Text -match '(?i)found corrupt files but was unable to fix some of them') {
                return [pscustomobject]@{ Status = 'fail'; Summary = 'SFC reports corrupt protected files remain unrepaired.' }
            }
            if ($Text -match '(?i)found corrupt files and successfully repaired them') {
                if ($ExitCode -ne 0) { return [pscustomobject]@{ Status = 'fail'; Summary = 'SFC reported repairs but exited with code ' + $ExitCode + '; verify-only is required and repair success is not assumed.' } }
                return [pscustomobject]@{ Status = 'warn'; Summary = 'SFC reports repairs; verify-only must still pass before claiming clean integrity.' }
            }
            if ($Text -match '(?i)did not find any integrity violations') {
                if ($ExitCode -eq 0) { return [pscustomobject]@{ Status = 'pass'; Summary = 'SFC reports no protected-file integrity violations.' } }
                return [pscustomobject]@{ Status = 'fail'; Summary = 'SFC printed a clean result but exited with code ' + $ExitCode + '.' }
            }
        }
    }
    if ($ExitCode -ne 0) {
        return [pscustomobject]@{ Status = 'fail'; Summary = 'Native command exited with code ' + $ExitCode + ' and no recognized clean result.' }
    }
    return [pscustomobject]@{ Status = 'unknown'; Summary = 'Exit code alone is insufficient; output did not match a recognized result.' }
}

function Get-PCRepairGate {
    param(
        [bool]$Confirmed,
        [bool]$Administrator,
        [bool]$PendingServicingReboot,
        [object[]]$ServicingProcesses
    )
    $reasons = [System.Collections.Generic.List[string]]::new()
    if (-not $Confirmed) { $reasons.Add('Explicit repair confirmation is missing.') }
    if (-not $Administrator) { $reasons.Add('The current process is not elevated.') }
    if ($PendingServicingReboot) { $reasons.Add('A Windows servicing or update reboot marker is present or unreadable.') }
    if (@($ServicingProcesses).Count -gt 0) { $reasons.Add('A servicing-related process is present.') }
    return [pscustomobject]@{ Open = ($reasons.Count -eq 0); Reasons = @($reasons.ToArray()) }
}

function Start-PCNativeCommandWorker {
    param(
        [Parameter(Mandatory = $true)][string]$Executable,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$StdoutPath,
        [Parameter(Mandatory = $true)][string]$StderrPath,
        [Parameter(Mandatory = $true)][string]$RunnerErrorPath,
        [Parameter(Mandatory = $true)][ValidateSet('Console', 'Unicode')][string]$StreamEncoding
    )
    if (-not [System.IO.File]::Exists($script:WindowsPowerShellExecutable)) {
        throw ('Windows PowerShell 5.1 worker was not found: ' + $script:WindowsPowerShellExecutable)
    }

    $configuration = [pscustomobject]@{
        Executable = $Executable
        Arguments = @($Arguments)
        StdoutPath = $StdoutPath
        StderrPath = $StderrPath
        RunnerErrorPath = $RunnerErrorPath
        StreamEncoding = $StreamEncoding
    }
    $configurationJson = ConvertTo-Json -InputObject $configuration -Depth 4 -Compress
    $configurationBase64 = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($configurationJson))
    $workerTemplate = @'
$configurationJson = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('__PC_NATIVE_CONFIG__'))
$configuration = ConvertFrom-Json -InputObject $configurationJson
$workerExecutable = [string]$configuration.Executable
$workerArguments = @($configuration.Arguments | ForEach-Object { [string]$_ })
$stdoutPath = [string]$configuration.StdoutPath
$stderrPath = [string]$configuration.StderrPath
$runnerErrorPath = [string]$configuration.RunnerErrorPath
$streamEncodingName = [string]$configuration.StreamEncoding
$nativeProcess = $null
try {
    if ($streamEncodingName -eq 'Unicode') { $nativeStreamEncoding = [System.Text.Encoding]::Unicode }
    elseif ($streamEncodingName -eq 'Console') { $nativeStreamEncoding = [System.Console]::OutputEncoding }
    else { throw ('Unsupported native output encoding: ' + $streamEncodingName) }

    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $workerExecutable
    $startInfo.Arguments = ($workerArguments -join ' ')
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.StandardOutputEncoding = $nativeStreamEncoding
    $startInfo.StandardErrorEncoding = $nativeStreamEncoding
    $nativeProcess = [System.Diagnostics.Process]::new()
    $nativeProcess.StartInfo = $startInfo
    if (-not $nativeProcess.Start()) { throw 'The native command worker could not start the requested process.' }
    $stdoutTask = $nativeProcess.StandardOutput.ReadToEndAsync()
    $stderrTask = $nativeProcess.StandardError.ReadToEndAsync()
    $nativeProcess.WaitForExit()
    $nativeExitCode = $nativeProcess.ExitCode
    $stdoutText = $stdoutTask.GetAwaiter().GetResult()
    $stderrText = $stderrTask.GetAwaiter().GetResult()
    [System.IO.File]::WriteAllText($stdoutPath, $stdoutText, [System.Text.UTF8Encoding]::new($true))
    [System.IO.File]::WriteAllText($stderrPath, $stderrText, [System.Text.UTF8Encoding]::new($true))
    exit [int]$nativeExitCode
}
catch {
    try { [System.IO.File]::WriteAllText($runnerErrorPath, $_.Exception.ToString(), [System.Text.UTF8Encoding]::new($true)) } catch { }
    exit 252
}
finally {
    if ($null -ne $nativeProcess) { $nativeProcess.Dispose() }
    if ($null -ne $stdoutWriter) { $stdoutWriter.Dispose() }
    if ($null -ne $stderrWriter) { $stderrWriter.Dispose() }
}
'@
    $workerScript = $workerTemplate.Replace('__PC_NATIVE_CONFIG__', $configurationBase64)
    $workerEncoded = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($workerScript))
    $workerArguments = '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand ' + $workerEncoded
    return Start-Process -FilePath $script:WindowsPowerShellExecutable -ArgumentList $workerArguments -PassThru -WindowStyle Hidden -ErrorAction Stop
}

function Invoke-PCNativeCheck {
    param(
        [string]$Name,
        [string]$Kind,
        [string]$Executable,
        [string[]]$Arguments,
        [int]$TimeoutSeconds
    )
    $quiet = Wait-PCServicingQuiet -TimeoutSeconds $script:ServicingSettleSeconds -RequiredQuietSeconds $script:ServicingQuietSeconds
    if (-not $quiet.Quiet) {
        Add-PCCheck -Name $Name -Status 'blocked' -Summary ('Did not observe a stable ' + $script:ServicingQuietSeconds + '-second servicing-free window within ' + $script:ServicingSettleSeconds + ' seconds; no DISM/SFC command was started.') -Evidence $quiet.Processes
        return [pscustomobject]@{ Started = $false; Status = 'blocked'; ExitCode = $null; StartedLocal = $null }
    }

    try {
        $latestReboot = Get-PCRebootState
        $latestProcesses = @(Get-PCServicingProcesses)
        $latestGate = Get-PCRepairGate -Confirmed $true -Administrator $true -PendingServicingReboot $latestReboot.BlocksComponentServicing -ServicingProcesses $latestProcesses
    }
    catch {
        Add-PCCheck -Name $Name -Status 'blocked' -Summary ('Final servicing preflight could not verify the reboot markers and process list; no DISM/SFC command was started. ' + $_.Exception.Message)
        return [pscustomobject]@{ Started = $false; Status = 'blocked'; ExitCode = $null; StartedLocal = $null }
    }
    if (-not $latestGate.Open) {
        Add-PCCheck -Name $Name -Status 'blocked' -Summary ('Final servicing preflight is closed: ' + ($latestGate.Reasons -join ' ') + ' No DISM/SFC command was started.') -Evidence ([pscustomobject]@{ Markers = $latestReboot.Markers; Processes = $latestProcesses })
        return [pscustomobject]@{ Started = $false; Status = 'blocked'; ExitCode = $null; StartedLocal = $null }
    }

    $safeName = $Name -replace '[^A-Za-z0-9-]', '-'
    $stdoutPath = [System.IO.Path]::Combine($script:RunDirectory, $safeName + '.stdout.txt')
    $stderrPath = [System.IO.Path]::Combine($script:RunDirectory, $safeName + '.stderr.txt')
    $runnerErrorPath = [System.IO.Path]::Combine($script:RunDirectory, $safeName + '.runner-error.txt')
    $streamEncoding = if ($Kind -match '^Sfc') { 'Unicode' } else { 'Console' }
    $startedLocal = [DateTime]::Now
    $process = $null
    try {
        $process = Start-PCNativeCommandWorker -Executable $Executable -Arguments $Arguments -StdoutPath $stdoutPath -StderrPath $stderrPath -RunnerErrorPath $runnerErrorPath -StreamEncoding $streamEncoding
        $watch = [System.Diagnostics.Stopwatch]::StartNew()
        $nextProgressSecond = 30
        while ($watch.Elapsed.TotalSeconds -lt $TimeoutSeconds) {
            $process.Refresh()
            if ($process.HasExited) { break }
            if ($watch.Elapsed.TotalSeconds -ge $nextProgressSecond) {
                Write-Host ('[RUNNING] ' + $Name + ' elapsed=' + [int][Math]::Floor($watch.Elapsed.TotalSeconds) + 's; native output is being retained in separate files.')
                $nextProgressSecond += 30
            }
            Start-Sleep -Seconds 2
        }
        $process.Refresh()
        if (-not $process.HasExited) {
            Write-Host ('[TIMEOUT] ' + $Name + ' elapsed=' + [int][Math]::Floor($watch.Elapsed.TotalSeconds) + 's; process was not killed.')
            Add-PCCheck -Name $Name -Status 'blocked' -Summary ('Timed out after ' + $TimeoutSeconds + ' seconds. The process was not killed; PID=' + $process.Id + '.') -Evidence ([pscustomobject]@{ ProcessId = $process.Id; Stdout = $stdoutPath; Stderr = $stderrPath })
            return [pscustomobject]@{ Started = $true; Status = 'timeout'; ExitCode = $null; StartedLocal = $startedLocal }
        }

        $process.WaitForExit()
        $process.Refresh()
        $nativeExitCode = $process.ExitCode
        if ($null -eq $nativeExitCode) {
            Write-Host ('[DONE] ' + $Name + ' elapsed=' + [int][Math]::Floor($watch.Elapsed.TotalSeconds) + 's; worker did not return a native exit code.')
            Add-PCCheck -Name $Name -Status 'unknown' -Summary 'The Windows PowerShell 5.1 worker exited, but did not provide the native command exit code; output is retained but the result is not treated as verified.' -Evidence ([pscustomobject]@{ Executable = $Executable; Arguments = $Arguments; ExitCode = $null; Stdout = $stdoutPath; Stderr = $stderrPath; RunnerError = $runnerErrorPath; NativeStreamEncoding = $streamEncoding; StartedLocal = $startedLocal.ToString('o'); CompletedLocal = [DateTime]::Now.ToString('o') })
            return [pscustomobject]@{ Started = $true; Status = 'unknown'; ExitCode = $null; StartedLocal = $startedLocal }
        }
        $exitCode = [int]$nativeExitCode
        Write-Host ('[DONE] ' + $Name + ' elapsed=' + [int][Math]::Floor($watch.Elapsed.TotalSeconds) + 's workerExitCode=' + $exitCode + '.')
        if ($exitCode -in @(251, 252, 253) -or [System.IO.File]::Exists($runnerErrorPath)) {
            Add-PCCheck -Name $Name -Status 'unknown' -Summary ('The native-command worker recorded a capture/launch error; its exit code is not treated as the native command result. ExitCode=' + $exitCode + '.') -Evidence ([pscustomobject]@{ Executable = $Executable; Arguments = $Arguments; WorkerExitCode = $exitCode; Stdout = $stdoutPath; Stderr = $stderrPath; RunnerError = $runnerErrorPath; NativeStreamEncoding = $streamEncoding; StartedLocal = $startedLocal.ToString('o'); CompletedLocal = [DateTime]::Now.ToString('o') })
            return [pscustomobject]@{ Started = $true; Status = 'unknown'; ExitCode = $null; StartedLocal = $startedLocal }
        }
        $stdout = if ([System.IO.File]::Exists($stdoutPath)) { [System.IO.File]::ReadAllText($stdoutPath) } else { '' }
        $stderr = if ([System.IO.File]::Exists($stderrPath)) { [System.IO.File]::ReadAllText($stderrPath) } else { '' }
        $verdict = Get-PCCommandVerdict -Kind $Kind -Text ($stdout + [Environment]::NewLine + $stderr) -ExitCode $exitCode
        Add-PCCheck -Name $Name -Status $verdict.Status -Summary ($verdict.Summary + ' ExitCode=' + $exitCode + '.') -Evidence ([pscustomobject]@{
            Executable = $Executable
            Arguments = $Arguments
            ExitCode = $exitCode
            Stdout = $stdoutPath
            Stderr = $stderrPath
            RunnerError = $runnerErrorPath
            Runner = $script:WindowsPowerShellExecutable
            NativeStreamEncoding = $streamEncoding
            StartedLocal = $startedLocal.ToString('o')
            CompletedLocal = [DateTime]::Now.ToString('o')
        })
        return [pscustomobject]@{ Started = $true; Status = $verdict.Status; ExitCode = $exitCode; StartedLocal = $startedLocal }
    }
    catch {
        Add-PCCheck -Name $Name -Status 'fail' -Summary ('Unable to run native command: ' + $_.Exception.Message)
        return [pscustomobject]@{ Started = $false; Status = 'fail'; ExitCode = $null; StartedLocal = $startedLocal }
    }
    finally {
        if ($null -ne $process) { $process.Dispose() }
    }
}

function Save-PCSfcEvidence {
    param([DateTime]$SinceLocal)
    $cbsPath = [System.IO.Path]::Combine($env:windir, 'Logs\CBS\CBS.log')
    if (-not [System.IO.File]::Exists($cbsPath)) {
        Add-PCCheck -Name 'CurrentSfcCBSRecords' -Status 'unknown' -Summary 'CBS.log was not found; no file-level SFC conclusion is available.'
        return
    }

    $srLines = [System.Collections.Generic.List[string]]::new()
    $currentStamp = [DateTime]::MinValue
    $reader = $null
    try {
        $stream = [System.IO.File]::Open($cbsPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        $reader = [System.IO.StreamReader]::new($stream)
        while (-not $reader.EndOfStream) {
            $line = $reader.ReadLine()
            $stampMatch = [System.Text.RegularExpressions.Regex]::Match($line, '^(?<stamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})')
            if ($stampMatch.Success) {
                $parsed = [DateTime]::MinValue
                $ok = [DateTime]::TryParse($stampMatch.Groups['stamp'].Value, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeLocal, [ref]$parsed)
                if ($ok) { $currentStamp = $parsed }
            }
            if ($currentStamp -ge $SinceLocal -and $line -match '\[SR\]' -and $srLines.Count -lt 1000) {
                $srLines.Add($line)
            }
        }
        $reader.Dispose()
        $reader = $null
        $evidencePath = [System.IO.Path]::Combine($script:RunDirectory, 'cbs-sfc-current.txt')
        [System.IO.File]::WriteAllLines($evidencePath, $srLines.ToArray(), [System.Text.UTF8Encoding]::new($true))
        if ($srLines.Count -gt 0) {
            Add-PCCheck -Name 'CurrentSfcCBSRecords' -Status 'warn' -Summary ('Captured ' + $srLines.Count + ' time-correlated [SR] records; review for exact unrepaired members.') -Evidence $evidencePath
        }
        else {
            Add-PCCheck -Name 'CurrentSfcCBSRecords' -Status 'unknown' -Summary 'No time-correlated [SR] records were found; this does not prove SFC found no corrupt files.' -Evidence $evidencePath
        }
    }
    catch {
        if ($null -ne $reader) { $reader.Dispose() }
        Add-PCCheck -Name 'CurrentSfcCBSRecords' -Status 'unknown' -Summary ('Could not extract time-correlated [SR] records: ' + $_.Exception.Message)
    }
}

function Write-PCReport {
    param([string]$Path)
    $overall = Get-PCOverallStatus -Checks $script:Checks.ToArray()
    $report = [ordered]@{
        SchemaVersion = 1
        RunId = $script:RunId
        Mode = $script:Mode
        ComputerName = $env:COMPUTERNAME
        StartedUtc = $script:RunStartedLocal.ToUniversalTime().ToString('o')
        CompletedUtc = [DateTime]::UtcNow.ToString('o')
        PowerShellVersion = $PSVersionTable.PSVersion.ToString()
        PowerShellEdition = $PSVersionTable.PSEdition
        WindowsDirectory = $env:windir
        Overall = $overall
        Checks = @($script:Checks.ToArray())
    }
    $json = ConvertTo-Json -InputObject $report -Depth 8
    [System.IO.File]::WriteAllText($Path, $json, [System.Text.UTF8Encoding]::new($true))
    return $overall
}

function Invoke-PCSelfTest {
    $failures = [System.Collections.Generic.List[string]]::new()
    $cases = @(
        @{ Name = 'DismClean'; Kind = 'DismCheckHealth'; Text = 'No component store corruption detected.'; ExitCode = 0; Expected = 'pass' },
        @{ Name = 'DismCleanNonZero'; Kind = 'DismCheckHealth'; Text = 'No component store corruption detected.'; ExitCode = 5; Expected = 'fail' },
        @{ Name = 'DismScanClean'; Kind = 'DismScanHealth'; Text = 'No component store corruption detected.'; ExitCode = 0; Expected = 'pass' },
        @{ Name = 'DismScanCleanNonZero'; Kind = 'DismScanHealth'; Text = 'No component store corruption detected.'; ExitCode = 5; Expected = 'fail' },
        @{ Name = 'DismRepairable'; Kind = 'DismCheckHealth'; Text = 'The component store is repairable.'; ExitCode = 0; Expected = 'fail' },
        @{ Name = 'DismRestoreSuccess'; Kind = 'DismRestoreHealth'; Text = 'The restore operation completed successfully.'; ExitCode = 0; Expected = 'pass' },
        @{ Name = 'DismRestoreNonZero'; Kind = 'DismRestoreHealth'; Text = 'The restore operation completed successfully.'; ExitCode = 5; Expected = 'fail' },
        @{ Name = 'SfcVerifyClean'; Kind = 'SfcVerifyOnly'; Text = 'Windows Resource Protection did not find any integrity violations.'; ExitCode = 0; Expected = 'pass' },
        @{ Name = 'SfcVerifyCleanNonZero'; Kind = 'SfcVerifyOnly'; Text = 'Windows Resource Protection did not find any integrity violations.'; ExitCode = 5; Expected = 'fail' },
        @{ Name = 'SfcVerifyDirty'; Kind = 'SfcVerifyOnly'; Text = 'Windows Resource Protection found integrity violations.'; ExitCode = 0; Expected = 'fail' },
        @{ Name = 'SfcScanCleanNonZero'; Kind = 'SfcScanNow'; Text = 'Windows Resource Protection did not find any integrity violations.'; ExitCode = 5; Expected = 'fail' },
        @{ Name = 'SfcUnrepairedExitZero'; Kind = 'SfcScanNow'; Text = 'Windows Resource Protection found corrupt files but was unable to fix some of them.'; ExitCode = 0; Expected = 'fail' },
        @{ Name = 'SfcRepairedNeedsVerify'; Kind = 'SfcScanNow'; Text = 'Windows Resource Protection found corrupt files and successfully repaired them.'; ExitCode = 0; Expected = 'warn' },
        @{ Name = 'SfcRepairedNonZero'; Kind = 'SfcScanNow'; Text = 'Windows Resource Protection found corrupt files and successfully repaired them.'; ExitCode = 5; Expected = 'fail' },
        @{ Name = 'UnknownExitZero'; Kind = 'SfcVerifyOnly'; Text = 'Unexpected native output.'; ExitCode = 0; Expected = 'unknown' }
    )
    foreach ($case in $cases) {
        $actual = Get-PCCommandVerdict -Kind $case.Kind -Text $case.Text -ExitCode $case.ExitCode
        if ($actual.Status -ne $case.Expected) { $failures.Add($case.Name + ' expected ' + $case.Expected + ' but got ' + $actual.Status) }
    }

    $healthyNtfs98 = Get-PCStorageEventVerdict -ProviderName 'Ntfs' -EventId 98 -Message 'The volume F: is healthy. No action is needed.'
    if ($healthyNtfs98.Status -ne 'pass') { $failures.Add('Healthy NTFS Event 98 should be informational/pass.') }
    $disk153 = Get-PCStorageEventVerdict -ProviderName 'disk' -EventId 153 -Message 'The IO operation at logical block address 12 was retried. Disk 1.'
    if ($disk153.Status -ne 'warn') { $failures.Add('Disk Event 153 should require review.') }
    $unhealthyNtfs98 = Get-PCStorageEventVerdict -ProviderName 'Ntfs' -EventId 98 -Message 'The volume requires a scan.'
    if ($unhealthyNtfs98.Status -ne 'warn') { $failures.Add('An NTFS Event 98 without the explicit healthy message should require review.') }
    $syntheticClearTime = '2026-09-17T22:00:47.1712502+03:00'
    $syntheticClearAudit = [pscustomobject]@{
        QueryError = ''
        Events = @(
            [pscustomobject]@{ Channel = 'System'; TimeCreatedLocal = $syntheticClearTime; TimeCreatedUtc = '2026-09-17T19:00:47.1712502Z'; EventRecordId = 50325; SubjectUserName = 'SyntheticUser'; ClientProcessId = 1234 },
            [pscustomobject]@{ Channel = 'Microsoft-Windows-Bits-Client/Operational'; TimeCreatedLocal = $syntheticClearTime; TimeCreatedUtc = '2026-09-17T19:00:47.1712502Z'; EventRecordId = 50765; SubjectUserName = 'SyntheticUser'; ClientProcessId = 1234 },
            [pscustomobject]@{ Channel = 'Microsoft-Windows-CodeIntegrity/Operational'; TimeCreatedLocal = $syntheticClearTime; TimeCreatedUtc = '2026-09-17T19:00:47.1712502Z'; EventRecordId = 50747; SubjectUserName = 'SyntheticUser'; ClientProcessId = 1234 }
        )
    }
    $syntheticHistoryWindowStart = [datetime]'2026-09-17T21:00:00'
    $completeLogMetadata = [pscustomobject]@{ IsEnabled = $true; RecordCount = 100; OldestRecordTimeLocal = '2026-09-17T20:00:00+03:00'; QueryError = '' }
    $partialSystemHistory = Get-PCEventLogClearState -Audit $syntheticClearAudit -LogName 'System' -WindowStartLocal $syntheticHistoryWindowStart -LogMetadata $completeLogMetadata
    if ($partialSystemHistory.HistoryComplete -or $partialSystemHistory.HistoryStatus -ne 'partial') { $failures.Add('A System log clear inside the review window must mark its event history partial.') }
    $partialBitsHistory = Get-PCEventLogClearState -Audit $syntheticClearAudit -LogName 'Microsoft-Windows-Bits-Client/Operational' -WindowStartLocal $syntheticHistoryWindowStart -LogMetadata $completeLogMetadata
    if ($partialBitsHistory.HistoryComplete -or $partialBitsHistory.ClearCount -ne 1) { $failures.Add('A BITS Operational clear inside the review window must be detected for that channel.') }
    $unaffectedLogHistory = Get-PCEventLogClearState -Audit $syntheticClearAudit -LogName 'Microsoft-Windows-WindowsUpdateClient/Operational' -WindowStartLocal $syntheticHistoryWindowStart -LogMetadata $completeLogMetadata
    if (-not $unaffectedLogHistory.HistoryComplete) { $failures.Add('A clear of a different channel must not invalidate an unaffected log window.') }
    $clearQueryFailure = Get-PCEventLogClearState -Audit ([pscustomobject]@{ QueryError = 'Synthetic Event ID 104 query failure.'; Events = @() }) -LogName 'System' -WindowStartLocal $syntheticHistoryWindowStart -LogMetadata $completeLogMetadata
    if ($clearQueryFailure.HistoryStatus -ne 'unknown') { $failures.Add('Unavailable log-clear markers must remain unknown, not complete.') }
    $rolloverMetadata = [pscustomobject]@{ IsEnabled = $true; RecordCount = 12; OldestRecordTimeLocal = '2026-09-17T21:15:00+03:00'; QueryError = '' }
    $rolloverHistory = Get-PCEventLogClearState -Audit ([pscustomobject]@{ QueryError = ''; Events = @() }) -LogName 'Microsoft-Windows-WindowsUpdateClient/Operational' -WindowStartLocal $syntheticHistoryWindowStart -LogMetadata $rolloverMetadata
    if ($rolloverHistory.HistoryStatus -ne 'partial' -or $rolloverHistory.Summary -notmatch '(?i)oldest retained') { $failures.Add('A log whose oldest retained record starts inside the requested window must be marked partial even without a clear marker.') }
    $disabledMetadata = [pscustomobject]@{ IsEnabled = $false; RecordCount = 0; OldestRecordTimeLocal = $null; QueryError = 'The channel is disabled; its requested history cannot be verified.' }
    $disabledHistory = Get-PCEventLogClearState -Audit ([pscustomobject]@{ QueryError = ''; Events = @() }) -LogName 'Microsoft-Windows-WindowsUpdateClient/Operational' -WindowStartLocal $syntheticHistoryWindowStart -LogMetadata $disabledMetadata
    if ($disabledHistory.HistoryStatus -ne 'unknown') { $failures.Add('A disabled or empty log must remain unknown rather than imply a clean history window.') }
    $preWindowClearAudit = [pscustomobject]@{ QueryError = ''; Events = @([pscustomobject]@{ Channel = 'Microsoft-Windows-Bits-Client/Operational'; TimeCreatedLocal = '2026-09-17T20:00:00+03:00'; TimeCreatedUtc = '2026-09-17T17:00:00Z'; EventRecordId = 10 }) }
    $preWindowClearHistory = Get-PCEventLogClearState -Audit $preWindowClearAudit -LogName 'Microsoft-Windows-Bits-Client/Operational' -WindowStartLocal $syntheticHistoryWindowStart -LogMetadata $completeLogMetadata
    if (-not $preWindowClearHistory.HistoryComplete) { $failures.Add('A clear before the requested window must not invalidate an otherwise retained complete window.') }
    $storageHistoryGap = Get-PCStorageEventsHistoryVerdict -EventCount 0 -WarningEventCount 0 -HistoryState $partialSystemHistory
    if ($storageHistoryGap.Status -ne 'unknown' -or $storageHistoryGap.Summary -notmatch '(?i)incomplete|cleared') { $failures.Add('An empty storage query after a System log clear must be unknown, not a clean pass.') }
    $storageFindingAfterClear = Get-PCStorageEventsHistoryVerdict -EventCount 1 -WarningEventCount 1 -HistoryState $partialSystemHistory
    if ($storageFindingAfterClear.Status -ne 'warn' -or $storageFindingAfterClear.Summary -notmatch '(?i)partial|cleared') { $failures.Add('A storage finding remains a warning and must disclose incomplete history.') }
    $completeStorageHistory = Get-PCStorageEventsHistoryVerdict -EventCount 0 -WarningEventCount 0 -HistoryState $unaffectedLogHistory
    if ($completeStorageHistory.Status -ne 'pass') { $failures.Add('A successful empty storage query with complete System history may pass.') }
    $diskNumberFromMessage = Get-PCDiskNumberFromStorageEvent -Message 'An I/O retry occurred on Disk 1.'
    if ($diskNumberFromMessage -ne 1) { $failures.Add('Storage event parser should extract Disk 1 from the rendered message.') }
    $diskNumberFromProperty = Get-PCDiskNumberFromStorageEvent -Properties @([pscustomobject]@{ Value = '\Device\Harddisk7\DR7' })
    if ($diskNumberFromProperty -ne 7) { $failures.Add('Storage event parser should extract a disk number from a device property.') }
    $eventLetters = @(Get-PCStorageDriveLettersFromEvent -Message 'I/O retry at F:\backup\disk.img; mounted volume G:')
    if ($eventLetters.Count -ne 2 -or $eventLetters[0] -ne 'F:' -or $eventLetters[1] -ne 'G:') { $failures.Add('Storage event parser should extract and sort mentioned drive letters.') }

    $syntheticDiskMap = @(Get-PCStorageDiskMap -DiskDrives @([pscustomobject]@{ Index = 1; Size = [long](953.9 * 1GB); DeviceID = '\\.\PHYSICALDRIVE1'; Model = 'Fanxiang FF951'; Status = 'OK' }) -PartitionAssociations @([pscustomobject]@{ Antecedent = 'Win32_DiskPartition.DeviceID="Disk #1, Partition #0"'; Dependent = 'Win32_LogicalDisk.DeviceID="F:"' }) -LogicalDisks @([pscustomobject]@{ DeviceID = 'F:'; FileSystem = 'NTFS' }))
    if ($syntheticDiskMap.Count -ne 1 -or $syntheticDiskMap[0].Number -ne 1 -or $syntheticDiskMap[0].DriveLetters -notcontains 'F:' -or $syntheticDiskMap[0].Volumes[0].FileSystem -ne 'NTFS') { $failures.Add('Disk-to-volume mapping should connect Disk 1 to F: (NTFS).') }

    $completeCounters = [pscustomobject]@{
        ReadErrorsTotal = 0; ReadErrorsUncorrected = 0; WriteErrorsTotal = 0; WriteErrorsUncorrected = 0
        ReadLatencyMax = 0; WriteLatencyMax = 0; FlushLatencyMax = 0; Temperature = 41; Wear = 0
    }
    $cleanReliability = Get-PCStorageReliabilityVerdict -HealthStatus 'Healthy' -OperationalStatus @('Online') -Counters $completeCounters
    if ($cleanReliability.Status -ne 'pass') { $failures.Add('Complete healthy storage counters should pass.') }
    $highLatencyCounters = [pscustomobject]@{ ReadErrorsTotal = 0; ReadErrorsUncorrected = 0; WriteErrorsTotal = 0; WriteErrorsUncorrected = 0; ReadLatencyMax = 10001; WriteLatencyMax = 0; FlushLatencyMax = 0; Temperature = 41; Wear = 0 }
    $highLatencyReliability = Get-PCStorageReliabilityVerdict -HealthStatus 'Healthy' -OperationalStatus @('Online') -Counters $highLatencyCounters
    if ($highLatencyReliability.Status -ne 'warn') { $failures.Add('Storage latency above 10000 ms should require review.') }
    $thresholdCounters = [pscustomobject]@{ ReadErrorsTotal = 0; ReadErrorsUncorrected = 0; WriteErrorsTotal = 0; WriteErrorsUncorrected = 0; ReadLatencyMax = 10000; WriteLatencyMax = 0; FlushLatencyMax = 0; Temperature = 41; Wear = 0 }
    $thresholdReliability = Get-PCStorageReliabilityVerdict -HealthStatus 'Healthy' -OperationalStatus @('Online') -Counters $thresholdCounters
    if ($thresholdReliability.Status -ne 'pass') { $failures.Add('Storage latency at exactly 10000 ms should not cross the strict review threshold.') }
    $errorCounters = [pscustomobject]@{ ReadErrorsTotal = 0; ReadErrorsUncorrected = 0; WriteErrorsTotal = 1; WriteErrorsUncorrected = 0; ReadLatencyMax = 0; WriteLatencyMax = 0; FlushLatencyMax = 0; Temperature = 41; Wear = 0 }
    $errorReliability = Get-PCStorageReliabilityVerdict -HealthStatus 'Healthy' -OperationalStatus @('Online') -Counters $errorCounters
    if ($errorReliability.Status -ne 'warn') { $failures.Add('A nonzero storage error counter should require review.') }
    $unknownReliability = Get-PCStorageReliabilityVerdict -HealthStatus 'Healthy' -OperationalStatus @('Online') -Counters $null
    if ($unknownReliability.Status -ne 'unknown') { $failures.Add('Unavailable reliability counters must remain unknown, not zero/pass.') }
    $counterSnapshot = Get-PCStorageCounterSnapshot -Counters ([pscustomobject]@{ DeviceId = '1'; ReadLatencyMax = 25; Temperature = 40; CimClass = 'metadata that must not be retained' })
    if ($counterSnapshot.ReadLatencyMax -ne 25 -or $counterSnapshot.PSObject.Properties['CimClass']) { $failures.Add('Storage counter snapshots should preserve selected measurements without serializing CIM metadata.') }

    $statusChecks = @(
        @{ Name = 'Completed'; Checks = @([pscustomobject]@{ Status = 'pass' }); Expected = 'Completed' },
        @{ Name = 'NeedsReview'; Checks = @([pscustomobject]@{ Status = 'warn' }); Expected = 'NeedsReview' },
        @{ Name = 'Incomplete'; Checks = @([pscustomobject]@{ Status = 'unknown' }); Expected = 'Incomplete' },
        @{ Name = 'Failed'; Checks = @([pscustomobject]@{ Status = 'pass' }, [pscustomobject]@{ Status = 'fail' }); Expected = 'Failed' }
    )
    foreach ($statusCase in $statusChecks) {
        $actualOverall = Get-PCOverallStatus -Checks $statusCase.Checks
        if ($actualOverall -ne $statusCase.Expected) { $failures.Add('Overall status ' + $statusCase.Name + ' expected ' + $statusCase.Expected + ' but got ' + $actualOverall) }
    }

    $enabledProfiles = @(
        [pscustomobject]@{ Name = 'Domain'; Enabled = $true },
        [pscustomobject]@{ Name = 'Private'; Enabled = $true },
        [pscustomobject]@{ Name = 'Public'; Enabled = $true }
    )
    $stoppedFirewall = Get-PCFirewallStateVerdict -FirewallServiceState 'Stopped' -FirewallStartMode 'Auto' -BaseFilteringEngineState 'Running' -EffectiveProfiles @() -ProfileQueryError 'Firewall service is unavailable.'
    if ($stoppedFirewall.Status -ne 'warn') { $failures.Add('A stopped firewall service should be visibly flagged even when its profiles cannot be queried.') }
    $runningFirewall = Get-PCFirewallStateVerdict -FirewallServiceState 'Running' -FirewallStartMode 'Auto' -BaseFilteringEngineState 'Running' -NetworkStoreInterfaceState 'Running' -EffectiveProfiles $enabledProfiles
    if ($runningFirewall.Status -ne 'pass') { $failures.Add('Running firewall dependencies with all three profiles enabled should pass.') }
    $unknownNetworkStore = Get-PCFirewallStateVerdict -FirewallServiceState 'Running' -FirewallStartMode 'Auto' -BaseFilteringEngineState 'Running' -EffectiveProfiles $enabledProfiles
    if ($unknownNetworkStore.Status -ne 'unknown') { $failures.Add('An unavailable NSI state must remain unknown even when other firewall checks pass.') }
    $stoppedNetworkStore = Get-PCFirewallStateVerdict -FirewallServiceState 'Running' -FirewallStartMode 'Auto' -BaseFilteringEngineState 'Running' -NetworkStoreInterfaceState 'Stopped' -EffectiveProfiles $enabledProfiles
    if ($stoppedNetworkStore.Status -ne 'warn') { $failures.Add('A stopped NSI dependency should be visibly flagged.') }
    $mpsdrvIntegrityFailure = Get-PCFirewallStateVerdict -FirewallServiceState 'Running' -FirewallStartMode 'Auto' -BaseFilteringEngineState 'Running' -NetworkStoreInterfaceState 'Running' -MpsdrvIntegrityFailureCount 1 -EffectiveProfiles $enabledProfiles
    if ($mpsdrvIntegrityFailure.Status -ne 'warn' -or $mpsdrvIntegrityFailure.Summary -notmatch 'Code Integrity') { $failures.Add('Recent mpsdrv image-integrity failures should be visibly flagged.') }
    $unknownMpsdrvIntegrity = Get-PCFirewallStateVerdict -FirewallServiceState 'Running' -FirewallStartMode 'Auto' -BaseFilteringEngineState 'Running' -NetworkStoreInterfaceState 'Running' -MpsdrvIntegrityQueryError 'Synthetic query failure.' -EffectiveProfiles $enabledProfiles
    if ($unknownMpsdrvIntegrity.Status -ne 'unknown') { $failures.Add('An unavailable mpsdrv Code Integrity query must not be reported as pass.') }
    $partialMpsdrvHistory = Get-PCEventLogClearState -Audit $syntheticClearAudit -LogName 'Microsoft-Windows-CodeIntegrity/Operational' -WindowStartLocal $syntheticHistoryWindowStart -LogMetadata $completeLogMetadata
    $unknownMpsdrvHistory = Get-PCFirewallStateVerdict -FirewallServiceState 'Running' -FirewallStartMode 'Auto' -BaseFilteringEngineState 'Running' -NetworkStoreInterfaceState 'Running' -MpsdrvIntegrityHistoryComplete $partialMpsdrvHistory.HistoryComplete -MpsdrvIntegrityHistoryNote $partialMpsdrvHistory.Summary -EffectiveProfiles $enabledProfiles
    if ($unknownMpsdrvHistory.Status -ne 'unknown' -or $unknownMpsdrvHistory.Summary -notmatch '(?i)partial|cleared') { $failures.Add('No Code Integrity findings after a channel clear must remain unknown and disclose the history gap.') }
    $warningMpsdrvHistory = Get-PCFirewallStateVerdict -FirewallServiceState 'Running' -FirewallStartMode 'Auto' -BaseFilteringEngineState 'Running' -NetworkStoreInterfaceState 'Running' -MpsdrvIntegrityFailureCount 1 -MpsdrvIntegrityHistoryComplete $partialMpsdrvHistory.HistoryComplete -MpsdrvIntegrityHistoryNote $partialMpsdrvHistory.Summary -EffectiveProfiles $enabledProfiles
    if ($warningMpsdrvHistory.Status -ne 'warn' -or $warningMpsdrvHistory.Summary -notmatch '(?i)partial|cleared') { $failures.Add('A current Code Integrity finding remains a warning and must disclose incomplete history.') }
    $unknownFirewall = Get-PCFirewallStateVerdict -FirewallServiceState 'Running' -FirewallStartMode 'Auto' -BaseFilteringEngineState 'Running' -NetworkStoreInterfaceState 'Running' -EffectiveProfiles @() -ProfileQueryError 'Synthetic query failure.'
    if ($unknownFirewall.Status -ne 'unknown') { $failures.Add('An unreadable firewall profile state must remain unknown.') }
    $syntheticErrorRecord = [System.Management.Automation.ErrorRecord]::new([System.InvalidOperationException]::new('Synthetic provider failure.'), 'SyntheticProviderFailure', [System.Management.Automation.ErrorCategory]::NotSpecified, $null)
    $syntheticErrorSummary = Get-PCErrorSummary -ErrorRecord $syntheticErrorRecord
    if ($syntheticErrorSummary -ne 'Synthetic provider failure. [SyntheticProviderFailure]') { $failures.Add('Provider-query summaries should retain the native error identifier.') }
    $transientBits = Get-PCBitsAuditVerdict -Jobs @([pscustomobject]@{ JobState = 'TransientError' }) -Event61Count 4
    if ($transientBits.Status -ne 'warn') { $failures.Add('BITS transient-error jobs or Event 61 records should require review.') }
    $cleanBits = Get-PCBitsAuditVerdict -Jobs @() -Event61Count 0
    if ($cleanBits.Status -ne 'pass') { $failures.Add('No BITS failures and no recent Event 61 records should pass.') }
    $unknownBits = Get-PCBitsAuditVerdict -Jobs @() -Event61Count 0 -QueryErrors @('Synthetic query failure.')
    if ($unknownBits.Status -ne 'unknown') { $failures.Add('Unavailable BITS data must remain unknown.') }
    $unknownBitsHistory = Get-PCBitsAuditVerdict -Jobs @() -Event61Count 0 -EventHistoryComplete $partialBitsHistory.HistoryComplete -EventHistoryNote $partialBitsHistory.Summary
    if ($unknownBitsHistory.Status -ne 'unknown' -or $unknownBitsHistory.Summary -notmatch '(?i)partial|cleared') { $failures.Add('No BITS Event 61 records after an Operational log clear must remain unknown and disclose the history gap.') }
    $warningBitsHistory = Get-PCBitsAuditVerdict -Jobs @() -Event61Count 1 -EventHistoryComplete $partialBitsHistory.HistoryComplete -EventHistoryNote $partialBitsHistory.Summary
    if ($warningBitsHistory.Status -ne 'warn' -or $warningBitsHistory.Summary -notmatch '(?i)partial|cleared') { $failures.Add('A current BITS Event 61 remains a warning and must disclose incomplete history.') }
    $unstableEverything = Get-PCServiceStabilityVerdict -ServiceName 'Everything' -ServiceState 'Running' -StartMode 'Auto' -UnexpectedExitCount 3
    if ($unstableEverything.Status -ne 'warn') { $failures.Add('Recent unexpected Everything service exits should require review.') }
    $stableEverything = Get-PCServiceStabilityVerdict -ServiceName 'Everything' -ServiceState 'Running' -StartMode 'Auto' -UnexpectedExitCount 0
    if ($stableEverything.Status -ne 'pass') { $failures.Add('A running Everything service with no unexpected exits should pass.') }
    $unknownEverythingHistory = Get-PCServiceStabilityVerdict -ServiceName 'Everything' -ServiceState 'Running' -StartMode 'Auto' -UnexpectedExitCount 0 -EventHistoryComplete $partialSystemHistory.HistoryComplete -EventHistoryNote $partialSystemHistory.Summary
    if ($unknownEverythingHistory.Status -ne 'unknown' -or $unknownEverythingHistory.Summary -notmatch '(?i)partial|cleared') { $failures.Add('No Everything exits after a System log clear must remain unknown and disclose the history gap.') }
    $warningEverythingHistory = Get-PCServiceStabilityVerdict -ServiceName 'Everything' -ServiceState 'Running' -StartMode 'Auto' -UnexpectedExitCount 1 -EventHistoryComplete $partialSystemHistory.HistoryComplete -EventHistoryNote $partialSystemHistory.Summary
    if ($warningEverythingHistory.Status -ne 'warn' -or $warningEverythingHistory.Summary -notmatch '(?i)partial|cleared') { $failures.Add('An Everything exit finding remains a warning and must disclose incomplete history.') }

    $nativeWorkerRoot = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), 'PCIntegrityNativeWorkerSelfTest_' + [Guid]::NewGuid().ToString('N'))
    $nativeWorkerSafeToDelete = $true
    try {
        [void][System.IO.Directory]::CreateDirectory($nativeWorkerRoot)
        $cmdExecutable = [System.IO.Path]::Combine($env:windir, 'System32\cmd.exe')
        $nativeWorkerCases = @(
            @{ Name = 'Console'; Encoding = 'Console'; Prefix = '' },
            @{ Name = 'Unicode'; Encoding = 'Unicode'; Prefix = '/u ' }
        )
        foreach ($nativeWorkerCase in $nativeWorkerCases) {
            $caseRoot = [System.IO.Path]::Combine($nativeWorkerRoot, $nativeWorkerCase.Name)
            [void][System.IO.Directory]::CreateDirectory($caseRoot)
            $nativeWorkerStdout = [System.IO.Path]::Combine($caseRoot, 'stdout.txt')
            $nativeWorkerStderr = [System.IO.Path]::Combine($caseRoot, 'stderr.txt')
            $nativeWorkerError = [System.IO.Path]::Combine($caseRoot, 'runner-error.txt')
            $marker = 'NATIVE-WORKER-' + $nativeWorkerCase.Name
            $cmdLine = 'echo ' + $marker + '-STDOUT & echo ' + $marker + '-STDERR 1>&2 & exit /b 7'
            $cmdArguments = @()
            if ($nativeWorkerCase.Prefix) { $cmdArguments += $nativeWorkerCase.Prefix.Trim() }
            $cmdArguments += @('/d', '/c', $cmdLine)
            $nativeWorkerProcess = $null
            $nativeWorkerCaseFinished = $true
            try {
                $nativeWorkerProcess = Start-PCNativeCommandWorker -Executable $cmdExecutable -Arguments $cmdArguments -StdoutPath $nativeWorkerStdout -StderrPath $nativeWorkerStderr -RunnerErrorPath $nativeWorkerError -StreamEncoding $nativeWorkerCase.Encoding
                $nativeWorkerCaseFinished = $false
                if (-not $nativeWorkerProcess.WaitForExit(15000)) {
                    $failures.Add('Native worker ' + $nativeWorkerCase.Name + ' self-test timed out; the harmless test process was not terminated.')
                }
                else {
                    $nativeWorkerCaseFinished = $true
                    $nativeWorkerProcess.WaitForExit()
                    $nativeWorkerProcess.Refresh()
                    if ($nativeWorkerProcess.ExitCode -ne 7) { $failures.Add('Native worker ' + $nativeWorkerCase.Name + ' self-test did not preserve exit code 7.') }
                    $nativeWorkerStdoutText = [System.IO.File]::ReadAllText($nativeWorkerStdout)
                    $nativeWorkerStderrText = [System.IO.File]::ReadAllText($nativeWorkerStderr)
                    if ($nativeWorkerStdoutText -notmatch ($marker + '-STDOUT')) { $failures.Add('Native worker ' + $nativeWorkerCase.Name + ' self-test did not preserve stdout.') }
                    if ($nativeWorkerStderrText -notmatch ($marker + '-STDERR')) { $failures.Add('Native worker ' + $nativeWorkerCase.Name + ' self-test did not preserve stderr.') }
                    if ([System.IO.File]::Exists($nativeWorkerError)) { $failures.Add('Native worker ' + $nativeWorkerCase.Name + ' self-test unexpectedly recorded a runner error.') }
                }
            }
            catch {
                $failures.Add('Native worker ' + $nativeWorkerCase.Name + ' self-test failed: ' + $_.Exception.Message)
            }
            finally {
                if ($null -ne $nativeWorkerProcess) {
                    try { if ($nativeWorkerProcess.HasExited) { $nativeWorkerCaseFinished = $true } } catch { }
                    $nativeWorkerProcess.Dispose()
                }
                if (-not $nativeWorkerCaseFinished) { $nativeWorkerSafeToDelete = $false }
            }
        }
    }
    catch {
        $failures.Add('Native worker self-test failed: ' + $_.Exception.Message)
    }
    finally {
        if ($nativeWorkerSafeToDelete) {
            $tempRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
            if (-not $tempRoot.EndsWith([string][System.IO.Path]::DirectorySeparatorChar)) { $tempRoot += [System.IO.Path]::DirectorySeparatorChar }
            $fullNativeWorkerRoot = [System.IO.Path]::GetFullPath($nativeWorkerRoot)
            if ($fullNativeWorkerRoot.StartsWith($tempRoot, [System.StringComparison]::OrdinalIgnoreCase) -and [System.IO.Directory]::Exists($fullNativeWorkerRoot)) {
                [System.IO.Directory]::Delete($fullNativeWorkerRoot, $true)
            }
        }
    }

    $openGate = Get-PCRepairGate -Confirmed $true -Administrator $true -PendingServicingReboot $false -ServicingProcesses @()
    if (-not $openGate.Open) { $failures.Add('Clean repair gate should be open.') }
    $unconfirmedGate = Get-PCRepairGate -Confirmed $false -Administrator $true -PendingServicingReboot $false -ServicingProcesses @()
    if ($unconfirmedGate.Open) { $failures.Add('Repair gate must reject missing explicit confirmation.') }
    $nonAdminGate = Get-PCRepairGate -Confirmed $true -Administrator $false -PendingServicingReboot $false -ServicingProcesses @()
    if ($nonAdminGate.Open) { $failures.Add('Repair gate must reject a non-administrator.') }
    $rebootGate = Get-PCRepairGate -Confirmed $true -Administrator $true -PendingServicingReboot $true -ServicingProcesses @()
    if ($rebootGate.Open) { $failures.Add('Repair gate must reject a Windows servicing reboot marker.') }
    $servicingGate = Get-PCRepairGate -Confirmed $true -Administrator $true -PendingServicingReboot $false -ServicingProcesses @([pscustomobject]@{ Name = 'TiWorker'; Id = 1 })
    if ($servicingGate.Open) { $failures.Add('Repair gate must reject an active servicing process.') }

    $tempRoot = 'C:\Users\SelfTest\AppData\Local\Temp'
    $customTempRoot = 'D:\Scratch\SelfTestTemp'
    $temporaryRoots = @($tempRoot, $customTempRoot)
    $cleanup = Get-PCPendingRenameAssessment -Entries @('*1\??\C:\Users\SelfTest\AppData\Local\Temp\file.node', '') -TemporaryRoots $temporaryRoots
    if (-not $cleanup.CleanupOnly -or $cleanup.BlocksComponentServicing) { $failures.Add('A deferred deletion under the current user LocalAppData Temp directory should not block component checks.') }
    $cleanupGate = Get-PCRepairGate -Confirmed $true -Administrator $true -PendingServicingReboot $cleanup.BlocksComponentServicing -ServicingProcesses @()
    if (-not $cleanupGate.Open) { $failures.Add('Cleanup-only pending renames should not close the Windows repair gate.') }
    $customCleanup = Get-PCPendingRenameAssessment -Entries @('*1\??\D:\Scratch\SelfTestTemp\setup.tmp', '') -TemporaryRoots $temporaryRoots
    if (-not $customCleanup.CleanupOnly -or $customCleanup.BlocksComponentServicing) { $failures.Add('A deferred deletion under the current user configured Temp directory should not block component checks.') }
    $systemRename = Get-PCPendingRenameAssessment -Entries @('*1\??\C:\Windows\WinSxS\pending.dll', '') -TemporaryRoots $temporaryRoots
    if (-not $systemRename.BlocksComponentServicing) { $failures.Add('A pending operation under Windows must block component repair.') }
    $otherUserTemp = Get-PCPendingRenameAssessment -Entries @('*1\??\C:\Users\Other\AppData\Local\Temp\other.tmp', '') -TemporaryRoots $temporaryRoots
    if (-not $otherUserTemp.BlocksComponentServicing) { $failures.Add('A deferred deletion under another user Temp directory must remain blocking.') }
    $tempMove = Get-PCPendingRenameAssessment -Entries @('*1\??\C:\Users\SelfTest\AppData\Local\Temp\old.tmp', '*1\??\C:\Users\SelfTest\AppData\Local\Temp\new.tmp') -TemporaryRoots $temporaryRoots
    if (-not $tempMove.BlocksComponentServicing) { $failures.Add('A rename/move under Temp must remain blocking.') }
    $incompletePair = Get-PCPendingRenameAssessment -Entries @('*1\??\C:\Users\SelfTest\AppData\Local\Temp\unpaired.tmp') -TemporaryRoots $temporaryRoots
    if (-not $incompletePair.BlocksComponentServicing) { $failures.Add('An incomplete pending operation must remain blocking.') }
    $tempTraversal = Get-PCPendingRenameAssessment -Entries @('*1\??\C:\Users\SelfTest\AppData\Local\Temp\..\..\..\Windows\WinSxS\pending.dll', '') -TemporaryRoots $temporaryRoots
    if (-not $tempTraversal.BlocksComponentServicing) { $failures.Add('A path that escapes Temp through parent components must remain blocking.') }
    $tempPrefixLookalike = Get-PCPendingRenameAssessment -Entries @('*1\??\C:\Users\SelfTest\AppData\Local\TempElsewhere\pending.dll', '') -TemporaryRoots $temporaryRoots
    if (-not $tempPrefixLookalike.BlocksComponentServicing) { $failures.Add('A sibling directory sharing the Temp prefix must remain blocking.') }
    $unreviewedPrefix = Get-PCPendingRenameAssessment -Entries @('*2\??\F:\backup\windowsapps\installed\tweaking.com\msvbvm60.dll', '') -TemporaryRoots $temporaryRoots
    if (-not $unreviewedPrefix.BlocksComponentServicing -or $unreviewedPrefix.OutsideTempDeletionCount -ne 1 -or $unreviewedPrefix.UnreviewedPrefixCount -ne 1) { $failures.Add('A non-Temp pending deletion with an unreviewed *2 prefix must remain blocked and report the reason counts.') }
    $servicingFileMoves = Get-PCPendingRenameAssessment -Entries @('*2\??\C:\WINDOWS\winsxs\pending.xml', '*1!\??\C:\Windows\WinSxS\pending.xml.24972.old', '*1\??\C:\Windows\System32\config\TxR\txr.regtrans-ms', '*1!\??\C:\Windows\System32\config\TxR\txr.regtrans-ms.old') -TemporaryRoots $temporaryRoots
    if (-not $servicingFileMoves.BlocksComponentServicing -or $servicingFileMoves.ReplacementOrMoveCount -ne 2 -or $servicingFileMoves.UnreviewedPrefixCount -ne 1) { $failures.Add('WinSxS and TxR rename pairs with *1! destinations must remain blocking, and an unreviewed *2 source must be reported.') }

    $selfTestCount = $cases.Count + 64
    if ($failures.Count -gt 0) {
        foreach ($failure in $failures) { Write-Error $failure }
        Write-Host ('SELFTEST_FAILED checks=' + $selfTestCount + ' failures=' + $failures.Count)
        exit 1
    }
    Write-Host ('SELFTEST_OK checks=' + $selfTestCount)
    exit 0
}

if ($SelfTest) { Invoke-PCSelfTest }

try {
    [System.IO.Directory]::CreateDirectory($script:RunDirectory) | Out-Null
}
catch {
    [Console]::Error.WriteLine('Unable to create evidence directory: ' + $_.Exception.Message)
    exit 10
}

$script:EventLogClearAudit = Get-PCEventLogClearAudit -SinceLocal $script:RunStartedLocal.AddDays(-30)
$auditHistoryLogNames = @(
    'System',
    'Security',
    'Microsoft-Windows-CodeIntegrity/Operational',
    'Microsoft-Windows-Bits-Client/Operational',
    'Microsoft-Windows-WindowsUpdateClient/Operational'
)
$auditHistoryClears = @($script:EventLogClearAudit.Events | Where-Object { $_.Channel -in $auditHistoryLogNames })
$clearedAuditLogNames = @($auditHistoryClears | ForEach-Object { [string]$_.Channel } | Sort-Object -Unique)
$eventLogClearWindowStart = [DateTimeOffset]::Parse([string]$script:EventLogClearAudit.WindowStartLocal).LocalDateTime
$systemLogCoverage = Get-PCEventLogClearState -Audit $script:EventLogClearAudit -LogName 'System' -WindowStartLocal $eventLogClearWindowStart
$securityLogCoverage = Get-PCEventLogClearState -Audit $script:EventLogClearAudit -LogName 'Security' -WindowStartLocal $eventLogClearWindowStart
$eventLogClearQueryErrors = [System.Collections.Generic.List[string]]::new()
foreach ($queryError in @([string]$script:EventLogClearAudit.QueryError, [string]$script:EventLogClearAudit.SecurityQueryError)) {
    if (-not [string]::IsNullOrWhiteSpace($queryError)) { $eventLogClearQueryErrors.Add($queryError) }
}
$eventLogClearQueryError = $eventLogClearQueryErrors -join ' | '
$eventLogClearStatus = if (-not [string]::IsNullOrWhiteSpace($eventLogClearQueryError)) { 'unknown' } elseif ($script:EventLogClearAudit.EventCount -gt 0 -or $script:EventLogClearAudit.SecurityClearEventCount -gt 0) { 'warn' } elseif (-not $systemLogCoverage.HistoryComplete -or -not $securityLogCoverage.HistoryComplete) { 'unknown' } else { 'pass' }
if ($script:EventLogClearAudit.EventCount -gt 0) {
    $eventLogClearSummary = 'System Event ID 104 records show {0} channel clear(s) in the 30-day window.' -f $script:EventLogClearAudit.EventCount
}
else {
    $eventLogClearSummary = 'No System Event ID 104 channel-clear markers were found in the retained 30-day System history.'
}
if ($script:EventLogClearAudit.SecurityClearEventCount -gt 0) { $eventLogClearSummary += ' Security Event ID 1102 records show {0} audit-log clear(s).' -f $script:EventLogClearAudit.SecurityClearEventCount }
if ($clearedAuditLogNames.Count -gt 0) { $eventLogClearSummary += ' Audited or servicing-context channels cleared: ' + ($clearedAuditLogNames -join ', ') + '.' }
if (-not [string]::IsNullOrWhiteSpace([string]$systemLogCoverage.Summary)) { $eventLogClearSummary += ' ' + $systemLogCoverage.Summary }
if (-not [string]::IsNullOrWhiteSpace([string]$securityLogCoverage.Summary)) { $eventLogClearSummary += ' ' + $securityLogCoverage.Summary }
if ($script:EventLogClearAudit.EventCount -gt 0 -or $script:EventLogClearAudit.SecurityClearEventCount -gt 0) { $eventLogClearSummary += ' A clear marker is not evidence that the underlying condition was repaired; pre-clear event history is unavailable.' }
if (-not [string]::IsNullOrWhiteSpace($eventLogClearQueryError)) { $eventLogClearSummary += ' Clear-marker query issue: ' + $eventLogClearQueryError }
$eventLogClearEvidence = [pscustomobject]@{
    WindowStartLocal = $script:EventLogClearAudit.WindowStartLocal
    SystemEvent104Count = $script:EventLogClearAudit.EventCount
    SecurityEvent1102Count = $script:EventLogClearAudit.SecurityClearEventCount
    AuditedOrServicingContextChannels = $auditHistoryLogNames
    MatchingChannelClearEvents = $auditHistoryClears
    QueryError = $script:EventLogClearAudit.QueryError
    SecurityClearQueryError = $script:EventLogClearAudit.SecurityQueryError
    SecurityClearEvents = $script:EventLogClearAudit.SecurityClearEvents
    SystemLogCoverage = $systemLogCoverage
    SecurityLogCoverage = $securityLogCoverage
    SystemEvent104Records = $script:EventLogClearAudit.Events
}
Add-PCCheck -Name 'EventLogHistoryCoverage30d' -Status $eventLogClearStatus -Summary $eventLogClearSummary -Evidence $eventLogClearEvidence

$isAdmin = Test-PCAdministrator
Add-PCCheck -Name 'ExecutionContext' -Status $(if ($isAdmin) { 'pass' } else { 'warn' }) -Summary ('PowerShell=' + $PSVersionTable.PSVersion + '; Edition=' + $PSVersionTable.PSEdition + '; Administrator=' + $isAdmin + '.')

try {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    Add-PCCheck -Name 'OperatingSystem' -Status 'pass' -Summary ($os.Caption + '; Version=' + $os.Version + '; Build=' + $os.BuildNumber + '; LastBootUtc=' + $os.LastBootUpTime.ToUniversalTime().ToString('o'))
}
catch {
    Add-PCCheck -Name 'OperatingSystem' -Status 'unknown' -Summary ('Could not query Win32_OperatingSystem: ' + $_.Exception.Message)
}

try {
    $drive = [System.IO.DriveInfo]::new($env:SystemDrive)
    $freePercent = if ($drive.TotalSize -gt 0) { [Math]::Round(($drive.AvailableFreeSpace / $drive.TotalSize) * 100, 2) } else { 0 }
    $driveStatus = if ($freePercent -lt 5) { 'warn' } else { 'pass' }
    Add-PCCheck -Name 'SystemVolume' -Status $driveStatus -Summary ($drive.Name + '; FileSystem=' + $drive.DriveFormat + '; FreeGiB=' + [Math]::Round($drive.AvailableFreeSpace / 1GB, 2) + '; FreePercent=' + $freePercent)
}
catch {
    Add-PCCheck -Name 'SystemVolume' -Status 'unknown' -Summary ('Could not inspect the system volume: ' + $_.Exception.Message)
}

try {
    $reboot = Get-PCRebootState
    $rebootStatus = if ($reboot.Detected) { 'warn' } else { 'pass' }
    if (-not $reboot.Detected) {
        $rebootSummary = 'No configured reboot markers were detected.'
    }
    elseif ($reboot.BlocksComponentServicing) {
        $rebootSummary = 'A Windows servicing/update reboot marker or unsafe pending file operation is present; DISM/SFC is gated.'
    }
    else {
        $rebootSummary = 'Only deferred deletions beneath the current user configured Temp or LocalAppData Temp directory are pending; recorded but not treated as a Windows component-servicing blocker.'
    }
    Add-PCCheck -Name 'PendingReboot' -Status $rebootStatus -Summary $rebootSummary -Evidence $reboot
}
catch {
    $reboot = [pscustomobject]@{ Detected = $true; BlocksComponentServicing = $true; Markers = @('Query failed; state treated as unknown'); BlockingReasons = @('Pending reboot state could not be verified'); PendingFileRenameAssessment = $null; PendingFileRenameEntries = @() }
    Add-PCCheck -Name 'PendingReboot' -Status 'unknown' -Summary ('Could not read reboot markers: ' + $_.Exception.Message) -Evidence $reboot
}

$servicing = @(Get-PCServicingProcesses)
$servicingStatus = if ($servicing.Count -gt 0) { 'warn' } else { 'pass' }
$servicingSummary = if ($servicing.Count -gt 0) { 'Servicing-related processes are present; DISM/SFC checks will not start until they exit.' } else { 'No DISM, SFC, TiWorker, or TrustedInstaller process was detected.' }
Add-PCCheck -Name 'ServicingProcesses' -Status $servicingStatus -Summary $servicingSummary -Evidence $servicing

try {
    $serviceNames = @('RpcSs', 'DcomLaunch', 'EventLog', 'TrustedInstaller', 'wuauserv', 'BITS', 'CryptSvc', 'BFE', 'MpsSvc', 'nsi', 'Everything')
    $serviceFilter = ($serviceNames | ForEach-Object { "Name='$_'" }) -join ' OR '
    $services = @(Get-CimInstance -ClassName Win32_Service -Filter $serviceFilter)
    $serviceEvidence = @($services | ForEach-Object {
        [pscustomobject]@{ Name = $_.Name; State = $_.State; StartMode = $_.StartMode; ExitCode = $_.ExitCode; ProcessId = $_.ProcessId }
    })
    $criticalStopped = @($services | Where-Object { $_.Name -in @('RpcSs', 'DcomLaunch', 'EventLog') -and $_.State -ne 'Running' })
    $serviceStatus = if ($criticalStopped.Count -gt 0) { 'fail' } else { 'pass' }
    $serviceSummary = if ($criticalStopped.Count -gt 0) { 'A core Windows service expected to be running is stopped.' } else { 'Core-service states are captured; stopped on-demand servicing services are not treated as failures.' }
    Add-PCCheck -Name 'CoreAndServicingServices' -Status $serviceStatus -Summary $serviceSummary -Evidence $serviceEvidence
}
catch {
    Add-PCCheck -Name 'CoreAndServicingServices' -Status 'unknown' -Summary ('Could not query Win32_Service: ' + $_.Exception.Message)
}

# These interfaces were removed by a bulk MOF/uninstall compilation. Keep their
# actual read-only queries in the audit so recurrence is visible.
$managementQueries = [ordered]@{
    NetworkAdapters = { Get-NetAdapter -ErrorAction Stop | Select-Object Name,Status,InterfaceDescription }
    IPAddresses = { Get-NetIPAddress -ErrorAction Stop | Select-Object InterfaceIndex,AddressFamily,AddressState }
    NetworkProfiles = { Get-NetConnectionProfile -ErrorAction Stop | Select-Object InterfaceIndex,NetworkCategory,IPv4Connectivity,IPv6Connectivity }
    Defender = { Get-MpComputerStatus -ErrorAction Stop | Select-Object AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,NISEnabled,AMRunningMode,AntivirusSignatureLastUpdated }
    BitLocker = { Get-BitLockerVolume -ErrorAction Stop | Select-Object MountPoint,VolumeStatus,ProtectionStatus }
}
foreach ($entry in $managementQueries.GetEnumerator()) {
    try {
        $providerData = @(& $entry.Value)
        $providerStatus = if ($providerData.Count -gt 0) { 'pass' } else { 'unknown' }
        Add-PCCheck -Name ('ManagementProvider_' + $entry.Key) -Status $providerStatus -Summary ('Read-only management query returned ' + $providerData.Count + ' instance(s); this checks query availability, not every underlying device or security policy.') -Evidence $providerData
    } catch {
        Add-PCCheck -Name ('ManagementProvider_' + $entry.Key) -Status 'warn' -Summary ('Management query failed: ' + $_.Exception.Message) -Evidence ([pscustomobject]@{ ErrorId=$_.FullyQualifiedErrorId })
    }
}

$scmEvents = @()
try {
    $since = (Get-Date).AddDays(-30)
    $scmHistory = Get-PCEventLogClearState -Audit $script:EventLogClearAudit -LogName 'System' -WindowStartLocal $since
    $eventIds = @(7000, 7001, 7009, 7011, 7022, 7023, 7024, 7031, 7034, 7043)
    $recent = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Service Control Manager'; Id = $eventIds; StartTime = $since } -MaxEvents 100 -ErrorAction Stop)
    $scmEvents = @($recent | ForEach-Object {
        $message = $_.Message
        if ($null -ne $message -and $message.Length -gt 2000) { $message = $message.Substring(0, 2000) }
        [pscustomobject]@{ TimeCreatedUtc = $_.TimeCreated.ToUniversalTime().ToString('o'); EventId = $_.Id; Level = $_.LevelDisplayName; Message = $message }
    })
    $eventStatus = if ($scmEvents.Count -gt 0) { 'warn' } elseif (-not $scmHistory.HistoryComplete) { 'unknown' } else { 'pass' }
    $eventCountText = [string]$scmEvents.Count
    if ($scmEvents.Count -gt 0) { $eventSummary = $eventCountText + ' matching SCM events captured; they require time/context correlation and are not automatically diagnosed as current failures.' }
    elseif (-not $scmHistory.HistoryComplete) { $eventSummary = 'No matching SCM events were found in retained System records, but the requested 30-day history is incomplete.' }
    else { $eventSummary = 'No matching SCM events were found in the last 30 days.' }
    if (-not $scmHistory.HistoryComplete -and -not [string]::IsNullOrWhiteSpace([string]$scmHistory.Summary)) { $eventSummary += ' ' + $scmHistory.Summary }
    $scmEvidence = [pscustomobject]@{ WindowStartLocal = $since.ToString('o'); EventCount = $scmEvents.Count; Events = $scmEvents; EventHistory = $scmHistory }
    Add-PCCheck -Name 'ServiceControlManagerEvents30d' -Status $eventStatus -Summary $eventSummary -Evidence $scmEvidence
}
catch {
    Add-PCCheck -Name 'ServiceControlManagerEvents30d' -Status 'unknown' -Summary ('Could not query recent SCM events: ' + $_.Exception.Message)
}

try {
    Invoke-PCStorageAudit -RunDirectory $script:RunDirectory
}
catch {
    Add-PCCheck -Name 'StorageAudit' -Status 'unknown' -Summary ('Storage event, disk mapping, or reliability audit stopped unexpectedly: ' + $_.Exception.Message)
}

try {
    Invoke-PCKnownServiceAudit -RunDirectory $script:RunDirectory
}
catch {
    Add-PCCheck -Name 'KnownServiceAudit' -Status 'unknown' -Summary ('Focused firewall, BITS, or Everything audit stopped unexpectedly: ' + $_.Exception.Message)
}

$nativePath = [System.IO.Path]::Combine($env:windir, 'System32')
$dismPath = [System.IO.Path]::Combine($nativePath, 'dism.exe')
$sfcPath = [System.IO.Path]::Combine($nativePath, 'sfc.exe')
$healthGateOpen = ($servicing.Count -eq 0 -and -not $reboot.BlocksComponentServicing)

if ($RepairWindowsFiles) {
    $repairGate = Get-PCRepairGate -Confirmed $ConfirmRepair -Administrator $isAdmin -PendingServicingReboot $reboot.BlocksComponentServicing -ServicingProcesses $servicing
    if (-not $repairGate.Open) {
        Add-PCCheck -Name 'RepairGate' -Status 'blocked' -Summary ($repairGate.Reasons -join ' ')
    }
    else {
        $restore = Invoke-PCNativeCheck -Name 'DISM-RestoreHealth' -Kind 'DismRestoreHealth' -Executable $dismPath -Arguments @('/Online', '/Cleanup-Image', '/RestoreHealth', '/English') -TimeoutSeconds $NativeTimeoutSeconds
        if ($restore.Status -eq 'pass') {
            $quiet = Wait-PCServicingQuiet -TimeoutSeconds $ServicingSettleSeconds
            if (-not $quiet.Quiet) {
                Add-PCCheck -Name 'AfterRestoreHealthSettle' -Status 'blocked' -Summary ('Servicing owners remained after ' + $quiet.WaitedSeconds + ' seconds; later DISM/SFC steps were not started.') -Evidence $quiet.Processes
            }
            else {
                $finalDism = Invoke-PCNativeCheck -Name 'DISM-Final-CheckHealth' -Kind 'DismCheckHealth' -Executable $dismPath -Arguments @('/Online', '/Cleanup-Image', '/CheckHealth', '/English') -TimeoutSeconds $NativeTimeoutSeconds
                if ($finalDism.Status -eq 'pass') {
                    $quiet = Wait-PCServicingQuiet -TimeoutSeconds $ServicingSettleSeconds
                    if (-not $quiet.Quiet) {
                        Add-PCCheck -Name 'BeforeSfcSettle' -Status 'blocked' -Summary ('Servicing owners remained after ' + $quiet.WaitedSeconds + ' seconds; SFC was not started.') -Evidence $quiet.Processes
                    }
                    else {
                        $sfcStarted = [DateTime]::Now
                        $scan = Invoke-PCNativeCheck -Name 'SFC-Scannow' -Kind 'SfcScanNow' -Executable $sfcPath -Arguments @('/scannow') -TimeoutSeconds $NativeTimeoutSeconds
                        if ($scan.Started) {
                            $quiet = Wait-PCServicingQuiet -TimeoutSeconds $ServicingSettleSeconds
                            if ($quiet.Quiet -and $scan.Status -ne 'timeout') {
                                Save-PCSfcEvidence -SinceLocal $sfcStarted.AddSeconds(-5)
                                $null = Invoke-PCNativeCheck -Name 'SFC-PostRepair-VerifyOnly' -Kind 'SfcVerifyOnly' -Executable $sfcPath -Arguments @('/verifyonly') -TimeoutSeconds $NativeTimeoutSeconds
                            }
                            else {
                                Add-PCCheck -Name 'CurrentSfcCBSRecords' -Status 'unknown' -Summary 'CBS evidence was not read because SFC timed out or servicing did not reach a stable quiet window.'
                                if (-not $quiet.Quiet) {
                                    Add-PCCheck -Name 'PostSfcVerification' -Status 'blocked' -Summary ('Servicing owners remained after ' + $quiet.WaitedSeconds + ' seconds; verify-only was not started.') -Evidence $quiet.Processes
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
elseif ($healthGateOpen) {
    $check = Invoke-PCNativeCheck -Name 'DISM-CheckHealth' -Kind 'DismCheckHealth' -Executable $dismPath -Arguments @('/Online', '/Cleanup-Image', '/CheckHealth', '/English') -TimeoutSeconds $NativeTimeoutSeconds
    if ($check.Status -eq 'pass') {
        $null = Invoke-PCNativeCheck -Name 'DISM-ScanHealth' -Kind 'DismScanHealth' -Executable $dismPath -Arguments @('/Online', '/Cleanup-Image', '/ScanHealth', '/English') -TimeoutSeconds $NativeTimeoutSeconds
    }
    $sfcStarted = [DateTime]::Now
    $verify = Invoke-PCNativeCheck -Name 'SFC-VerifyOnly' -Kind 'SfcVerifyOnly' -Executable $sfcPath -Arguments @('/verifyonly') -TimeoutSeconds $NativeTimeoutSeconds
    if ($verify.Started -and $verify.Status -ne 'timeout') {
        $quiet = Wait-PCServicingQuiet -TimeoutSeconds $ServicingSettleSeconds
        if ($quiet.Quiet) {
            Save-PCSfcEvidence -SinceLocal $sfcStarted.AddSeconds(-5)
        }
        else {
            Add-PCCheck -Name 'CurrentSfcCBSRecords' -Status 'unknown' -Summary ('CBS evidence was not read because servicing owners remained after ' + $quiet.WaitedSeconds + ' seconds.') -Evidence $quiet.Processes
        }
    }
    elseif ($verify.Status -eq 'timeout') {
        Add-PCCheck -Name 'CurrentSfcCBSRecords' -Status 'unknown' -Summary 'CBS evidence was not read because SFC verify-only timed out and may still be running.'
    }
    else {
        Add-PCCheck -Name 'CurrentSfcCBSRecords' -Status 'unknown' -Summary 'CBS evidence was not read because SFC verification was blocked or could not be started.'
    }
}
else {
    $why = [System.Collections.Generic.List[string]]::new()
    if ($servicing.Count -gt 0) { $why.Add('servicing process present') }
    if ($reboot.BlocksComponentServicing) { $why.Add('Windows servicing reboot marker or unsafe pending file operation present or unreadable') }
    Add-PCCheck -Name 'WindowsComponentIntegrity' -Status 'blocked' -Summary ('DISM/SFC checks were skipped: ' + ($why -join '; ') + '.')
}

$overall = Write-PCReport -Path $script:ReportPath
Write-Host ('Report: ' + $script:ReportPath)
foreach ($check in $script:Checks) {
    Write-Host ('[' + $check.Status.ToUpperInvariant() + '] ' + $check.Name + ': ' + $check.Summary)
}
Write-Host ('OVERALL=' + $overall)
if ($overall -eq 'Failed') { exit 2 }
if ($overall -eq 'Incomplete') { exit 3 }
if ($overall -eq 'NeedsReview') { exit 4 }
exit 0
