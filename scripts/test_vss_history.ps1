# Copyright (C) 2026 Shirofune Security Co., Ltd.
# SPDX-License-Identifier: RPL-1.5
param(
    [Parameter(Mandatory=$true)][string]$Binary,
    [Parameter(Mandatory=$true)][string]$WorkDirectory
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$Binary = (Resolve-Path -LiteralPath $Binary).Path
if (Test-Path -LiteralPath $WorkDirectory) { throw 'Use a fresh validation directory' }
$null = New-Item -ItemType Directory -Path $WorkDirectory
$WorkDirectory = (Resolve-Path -LiteralPath $WorkDirectory).Path
$image = Join-Path $WorkDirectory 'history-test.vhdx'
$diskpart = Join-Path $WorkDirectory 'diskpart.txt'
$volume = $null
$snapshotIds = @()
$cases = @()

function Invoke-Kumade([string[]]$Arguments) {
    $start = New-Object Diagnostics.ProcessStartInfo
    $start.FileName = $Binary
    # Inputs below are owned paths and fixed switches. Escape terminal backslashes
    # for Windows argv parsing rather than altering the source volume argument.
    $quoted = foreach ($argument in $Arguments) {
        if ($argument.Contains('"')) { throw 'Unexpected quote in test argument' }
        '"' + [regex]::Replace($argument, '(\\+)$', '$1$1') + '"'
    }
    $start.Arguments = $quoted -join ' '
    $start.UseShellExecute = $false
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $process = [Diagnostics.Process]::Start($start)
    $stdout = $process.StandardOutput.ReadToEndAsync()
    $stderr = $process.StandardError.ReadToEndAsync()
    if (!$process.WaitForExit(180000)) { $process.Kill(); throw 'Collector test timed out' }
    $out = $stdout.GetAwaiter().GetResult()
    $err = $stderr.GetAwaiter().GetResult()
    if ($process.ExitCode -ne 0) { throw "Collector exit $($process.ExitCode): $out $err" }
    return $out
}
function New-TestSnapshot {
    $result = Invoke-CimMethod -ClassName Win32_ShadowCopy -MethodName Create -Arguments @{Volume=$snapshotVolume; Context='ClientAccessible'}
    if ($result.ReturnValue -ne 0 -or !$result.ShadowID) { throw "Snapshot creation failed: $($result | ConvertTo-Json -Compress)" }
    return ([guid]$result.ShadowID).ToString()
}
function Read-Manifest([string]$Parent) {
    $runs = @(Get-ChildItem -LiteralPath $Parent -Directory)
    if ($runs.Count -ne 1) { throw 'Expected one run' }
    $rows = @(Get-Content -LiteralPath (Join-Path $runs[0].FullName 'Manifest.jsonl') | ForEach-Object { $_ | ConvertFrom-Json })
    return @{Root=$runs[0].FullName; Rows=$rows}
}
try {
    @"
create vdisk file="$image" maximum=8192 type=expandable
select vdisk file="$image"
attach vdisk
create partition primary
format fs=ntfs quick label=KumadeVssHistory
assign
"@ | Set-Content -LiteralPath $diskpart -Encoding ascii
    & diskpart.exe /s $diskpart | Out-Null
    $volumes = @(Get-DiskImage -ImagePath $image | Get-Disk | Get-Partition | Get-Volume | Where-Object FileSystem -eq NTFS)
    if ($volumes.Count -ne 1) { throw 'Expected one isolated NTFS volume' }
    $volume = $volumes[0].UniqueId
    $snapshotVolume = if ($volumes[0].DriveLetter) { [string]$volumes[0].DriveLetter + ':\' } else { $volume }
    # Native stderr must not turn an unsupported Add command into a terminating
    # PowerShell 5.1 error before the client-Windows Resize fallback can run.
    $ErrorActionPreference = 'Continue'
    & vssadmin.exe add shadowstorage "/for=$volume" "/on=$volume" /maxsize=1GB 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        # Client Windows exposes Resize rather than the Server-only Add command.
        & vssadmin.exe resize shadowstorage "/for=$volume" "/on=$volume" /maxsize=1GB 2>&1 | Out-Null
    }
    $storageExit = $LASTEXITCODE
    $ErrorActionPreference = 'Stop'
    if ($storageExit -ne 0) { throw 'Cannot configure owned test volume shadow storage' }
    $prefetch = Join-Path $volume 'Windows\Prefetch'
    $null = New-Item -ItemType Directory -Path $prefetch
    $evidence = Join-Path $prefetch 'HISTORY.pf'
    [IO.File]::WriteAllText($evidence, 'old-version-A')
    [IO.File]::WriteAllText((Join-Path $prefetch 'UNCHANGED.pf'), 'identical-evidence')
    [IO.File]::WriteAllText((Join-Path $prefetch 'DELETED.pf'), 'deleted-before-second-snapshot')
    $snapshotIds += New-TestSnapshot
    [IO.File]::WriteAllText($evidence, 'old-version-B')
    Remove-Item -LiteralPath (Join-Path $prefetch 'DELETED.pf')
    $snapshotIds += New-TestSnapshot
    [IO.File]::WriteAllText($evidence, 'current-version-C')

    $json = Invoke-Kumade -Arguments @('list-vss','--volume',$volume,'-t','json')
    [IO.File]::WriteAllText((Join-Path $WorkDirectory 'Snapshots.json'), $json)
    $listing = $json | ConvertFrom-Json
    $listing = @($listing)
    if ($listing.Count -ne 2) { throw "Expected two historical snapshots, got $($listing.Count)" }
    foreach ($id in $snapshotIds) {
        $row = @($listing | Where-Object SnapshotId -eq $id)
        if ($row.Count -ne 1 -or !$row[0].RootReadable) { throw 'Snapshot listing lost an owned readable snapshot' }
    }
    $csv = Join-Path $WorkDirectory 'Snapshots.csv'
    Invoke-Kumade -Arguments @('list-vss','--volume',$volume,'-o',$csv) | Out-Null
    if (@(Import-Csv -LiteralPath $csv).Count -ne 2) { throw 'CSV snapshot listing is incomplete' }

    foreach ($test in @(
        @{Name='all'; Selector='all'; Count=7; Historical=2; New=$false},
        @{Name='newest'; Selector='newest'; Count=4; Historical=1; New=$false},
        @{Name='id'; Selector=$snapshotIds[0]; Count=5; Historical=1; New=$false},
        @{Name='new-plus-existing'; Selector='all'; Count=7; Historical=2; New=$true}
    )) {
        $parent = Join-Path $WorkDirectory $test.Name
        $arguments = @('collect','--yes','--vss-existing',$test.Selector,'--volume',$volume,'--artifact','windows.prefetch','--no-live-info','--reserve-mib','0','-q','-o',$parent)
        if ($test.New) { $arguments += '--vss' }
        Invoke-Kumade -Arguments $arguments | Out-Null
        $run = Read-Manifest $parent
        $rows = @($run.Rows)
        if ($rows.Count -ne $test.Count -or @($rows | Where-Object Status -ne Acquired).Count -ne 0) { throw "Incorrect acquisition accounting for $($test.Name)" }
        $plan = Get-Content -Raw -LiteralPath (Join-Path $run.Root 'Plan.json') | ConvertFrom-Json
        $historical = @($plan.Sources | Where-Object {$_.Snapshot -and $_.Snapshot.OwnedByCollector -eq $false})
        if ($historical.Count -ne $test.Historical) { throw 'Historical ownership metadata is wrong' }
        foreach ($source in $historical) {
            if ($null -ne $source.Snapshot.WritersParticipated -or $source.Snapshot.Consistency -ne 'UnknownHistorical') { throw 'Historical consistency was invented' }
            if ($source.Id -notmatch '-VSS-' -or $snapshotIds -notcontains $source.Snapshot.SnapshotId) { throw 'Snapshot output identity is wrong' }
        }
        Invoke-Kumade -Arguments @('verify',$run.Root) | Out-Null
        if ($test.Name -eq 'all') {
            $contents = @($rows | Where-Object {$_.SourcePath -like '*HISTORY.pf'} | ForEach-Object {[IO.File]::ReadAllText((Join-Path $run.Root $_.RelativeOutputPath))})
            foreach ($value in @('old-version-A','old-version-B','current-version-C')) { if ($contents -notcontains $value) { throw "Lost version $value" } }
            if (@($rows | Where-Object {$_.SourcePath -like '*UNCHANGED.pf'}).Count -ne 3) { throw 'Identical historical versions were omitted' }
            if (@($rows | Where-Object {$_.SourcePath -like '*DELETED.pf'}).Count -ne 1) { throw 'Deleted historical evidence was lost' }
        }
        $after = Invoke-Kumade -Arguments @('list-vss','--volume',$volume,'-t','json') | ConvertFrom-Json
        $after = @($after)
        if ($after.Count -ne 2) { throw 'Collection created a residual snapshot or removed historical evidence' }
        foreach ($id in $snapshotIds) { if ($after.SnapshotId -notcontains $id) { throw 'Historical snapshot was deleted' } }
        $cases += @{Case=$test.Name; Payloads=$rows.Count; HistoricalSources=$historical.Count; Verified=$true}
    }
    $cases | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $WorkDirectory 'Validation.json') -Encoding utf8
    Write-Output 'Historical VSS listing, all/newest/ID, live plus historical, deleted/identical evidence, provenance, verification and ownership cleanup passed.'
} finally {
    # Only this newly created test volume. Never target the system volume or
    # delete snapshots belonging to any pre-existing volume.
    if ($volume) {
        Get-CimInstance Win32_ShadowCopy | Where-Object {$_.VolumeName -eq $volume} | Remove-CimInstance -ErrorAction Continue
    }
    if (Test-Path -LiteralPath $image) {
        Dismount-DiskImage -ImagePath $image -ErrorAction Continue | Out-Null
    }
}
