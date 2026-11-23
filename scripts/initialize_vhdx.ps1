# Copyright (C) 2026 Shirofune Security Co., Ltd.
# SPDX-License-Identifier: RPL-1.5
# Called only after Kumade has exclusively created and attached a new image.
# Values are passed through the child environment, never interpolated as code.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$env:PSModulePath=Join-Path $PSHOME 'Modules'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$number = [uint32]::Parse($env:KUMADE_VHDX_DISK_NUMBER)
$image = Get-DiskImage -ImagePath $env:KUMADE_VHDX_PATH -ErrorAction Stop
$disks = @($image | Get-Disk -ErrorAction Stop)
if ($disks.Count -ne 1) { throw 'The created image must identify exactly one disk' }
$disk = $disks[0]
if ($disk.Number -ne $number -or $disk.IsBoot -or $disk.IsSystem -or
    $disk.PartitionStyle -ne 'RAW' -or ([uint16]$disk.CimInstanceProperties['BusType'].Value) -ne 15) {
    throw 'Refusing to initialize a disk that is not the newly created RAW virtual disk'
}
$null = Initialize-Disk -InputObject $disk -PartitionStyle GPT -ErrorAction Stop
$part = New-Partition -DiskNumber $number -UseMaximumSize -AssignDriveLetter:$false -ErrorAction Stop
if ($part.DiskNumber -ne $number -or $part.DriveLetter) { throw 'Unexpected new partition identity' }
$null = Format-Volume -Partition $part -FileSystem NTFS -NewFileSystemLabel 'KumadeEvidence' -Confirm:$false -Force -ErrorAction Stop
$volumes = @($part | Get-Volume -ErrorAction Stop)
if ($volumes.Count -ne 1 -or $volumes[0].FileSystem -ne 'NTFS') { throw 'Expected one NTFS evidence volume' }
@{ DiskNumber=$number; DiskUniqueId=(Get-Disk -Number $number -ErrorAction Stop).UniqueId; VolumePath=$volumes[0].UniqueId; FileSystem=$volumes[0].FileSystem } | ConvertTo-Json -Compress
